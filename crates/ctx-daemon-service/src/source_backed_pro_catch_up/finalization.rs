use std::{
    path::Path,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use ctx_history_index::VerifiedIndex;
use ctx_pro_host_protocol::{CoreMaterializationFinalizationPending, CoreMaterializationReceipt};

use crate::{ProCatchUpOutcome, ProCatchUpPort};

use super::super::source_backed_refresh_coordinator::{
    nonzero_duration_micros, open_verified_index, source_backed_index_root,
};
use super::recheck::{
    complete as complete_observed_recheck, read as read_recheck_request,
    read_unlocked as read_recheck_request_unlocked, with_lock as with_recheck_lock,
};
use super::status::{
    persist_status, read_status, SourceBackedProCatchUpError, SourceBackedProCatchUpState,
    SourceBackedProCatchUpStatus,
};
use super::{SourceBackedProCatchUpRun, SourceBackedProCoreAuthority};

const SOURCE_BACKED_PRO_CATCH_UP_POLL_INTERVAL: Duration = Duration::from_millis(50);
const SOURCE_BACKED_PRO_CATCH_UP_WAIT_TIMEOUT: Duration = Duration::from_secs(60 * 60);

pub fn run_after_core_publication(
    data_root: &Path,
    core_generation_id: &str,
    authority: SourceBackedProCoreAuthority<'_>,
    pro: &dyn ProCatchUpPort,
) -> Result<SourceBackedProCatchUpRun> {
    if authority.generation_id() != core_generation_id {
        return record_preflight_error(
            data_root,
            core_generation_id,
            SourceBackedProCatchUpError::GenerationMismatch {
                expected: core_generation_id.to_owned(),
                authority: authority.generation_id().to_owned(),
                surface: authority.surface(),
            },
        );
    }
    run_with(
        data_root,
        core_generation_id,
        ProCatchUpAuthority {
            generation_id: Some(authority.generation_id()),
            verified_index: Some(authority.verified_index()),
        },
        pro,
        |data_root| pro.preflight(data_root),
        |data_root, index| {
            Ok(match pro.sync(data_root, index)? {
                ProCatchUpOutcome::Finished {
                    receipt,
                    did_work,
                    helper_artifact_sha256,
                } => ProCatchUpSyncOutcome::Finished {
                    receipt,
                    did_work,
                    helper_artifact_sha256,
                },
                ProCatchUpOutcome::FinalizationPending { pending } => {
                    ProCatchUpSyncOutcome::FinalizationPending { pending }
                }
            })
        },
    )
}

pub(super) struct ProCatchUpAuthority<'a> {
    pub(super) generation_id: Option<&'a str>,
    pub(super) verified_index: Option<&'a VerifiedIndex>,
}

pub(super) enum ProCatchUpSyncOutcome {
    Finished {
        receipt: CoreMaterializationReceipt,
        did_work: bool,
        helper_artifact_sha256: String,
    },
    FinalizationPending {
        pending: CoreMaterializationFinalizationPending,
    },
}

pub(super) fn run_with<Preflight, Sync>(
    data_root: &Path,
    core_generation_id: &str,
    authority: ProCatchUpAuthority<'_>,
    pro: &dyn ProCatchUpPort,
    preflight: Preflight,
    sync: Sync,
) -> Result<SourceBackedProCatchUpRun>
where
    Preflight: FnOnce(&Path) -> Result<()>,
    Sync: FnOnce(&Path, &VerifiedIndex) -> Result<ProCatchUpSyncOutcome>,
{
    // Capture the exact target this run is allowed to satisfy. The completion
    // path additionally requires the helper identity reported by this exact
    // materialization session, so an old helper cannot clear a newer intent.
    let observed_recheck = read_recheck_request(data_root)?;
    let prior = read_status(data_root);
    let attempts = next_attempt(prior.as_ref(), core_generation_id);
    let attempt_started = Instant::now();
    let pending = prior
        .as_ref()
        .filter(|status| status.core_generation_id == core_generation_id)
        .and_then(|status| status.finalization_progress.clone())
        .map(|progress| {
            SourceBackedProCatchUpStatus::pending(core_generation_id, attempts).finalizing(progress)
        })
        .unwrap_or_else(|| SourceBackedProCatchUpStatus::pending(core_generation_id, attempts));
    persist_status(data_root, &pending)?;

    let result: std::result::Result<ProCatchUpSyncOutcome, SourceBackedProCatchUpError> = (|| {
        if let Some(generation_id) = authority.generation_id {
            require_generation(
                core_generation_id,
                generation_id,
                "retained Core generation pin",
            )?;
        }
        preflight(data_root)
            .map_err(|error| SourceBackedProCatchUpError::projection(error, pro))?;
        let opened_index: VerifiedIndex;
        let index = match authority.verified_index {
            Some(index) => index,
            None => {
                opened_index = open_exact_index(data_root, core_generation_id)?;
                &opened_index
            }
        };
        require_generation(
            core_generation_id,
            index.generation_id(),
            "pinned VerifiedIndex",
        )?;
        let outcome = sync(data_root, index)
            .map_err(|error| SourceBackedProCatchUpError::projection(error, pro))?;
        match &outcome {
            ProCatchUpSyncOutcome::Finished { receipt, .. } => require_generation(
                core_generation_id,
                &receipt.core_generation_id,
                "Pro Core materialization receipt",
            )?,
            ProCatchUpSyncOutcome::FinalizationPending { pending } => {
                require_generation(
                    core_generation_id,
                    &pending.progress.core_generation_id,
                    "Pro Core finalization progress",
                )?;
                // Production acquires this before sending Finish/Continue. This
                // idempotent reconstruction also covers restart migration and
                // injected consumers while the exact generation is still pinned.
                pro.reconstruct_finalization_lease(data_root, &pending.progress)
                    .map_err(|error| SourceBackedProCatchUpError::projection(error, pro))?;
            }
        }
        Ok(outcome)
    })();

    match result {
        Ok(ProCatchUpSyncOutcome::Finished {
            receipt,
            did_work,
            helper_artifact_sha256,
        }) => {
            let completed = pending
                .completed(receipt.core_generation_id)
                .with_duration(nonzero_duration_micros(attempt_started.elapsed()));
            persist_status(data_root, &completed)?;
            // Status is the durable job authority. Publish terminal state before
            // dropping the target lease so a crash can only retain, never reclaim
            // an unfinished target.
            pro.release_finalization_lease(data_root, Some(core_generation_id))?;
            complete_observed_recheck(
                data_root,
                observed_recheck.as_ref(),
                &helper_artifact_sha256,
            )?;
            Ok(SourceBackedProCatchUpRun {
                status: completed.to_json()?,
                did_work,
                continuation_pending: false,
            })
        }
        Ok(ProCatchUpSyncOutcome::FinalizationPending {
            pending: finalization,
        }) => {
            let did_work = !finalization.replayed;
            let finalizing = pending
                .finalizing(finalization.progress)
                .with_duration(nonzero_duration_micros(attempt_started.elapsed()));
            persist_status(data_root, &finalizing)?;
            Ok(SourceBackedProCatchUpRun {
                status: finalizing.to_json()?,
                did_work,
                continuation_pending: true,
            })
        }
        Err(error) => {
            let terminal = !error.retryable();
            let failed = pending
                .error(error)
                .with_duration(nonzero_duration_micros(attempt_started.elapsed()));
            persist_status(data_root, &failed)?;
            if terminal {
                pro.release_finalization_lease(data_root, Some(core_generation_id))?;
            }
            Ok(SourceBackedProCatchUpRun {
                status: failed.to_json()?,
                did_work: false,
                continuation_pending: false,
            })
        }
    }
}

fn record_preflight_error(
    data_root: &Path,
    core_generation_id: &str,
    error: SourceBackedProCatchUpError,
) -> Result<SourceBackedProCatchUpRun> {
    let prior = read_status(data_root);
    let attempts = next_attempt(prior.as_ref(), core_generation_id);
    let failed = SourceBackedProCatchUpStatus::pending(core_generation_id, attempts).error(error);
    persist_status(data_root, &failed)?;
    Ok(SourceBackedProCatchUpRun {
        status: failed.to_json()?,
        did_work: false,
        continuation_pending: false,
    })
}

fn next_attempt(prior: Option<&SourceBackedProCatchUpStatus>, core_generation_id: &str) -> u64 {
    prior
        .filter(|status| status.core_generation_id == core_generation_id)
        .map(|status| status.attempts.saturating_add(1))
        .unwrap_or(1)
}

fn require_generation(
    expected: &str,
    authority: &str,
    surface: &'static str,
) -> std::result::Result<(), SourceBackedProCatchUpError> {
    if authority == expected {
        return Ok(());
    }
    Err(SourceBackedProCatchUpError::GenerationMismatch {
        expected: expected.to_owned(),
        authority: authority.to_owned(),
        surface,
    })
}

fn open_exact_index(
    data_root: &Path,
    core_generation_id: &str,
) -> std::result::Result<VerifiedIndex, SourceBackedProCatchUpError> {
    let index_root = source_backed_index_root(data_root);
    let index = open_verified_index(&index_root)
        .with_context(|| format!("open verified Core index {}", index_root.display()))
        .map_err(|error| SourceBackedProCatchUpError::IndexUnavailable(format!("{error:#}")))?;
    require_generation(
        core_generation_id,
        index.generation_id(),
        "pinned VerifiedIndex",
    )?;
    Ok(index)
}

/// Waits for the daemon-owned Pro projection of one exact Core generation.
///
/// This is deliberately a status-only seam. The CLI must not reread provider
/// sources or materialize Pro itself; that work remains owned by the daemon
/// tick that retained the generation-bound Core authority.
pub fn wait_for_completed_generation(data_root: &Path, core_generation_id: &str) -> Result<()> {
    wait_for_completed_generation_with(
        data_root,
        core_generation_id,
        SOURCE_BACKED_PRO_CATCH_UP_WAIT_TIMEOUT,
        || thread::sleep(SOURCE_BACKED_PRO_CATCH_UP_POLL_INTERVAL),
    )
}

pub(super) fn wait_for_completed_generation_with(
    data_root: &Path,
    core_generation_id: &str,
    timeout: Duration,
    mut wait: impl FnMut(),
) -> Result<()> {
    let started = Instant::now();
    loop {
        let (pending_recheck, status) = with_recheck_lock(data_root, || {
            Ok((
                read_recheck_request_unlocked(data_root)?.is_some(),
                read_status(data_root),
            ))
        })?;
        if let Some(status) = status {
            if !pending_recheck && status.is_completed_for(core_generation_id) {
                return Ok(());
            }
            if status.core_generation_id == core_generation_id
                && status.status == SourceBackedProCatchUpState::Error
            {
                let code = status.error_code.as_deref().unwrap_or("not_materialized");
                let detail = status
                    .last_error
                    .as_deref()
                    .unwrap_or("daemon source-backed Pro catch-up failed");
                anyhow::bail!("{code}: {detail}");
            }
        }
        if started.elapsed() >= timeout {
            anyhow::bail!(
                "not_materialized: timed out waiting for daemon source-backed Pro generation {core_generation_id}"
            );
        }
        wait();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ctx_history_index::{GenerationWriter, WriterOptions};
    use ctx_pro_host_protocol::{
        CoreMaterializationFinalizationPhase, CoreMaterializationFinalizationProgress,
    };

    use super::*;

    #[derive(Default)]
    struct RecordingPro {
        reconstructed: AtomicUsize,
        released: AtomicUsize,
    }

    impl ProCatchUpPort for RecordingPro {
        fn preflight(&self, _data_root: &Path) -> Result<()> {
            unreachable!()
        }
        fn sync(&self, _data_root: &Path, _index: &VerifiedIndex) -> Result<ProCatchUpOutcome> {
            unreachable!()
        }
        fn reconcile_finalization_lease(&self, _data_root: &Path) -> Result<()> {
            Ok(())
        }
        fn cancel_finalization_lease(&self, _data_root: &Path, _reason: &str) -> Result<bool> {
            Ok(false)
        }
        fn reconstruct_finalization_lease(
            &self,
            _data_root: &Path,
            _progress: &CoreMaterializationFinalizationProgress,
        ) -> Result<()> {
            self.reconstructed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn validate_finalization_lease(
            &self,
            _data_root: &Path,
            _progress: &CoreMaterializationFinalizationProgress,
        ) -> Result<()> {
            Ok(())
        }
        fn release_finalization_lease(
            &self,
            _data_root: &Path,
            _generation_id: Option<&str>,
        ) -> Result<bool> {
            self.released.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        }
        fn selected_helper_artifact_sha256(&self, _data_root: &Path) -> Result<Option<String>> {
            Ok(None)
        }
        fn stable_error_code(&self, _error: &anyhow::Error) -> Option<&'static str> {
            Some("pro_not_installed")
        }
    }

    fn empty_index(data_root: &Path) -> VerifiedIndex {
        GenerationWriter::open(
            source_backed_index_root(data_root),
            WriterOptions::default(),
        )
        .unwrap()
        .into_writer()
        .unwrap()
        .commit(|_| true)
        .unwrap();
        open_verified_index(&source_backed_index_root(data_root)).unwrap()
    }

    fn receipt(index: &VerifiedIndex) -> CoreMaterializationReceipt {
        CoreMaterializationReceipt {
            core_generation_id: index.generation_id().to_owned(),
            core_record_contract_fingerprint: index
                .manifest()
                .core_record_contract_fingerprint
                .clone(),
            source_snapshot_sha256: "a".repeat(64),
            materializer_revision: "test-core-materializer-v1".to_owned(),
            source_count: 0,
            event_count: 0,
        }
    }

    fn progress(index: &VerifiedIndex) -> CoreMaterializationFinalizationProgress {
        CoreMaterializationFinalizationProgress {
            materialization_id: "b".repeat(64),
            core_generation_id: index.generation_id().to_owned(),
            finish_request_digest: "d".repeat(64),
            materializer_revision: "test-core-materializer-v1".to_owned(),
            phase: CoreMaterializationFinalizationPhase::EmitReplay,
            cursor_sha256: "c".repeat(64),
        }
    }

    #[test]
    fn pinned_completion_reuses_the_index_and_releases_after_terminal_status() {
        let temp = tempfile::tempdir().unwrap();
        let index = empty_index(temp.path());
        let generation = index.generation_id().to_owned();
        let pro = RecordingPro::default();
        let (run, opens) = ctx_history_refresh::count_verified_index_opens(|| {
            run_with(
                temp.path(),
                &generation,
                ProCatchUpAuthority {
                    generation_id: Some(&generation),
                    verified_index: Some(&index),
                },
                &pro,
                |_| Ok(()),
                |_, supplied| {
                    Ok(ProCatchUpSyncOutcome::Finished {
                        receipt: receipt(supplied),
                        did_work: true,
                        helper_artifact_sha256: "a".repeat(64),
                    })
                },
            )
            .unwrap()
        });

        assert_eq!(opens, 0);
        assert!(run.did_work);
        assert!(!run.continuation_pending);
        assert_eq!(run.status["status"], "completed");
        assert_eq!(run.status["receipt_core_generation_id"], generation);
        assert_eq!(pro.reconstructed.load(Ordering::SeqCst), 0);
        assert_eq!(pro.released.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn pending_finalization_reconstructs_lease_and_yields_without_backoff() {
        let temp = tempfile::tempdir().unwrap();
        let index = empty_index(temp.path());
        let generation = index.generation_id().to_owned();
        let pro = RecordingPro::default();
        let run = run_with(
            temp.path(),
            &generation,
            ProCatchUpAuthority {
                generation_id: Some(&generation),
                verified_index: Some(&index),
            },
            &pro,
            |_| Ok(()),
            |_, supplied| {
                Ok(ProCatchUpSyncOutcome::FinalizationPending {
                    pending: CoreMaterializationFinalizationPending {
                        progress: progress(supplied),
                        replayed: false,
                    },
                })
            },
        )
        .unwrap();

        assert!(run.did_work);
        assert!(run.continuation_pending);
        assert_eq!(run.status["status"], "pending");
        assert_eq!(run.status["retryable"], false);
        assert_eq!(run.status["reason"], "finalizing");
        assert_eq!(pro.reconstructed.load(Ordering::SeqCst), 1);
        assert_eq!(pro.released.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn stable_port_error_code_controls_terminal_retry_policy() {
        let temp = tempfile::tempdir().unwrap();
        let index = empty_index(temp.path());
        let generation = index.generation_id().to_owned();
        let pro = RecordingPro::default();
        let run = run_with(
            temp.path(),
            &generation,
            ProCatchUpAuthority {
                generation_id: Some(&generation),
                verified_index: Some(&index),
            },
            &pro,
            |_| anyhow::bail!("host unavailable"),
            |_, _| unreachable!(),
        )
        .unwrap();

        assert_eq!(run.status["status"], "error");
        assert_eq!(run.status["error_code"], "pro_not_installed");
        assert_eq!(run.status["retryable"], false);
        assert_eq!(pro.released.load(Ordering::SeqCst), 1);
    }
}
