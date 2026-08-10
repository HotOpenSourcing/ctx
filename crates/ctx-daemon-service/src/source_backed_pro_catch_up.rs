use std::time::Duration;

use ctx_history_index::VerifiedIndex;
use serde_json::Value;

use super::{
    paths_status::{daemon_jobs_path, write_daemon_job_status},
    source_backed_refresh_coordinator::{PinnedCorePublication, PinnedSourceBackedGeneration},
};

mod finalization;
mod lease_reconciliation;
mod recheck;
mod status;

pub(super) use finalization::run_after_core_publication;
pub use finalization::wait_for_completed_generation;
pub use lease_reconciliation::cancel_core_finalization_generation_lease;
pub(super) use lease_reconciliation::reconcile_core_finalization_generation_lease;
pub(super) use recheck::schedule as helper_recheck_schedule;
pub use recheck::{
    publish as publish_helper_recheck_intent, targets as helper_recheck_targets,
    wake as wake_helper_recheck,
};
pub(super) use status::{
    persist_status_json, read_status_json, scheduled_target_generation, status_generation,
    status_has_finalization_pending,
};

const SOURCE_BACKED_PRO_CATCH_UP_WAKE_TIMEOUT: Duration = Duration::from_millis(500);
const SOURCE_BACKED_PRO_CATCH_UP_WAKE_RESPONSE_MAX_BYTES: u64 = 64 * 1024;

pub struct SourceBackedProCatchUpRun {
    pub status: Value,
    pub did_work: bool,
    pub continuation_pending: bool,
}

#[derive(Clone, Copy)]
pub(super) enum SourceBackedProCoreAuthority<'a> {
    Retained(&'a PinnedCorePublication),
    Durable(&'a PinnedSourceBackedGeneration),
}

impl<'a> SourceBackedProCoreAuthority<'a> {
    pub(super) fn generation_id(self) -> &'a str {
        match self {
            Self::Retained(authority) => authority.generation_id(),
            Self::Durable(authority) => authority.generation_id(),
        }
    }

    fn verified_index(self) -> &'a VerifiedIndex {
        match self {
            Self::Retained(authority) => authority.verified_index_ref(),
            Self::Durable(authority) => authority.verified_index(),
        }
    }

    fn surface(self) -> &'static str {
        match self {
            Self::Retained(_) => "retained Core generation pin",
            Self::Durable(_) => "durable active Core generation pin",
        }
    }
}

#[cfg(feature = "test-support")]
pub mod testing {
    use std::path::{Path, PathBuf};

    use anyhow::Result;
    use ctx_pro_host_protocol::CoreMaterializationFinalizationProgress;
    use serde_json::Value;

    pub use super::finalization::{
        run_with as run_pro_catch_up_with, wait_for_completed_generation_with, ProCatchUpAuthority,
        ProCatchUpSyncOutcome,
    };
    pub use super::lease_reconciliation::reconcile_core_finalization_generation_lease;
    pub use super::SourceBackedProCatchUpRun;

    pub fn persist_finalizing_status(
        data_root: &Path,
        generation: &str,
        attempts: u64,
        progress: CoreMaterializationFinalizationProgress,
    ) -> Result<()> {
        super::status::persist_status(
            data_root,
            &super::status::SourceBackedProCatchUpStatus::pending(generation, attempts)
                .finalizing(progress),
        )
    }

    pub fn persist_completed_status(data_root: &Path, generation: &str) -> Result<()> {
        super::status::persist_status(
            data_root,
            &super::status::SourceBackedProCatchUpStatus::pending(generation, 1)
                .completed(generation.to_owned()),
        )
    }

    pub fn pro_catch_up_status_path(data_root: &Path) -> PathBuf {
        super::status::status_path(data_root)
    }

    pub fn read_pro_catch_up_status(data_root: &Path) -> Option<Value> {
        super::status::read_status_json(data_root)
    }

    pub fn scheduled_pro_catch_up_target(data_root: &Path) -> Result<Option<String>> {
        super::status::scheduled_target_generation(data_root)
    }

    pub fn pro_catch_up_has_finalization_pending(data_root: &Path, generation: &str) -> bool {
        super::status::status_has_finalization_pending(data_root, generation)
    }

    pub fn helper_recheck_target(data_root: &Path) -> Result<Option<String>> {
        Ok(super::recheck::read(data_root)?.map(|intent| intent.target_helper_sha256().to_owned()))
    }
}
