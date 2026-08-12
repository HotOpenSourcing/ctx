use std::path::Path;

use anyhow::{anyhow, bail, Result};
use ctx_pro_host::{stable_error_code, HelperSmoke, ProStatus};
use ctx_pro_lifecycle::{
    installation::{reconcile_setup_installation, SetupInstallation},
    operation::LifecycleOperation,
    release_manifest::ReleaseTrust,
    state_markers,
};

use crate::{
    setup_artifact, validate_access_status, validate_account_state, validate_portal_url,
    validate_staged_helper, MaterializationMode, MaterializationOutcome, ProApplication,
    ProApplicationHost,
};

/// Coarse setup boundary implemented by the executable's concrete identity,
/// helper-verification, and installation adapter.
pub trait SetupCommandHost<A> {
    fn initialize_setup_identity(&self, data_root: &Path) -> Result<()>;

    fn smoke_setup_artifact(&self, data_root: &Path, artifact: &A) -> Result<HelperSmoke>;

    /// Returns whether the selected artifact replaced the installed helper.
    fn install_setup_artifact(
        &self,
        artifact: &A,
        operation: &LifecycleOperation,
        trust: ReleaseTrust,
    ) -> Result<bool>;
}

pub struct SetupAccessRequest<'a> {
    pub operation: &'a LifecycleOperation,
    pub data_root: &'a Path,
    pub installed_version: Option<&'a str>,
    pub trial_only: bool,
    pub referral_codename: Option<&'a str>,
}

/// Headless access and artifact acquisition for setup. Implementations may
/// perform commercial service calls, but receive no presentation callbacks.
pub trait SetupAccess<A> {
    fn release_trust(&self) -> Result<ReleaseTrust>;
    fn setup(&mut self, request: SetupAccessRequest<'_>) -> Result<SetupPlan<A>>;
}

/// Headless account-management service operation. Browser opening and output
/// routing remain outside this port.
pub trait ManageAccess {
    fn manage(&mut self, data_root: &Path) -> Result<ManagePlan>;
}

#[derive(Debug)]
pub struct SetupPlan<A> {
    pub artifact: Option<A>,
    pub account_state: String,
}

#[derive(Debug)]
pub struct ManagePlan {
    pub portal_url: String,
    pub access_state: String,
    pub refresh_after_unix: Option<i64>,
    pub access_deadline_unix: Option<i64>,
    pub grace_deadline_unix: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReconcileFact {
    #[default]
    NotAttempted,
    Missing,
    Current,
    Installed,
    Updated,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum HelperConnectionFact {
    #[default]
    NotAttempted,
    Connected,
    Failed {
        error_code: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializationFact {
    Completed {
        mode: MaterializationMode,
        batches: u64,
        source_count: u64,
        replayed_batches: u64,
    },
    Failed {
        error_code: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LifecycleCommandFacts {
    pub reconcile: ReconcileFact,
    pub access_state: Option<String>,
    pub helper_connection: HelperConnectionFact,
    pub materialization: Option<MaterializationFact>,
}

pub struct LifecycleExecution<T> {
    pub facts: LifecycleCommandFacts,
    pub result: Result<T>,
}

pub struct SetupStart<'a> {
    data_root: &'a Path,
}

pub enum SetupAdmission<'a> {
    Start(SetupStart<'a>),
    Replayed(SetupCommandOutcome),
}

#[derive(Debug, Clone)]
pub enum SetupCompletion {
    Materialized(MaterializationOutcome),
    Deferred,
}

pub struct SetupCommandOutcome {
    pub account_state: String,
    pub helper_updated: bool,
    pub completion: SetupCompletion,
    _operation: Option<LifecycleOperation>,
}

pub struct ManageCommandOutcome {
    pub plan: ManagePlan,
    _operation: LifecycleOperation,
}

pub fn reusable_setup_access_state(
    helper: &ProStatus,
    trial_only: bool,
    referral_codename: Option<&str>,
) -> Option<String> {
    if trial_only
        || referral_codename.is_some()
        || !helper.installed
        || !helper.ready
        || !helper.materialized
    {
        return None;
    }
    let account_state = helper.access_state.as_deref()?;
    validate_account_state(account_state).ok()?;
    Some(account_state.to_owned())
}

impl<'a, H: ProApplicationHost + ?Sized> ProApplication<'a, H> {
    /// Initializes local identity, queries passive status exactly once, and
    /// either replays a completed setup without commercial service authority
    /// or returns admission for the ordinary setup path.
    pub fn admit_setup<'root, A>(
        &self,
        data_root: &'root Path,
        trial_only: bool,
        referral_codename: Option<&str>,
    ) -> LifecycleExecution<SetupAdmission<'root>>
    where
        H: SetupCommandHost<A>,
    {
        let mut facts = LifecycleCommandFacts::default();
        let result = (|| {
            self.host.initialize_setup_identity(data_root)?;
            let Some(account_state) =
                reusable_setup_access_state(&self.status(data_root), trial_only, referral_codename)
            else {
                return Ok(SetupAdmission::Start(SetupStart { data_root }));
            };

            facts.reconcile = ReconcileFact::Current;
            facts.access_state = Some(account_state.clone());
            let materialized = self.materialize_with_facts(data_root, None, &mut facts)?;
            Ok(SetupAdmission::Replayed(SetupCommandOutcome {
                account_state,
                helper_updated: false,
                completion: SetupCompletion::Materialized(materialized),
                _operation: None,
            }))
        })();
        LifecycleExecution { facts, result }
    }

    pub fn setup<A>(
        &self,
        admission: SetupStart<'_>,
        access: &mut impl SetupAccess<A>,
        defer_materialization: bool,
        trial_only: bool,
        referral_codename: Option<&str>,
    ) -> LifecycleExecution<SetupCommandOutcome>
    where
        H: SetupCommandHost<A>,
    {
        let mut facts = LifecycleCommandFacts::default();
        let result = self.setup_inner(
            admission,
            access,
            defer_materialization,
            trial_only,
            referral_codename,
            &mut facts,
        );
        LifecycleExecution { facts, result }
    }

    fn setup_inner<A>(
        &self,
        admission: SetupStart<'_>,
        access: &mut impl SetupAccess<A>,
        defer_materialization: bool,
        trial_only: bool,
        referral_codename: Option<&str>,
        facts: &mut LifecycleCommandFacts,
    ) -> Result<SetupCommandOutcome>
    where
        H: SetupCommandHost<A>,
    {
        let trust = access.release_trust()?;
        facts.reconcile = ReconcileFact::Failed;
        let operation = begin_pro_operation(admission.data_root)?;
        let installation = reconcile_setup_installation(&operation, trust)?;
        let plan = access.setup(SetupAccessRequest {
            operation: &operation,
            data_root: admission.data_root,
            installed_version: installation.installed_version(),
            trial_only,
            referral_codename,
        })?;
        let replacing_existing = matches!(
            &installation,
            SetupInstallation::Current(_) | SetupInstallation::RepairRequired
        );
        facts.reconcile = match &installation {
            SetupInstallation::Current(_) => ReconcileFact::Current,
            SetupInstallation::Missing => ReconcileFact::Missing,
            SetupInstallation::RepairRequired => ReconcileFact::Failed,
        };
        validate_account_state(&plan.account_state)?;
        facts.access_state = Some(plan.account_state.clone());
        let artifact = setup_artifact(&installation, plan.artifact)?;
        let helper_updated = if let Some(artifact) = artifact {
            let smoke = self
                .host
                .smoke_setup_artifact(admission.data_root, &artifact)
                .inspect_err(|error| {
                    facts.helper_connection = HelperConnectionFact::Failed {
                        error_code: stable_error_code(error).map(str::to_owned),
                    };
                })?;
            facts.helper_connection = HelperConnectionFact::Connected;
            validate_staged_helper(&smoke)?;
            let installed = self
                .host
                .install_setup_artifact(&artifact, &operation, trust)?;
            if installed {
                facts.reconcile = if replacing_existing {
                    ReconcileFact::Updated
                } else {
                    ReconcileFact::Installed
                };
            }
            installed
        } else {
            false
        };

        let completion = if defer_materialization {
            operation.require_data_root(admission.data_root)?;
            state_markers::request_materialization(&operation)?;
            SetupCompletion::Deferred
        } else {
            // An empty repository-root set still materializes canonical transcript evidence.
            SetupCompletion::Materialized(self.materialize_with_facts(
                admission.data_root,
                Some(&operation),
                facts,
            )?)
        };
        Ok(SetupCommandOutcome {
            account_state: plan.account_state,
            helper_updated,
            completion,
            _operation: Some(operation),
        })
    }

    pub fn manage(
        &self,
        data_root: &Path,
        access: &mut impl ManageAccess,
    ) -> LifecycleExecution<ManageCommandOutcome> {
        let mut facts = LifecycleCommandFacts::default();
        let result = (|| {
            let operation = begin_pro_operation(data_root)?;
            let plan = access.manage(data_root)?;
            validate_portal_url(&plan.portal_url)?;
            validate_access_status(
                &plan.access_state,
                plan.refresh_after_unix,
                plan.access_deadline_unix,
                plan.grace_deadline_unix,
            )?;
            facts.access_state = Some(plan.access_state.clone());
            Ok(ManageCommandOutcome {
                plan,
                _operation: operation,
            })
        })();
        LifecycleExecution { facts, result }
    }

    fn materialize_with_facts(
        &self,
        data_root: &Path,
        operation: Option<&LifecycleOperation>,
        facts: &mut LifecycleCommandFacts,
    ) -> Result<MaterializationOutcome> {
        match self.materialize_in(data_root, operation) {
            Ok(outcome) => {
                facts.helper_connection = HelperConnectionFact::Connected;
                facts.materialization = Some(MaterializationFact::Completed {
                    mode: outcome.mode,
                    batches: outcome.report.batches,
                    source_count: outcome.report.source_count,
                    replayed_batches: outcome.report.replayed_batches,
                });
                Ok(outcome)
            }
            Err(error) => {
                facts.materialization = Some(MaterializationFact::Failed {
                    error_code: stable_error_code(&error).map(str::to_owned),
                });
                Err(error)
            }
        }
    }
}

fn begin_pro_operation(data_root: &Path) -> Result<LifecycleOperation> {
    let operation = LifecycleOperation::begin(data_root, true)?
        .ok_or_else(|| anyhow!("invalid_request: failed to create Pro lifecycle lock"))?;
    if ctx_pro_lifecycle::deletion::local_pro_graph_key_cleanup_phase_exists(data_root)? {
        bail!(
            "key_store_unavailable: interrupted Pro deletion must be completed with `ctx pro uninstall --delete-data`"
        );
    }
    state_markers::mark_initialized(&operation)?;
    Ok(operation)
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, path::PathBuf};

    use ctx_pro_host::{
        AuthorizationMode, AuthorizationReceipt, CoreGenerationHost, CoreGenerationPin,
        InstalledProHost, ProSetupRepairability,
    };
    use ctx_pro_host_protocol::PROTOCOL_VERSION;
    use ctx_pro_lifecycle::{
        installed_artifact::ValidatedArtifactIdentity,
        release_manifest::{release_trust, ReleaseChannel},
    };

    use super::*;

    #[derive(Default)]
    struct RecordingHost {
        events: RefCell<Vec<&'static str>>,
    }

    struct RecordingPin;

    impl CoreGenerationPin for RecordingPin {
        fn generation_id(&self) -> &str {
            "unused"
        }
    }

    impl InstalledProHost for RecordingHost {
        fn host_version(&self) -> &str {
            "1.0.0"
        }

        fn existing_installation_id(&self, _data_root: &Path) -> Result<Option<String>> {
            Ok(None)
        }

        fn validated_installed_helper(
            &self,
            _data_root: &Path,
            _operation: Option<&LifecycleOperation>,
        ) -> Result<ValidatedArtifactIdentity> {
            bail!("unused")
        }

        fn authorization_for_challenge(
            &self,
            _data_root: &Path,
            _challenge: &[u8; ctx_pro_host_protocol::AUTHORIZATION_CHALLENGE_BYTES],
            _mode: AuthorizationMode,
        ) -> Result<AuthorizationReceipt> {
            bail!("unused")
        }

        fn unix_time(&self) -> Result<i64> {
            Ok(0)
        }
    }

    impl CoreGenerationHost for RecordingHost {
        type Pin = RecordingPin;

        fn pin_active_core_generation(&self, _data_root: &Path) -> Result<Self::Pin> {
            bail!("unused")
        }
    }

    impl crate::CoreOrchestration for RecordingHost {
        fn prepare_materialization_generation(&self, _data_root: &Path) -> Result<String> {
            bail!("unused")
        }

        fn wait_for_pro_generation(&self, _data_root: &Path, _generation_id: &str) -> Result<()> {
            bail!("unused")
        }

        fn wake_blame_refresh(&self, _data_root: &Path) -> Result<()> {
            bail!("unused")
        }

        fn cancel_core_finalization(&self, _data_root: &Path, _reason: &str) -> Result<()> {
            bail!("unused")
        }
    }

    impl SetupCommandHost<()> for RecordingHost {
        fn initialize_setup_identity(&self, _data_root: &Path) -> Result<()> {
            self.events.borrow_mut().push("identity");
            Ok(())
        }

        fn smoke_setup_artifact(&self, data_root: &Path, _artifact: &()) -> Result<HelperSmoke> {
            assert!(!state_markers::materialization_pending(data_root)?);
            self.events.borrow_mut().push("smoke");
            Ok(HelperSmoke {
                protocol_version: ctx_pro_host_protocol::PROTOCOL_VERSION,
                protocol_fingerprint: ctx_pro_host_protocol::PROTOCOL_FINGERPRINT.to_owned(),
                helper_version: "1.0.0".to_owned(),
                capabilities: [
                    ctx_pro_host_protocol::Capability::EntitlementAuthorization,
                    ctx_pro_host_protocol::Capability::Status,
                ]
                .into_iter()
                .collect(),
            })
        }

        fn install_setup_artifact(
            &self,
            _artifact: &(),
            operation: &LifecycleOperation,
            _trust: ReleaseTrust,
        ) -> Result<bool> {
            assert!(!state_markers::materialization_pending(
                operation.data_root()
            )?);
            self.events.borrow_mut().push("install");
            Ok(true)
        }
    }

    struct RecordingSetupAccess<'a> {
        host: &'a RecordingHost,
    }

    impl SetupAccess<()> for RecordingSetupAccess<'_> {
        fn release_trust(&self) -> Result<ReleaseTrust> {
            self.host.events.borrow_mut().push("release_trust");
            release_trust(ReleaseChannel::Stable)
        }

        fn setup(&mut self, request: SetupAccessRequest<'_>) -> Result<SetupPlan<()>> {
            request.operation.require_data_root(request.data_root)?;
            assert_eq!(request.installed_version, None);
            assert!(!request.trial_only);
            assert_eq!(request.referral_codename, None);
            assert!(!state_markers::materialization_pending(request.data_root)?);
            self.host.events.borrow_mut().push("setup_access");
            Ok(SetupPlan {
                artifact: Some(()),
                account_state: "active".to_owned(),
            })
        }
    }

    struct RecordingManageAccess<'a> {
        host: &'a RecordingHost,
    }

    impl ManageAccess for RecordingManageAccess<'_> {
        fn manage(&mut self, _data_root: &Path) -> Result<ManagePlan> {
            self.host.events.borrow_mut().push("manage_access");
            Ok(ManagePlan {
                portal_url: "https://billing.example.test/session".to_owned(),
                access_state: "canceling_paid".to_owned(),
                refresh_after_unix: Some(100),
                access_deadline_unix: Some(200),
                grace_deadline_unix: Some(300),
            })
        }
    }

    fn private_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        ctx_history_core::platform_security::restrict_private_directory(root.path()).unwrap();
        root
    }

    fn status(access_state: &str) -> ProStatus {
        ProStatus {
            schema_version: 1,
            installed: true,
            ready: true,
            materialized: true,
            helper_path: PathBuf::from("/unused/helper"),
            helper_version: Some("1.0.0".to_owned()),
            protocol_version: PROTOCOL_VERSION,
            capabilities: vec!["status".to_owned()],
            error_code: None,
            projection_currentness: None,
            materialized_coverage: None,
            repository_coverage: None,
            core_preparation_peak_workers: None,
            storage_evidence: None,
            supported_operations: None,
            available_operations: None,
            access_state: Some(access_state.to_owned()),
            refresh_after_unix: None,
            access_deadline_unix: Some(200),
            grace_deadline_unix: None,
            setup_repairability: ProSetupRepairability::NotNeeded,
        }
    }

    #[test]
    fn replay_requires_complete_local_setup_and_current_access() {
        for access_state in ["trial", "active", "canceling_paid"] {
            assert_eq!(
                reusable_setup_access_state(&status(access_state), false, None).as_deref(),
                Some(access_state)
            );
        }
        assert!(reusable_setup_access_state(&status("active"), true, None).is_none());
        assert!(
            reusable_setup_access_state(&status("active"), false, Some("agent-smith")).is_none()
        );
        assert!(reusable_setup_access_state(&status("offline_grace"), false, None).is_none());

        let mut stale = status("active");
        stale.materialized = false;
        assert!(reusable_setup_access_state(&stale, false, None).is_none());
        stale.materialized = true;
        stale.ready = false;
        assert!(reusable_setup_access_state(&stale, false, None).is_none());
    }

    #[test]
    fn deferred_setup_preserves_verification_install_and_marker_order() {
        let root = private_root();
        let host = RecordingHost::default();
        let application = ProApplication::new(&host);
        let mut access = RecordingSetupAccess { host: &host };
        let execution = application.setup(
            SetupStart {
                data_root: root.path(),
            },
            &mut access,
            true,
            false,
            None,
        );
        assert_eq!(
            execution.facts,
            LifecycleCommandFacts {
                reconcile: ReconcileFact::Installed,
                access_state: Some("active".to_owned()),
                helper_connection: HelperConnectionFact::Connected,
                materialization: None,
            }
        );
        let outcome = execution.result.unwrap();
        assert!(matches!(outcome.completion, SetupCompletion::Deferred));
        assert!(outcome.helper_updated);
        assert!(state_markers::materialization_pending(root.path()).unwrap());
        assert!(state_markers::initialization_marker_exists(root.path()).unwrap());
        assert_eq!(
            host.events.borrow().as_slice(),
            ["release_trust", "setup_access", "smoke", "install"]
        );
    }

    #[test]
    fn manage_validates_and_returns_only_headless_state() {
        let root = private_root();
        let host = RecordingHost::default();
        let application = ProApplication::new(&host);
        let mut access = RecordingManageAccess { host: &host };
        let execution = application.manage(root.path(), &mut access);
        assert_eq!(
            execution.facts.access_state.as_deref(),
            Some("canceling_paid")
        );
        let outcome = execution.result.unwrap();
        assert_eq!(
            outcome.plan.portal_url,
            "https://billing.example.test/session"
        );
        assert_eq!(host.events.borrow().as_slice(), ["manage_access"]);
        assert!(state_markers::initialization_marker_exists(root.path()).unwrap());
    }
}
