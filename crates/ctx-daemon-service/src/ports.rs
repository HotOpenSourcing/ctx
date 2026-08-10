use std::{path::Path, time::Duration};

use anyhow::Result;
use ctx_client_observability::analytics::PublicEventV1;
use ctx_history_capture::DiscoveryContext;
use ctx_history_index::VerifiedIndex;
use ctx_pro_host_protocol::{
    CoreMaterializationFinalizationPending, CoreMaterializationFinalizationProgress,
    CoreMaterializationReceipt,
};
use ctx_semantic_model::SemanticModelConfig;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DaemonMode {
    #[default]
    Full,
    SourceRefreshOnly,
}

impl DaemonMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::SourceRefreshOnly => "source-refresh-only",
        }
    }

    pub const fn runs_only_source_refresh(self) -> bool {
        matches!(self, Self::SourceRefreshOnly)
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "full" => Some(Self::Full),
            "source-refresh-only" => Some(Self::SourceRefreshOnly),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DaemonStartMode {
    #[default]
    Manual,
    Auto,
}

impl DaemonStartMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Auto => "auto",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonTrigger {
    Setup,
    Import,
    Search,
}

impl DaemonTrigger {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Import => "import",
            Self::Search => "search",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DaemonRunArgs {
    pub idle_exit_seconds: Option<u64>,
    pub loop_interval_seconds: Option<u64>,
    pub max_chunks: Option<usize>,
    pub max_seconds: Option<u64>,
    pub force: bool,
    pub start_mode: Option<DaemonStartMode>,
    pub trigger_command: Option<DaemonTrigger>,
    pub supervisor: DaemonSupervisor,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DaemonSupervisor {
    #[default]
    User,
    CliAutostart,
}

#[derive(Debug, Clone, Default)]
pub struct DaemonConfigSnapshot {
    pub daemon: DaemonProductConfig,
    pub semantic_enabled: bool,
    pub automatic_upgrade_enabled: bool,
    pub automatic_upgrade_interval: Duration,
    pub upgrade_channel: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DaemonProductConfig {
    pub enabled: bool,
    pub mode: DaemonMode,
}

impl DaemonConfigSnapshot {
    pub const fn semantic_search_enabled(&self) -> bool {
        self.semantic_enabled
    }
}

impl ctx_upgrade_engine::AutomaticUpgradePolicySnapshot for DaemonConfigSnapshot {
    fn daemon_enabled(&self) -> bool {
        self.daemon.enabled
    }

    fn automatic_upgrade_enabled(&self) -> bool {
        self.automatic_upgrade_enabled
    }

    fn interval(&self) -> Duration {
        self.automatic_upgrade_interval
    }

    fn channel(&self) -> &str {
        &self.upgrade_channel
    }

    fn semantic_enabled(&self) -> bool {
        self.semantic_enabled
    }
}

pub trait DaemonConfigPort: Sync {
    fn load(&self, data_root: &Path) -> Result<DaemonConfigSnapshot>;
    fn semantic_model_config(&self, data_root: &Path) -> SemanticModelConfig;
    fn discovery_context(&self, data_root: &Path) -> Result<DiscoveryContext>;
}

pub trait DaemonAvailabilityPort: Sync {
    fn ensure_available(
        &self,
        data_root: &Path,
        trigger: DaemonTrigger,
    ) -> Result<DaemonAvailability>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonAvailability {
    Available,
    Disabled,
}

pub trait DaemonInstallationLease {
    fn acknowledge(self, attempt_id: &str) -> Result<()>;
}

pub trait DaemonInstallationPort {
    type Lease: DaemonInstallationLease;

    fn lifecycle_blocks_current_process(&self, data_root: &Path) -> bool;
    fn upgrade_handoff_blocks_current_process(&self, data_root: &Path) -> bool;
    fn current_process_owns_upgrade_handoff(&self, data_root: &Path) -> bool;
    fn acquire(
        &self,
        data_root: &Path,
        trigger: DaemonTrigger,
        idle_exit_seconds: Option<u64>,
        loop_interval_seconds: Option<u64>,
        allow_active_upgrade: bool,
    ) -> Result<Option<Self::Lease>>;
    fn resume_completed(&self, data_root: &Path) -> Result<()>;
    fn acknowledge_restart_requests(&self, data_root: &Path);
}

pub enum ProCatchUpOutcome {
    Finished {
        receipt: CoreMaterializationReceipt,
        did_work: bool,
        helper_artifact_sha256: String,
    },
    FinalizationPending {
        pending: CoreMaterializationFinalizationPending,
    },
}

pub trait ProCatchUpPort: Sync {
    type FinalizationLeaseToken;

    fn preflight(&self, data_root: &Path) -> Result<()>;
    fn sync(&self, data_root: &Path, index: &VerifiedIndex) -> Result<ProCatchUpOutcome>;
    fn finalization_lease(&self, data_root: &Path) -> Result<Option<Self::FinalizationLeaseToken>>;
    fn finalization_lease_generation<'a>(&self, lease: &'a Self::FinalizationLeaseToken)
        -> &'a str;
    fn release_observed_finalization_lease(
        &self,
        data_root: &Path,
        lease: &Self::FinalizationLeaseToken,
    ) -> Result<bool>;
    fn reconstruct_finalization_lease(
        &self,
        data_root: &Path,
        progress: &CoreMaterializationFinalizationProgress,
    ) -> Result<()>;
    fn validate_finalization_lease(
        &self,
        data_root: &Path,
        progress: &CoreMaterializationFinalizationProgress,
    ) -> Result<()>;
    fn release_finalization_lease(
        &self,
        data_root: &Path,
        generation_id: Option<&str>,
    ) -> Result<bool>;
    fn selected_helper_artifact_sha256(&self, data_root: &Path) -> Result<Option<String>>;
    fn stable_error_code(&self, error: &anyhow::Error) -> Option<&'static str>;
}

pub trait DaemonObservationPort: Sync {
    fn deliver(&self, data_root: &Path, events: &[PublicEventV1]);
}

pub struct DaemonServicePorts<'a, C: ?Sized, A: ?Sized, I, P: ?Sized, O: ?Sized> {
    pub config: &'a C,
    pub availability: &'a A,
    pub installation: &'a I,
    pub pro_catch_up: &'a P,
    pub observation: &'a O,
    pub artifact_fetcher: &'a (dyn ctx_semantic_model::ArtifactFetcher + Sync),
}

pub struct DaemonUpgradePorts<'a, D, P, O>
where
    D: ctx_upgrade_engine::DaemonUpgradePort + ?Sized,
{
    pub engine: &'a ctx_upgrade_engine::UpgradeEngine<'a, D>,
    pub daemon: &'a D,
    pub automatic_policy: &'a P,
    pub observer: &'a O,
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use ctx_upgrade_engine::AutomaticUpgradePolicySnapshot;

    use super::*;

    struct Lease(Arc<AtomicBool>);

    impl DaemonInstallationLease for Lease {
        fn acknowledge(self, attempt_id: &str) -> Result<()> {
            assert_eq!(attempt_id, "install-attempt");
            self.0.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    struct Installation(Arc<AtomicBool>);

    impl DaemonInstallationPort for Installation {
        type Lease = Lease;

        fn lifecycle_blocks_current_process(&self, _data_root: &Path) -> bool {
            false
        }
        fn upgrade_handoff_blocks_current_process(&self, _data_root: &Path) -> bool {
            false
        }
        fn current_process_owns_upgrade_handoff(&self, _data_root: &Path) -> bool {
            false
        }
        fn acquire(
            &self,
            _data_root: &Path,
            _trigger: DaemonTrigger,
            _idle_exit_seconds: Option<u64>,
            _loop_interval_seconds: Option<u64>,
            _allow_active_upgrade: bool,
        ) -> Result<Option<Self::Lease>> {
            Ok(Some(Lease(Arc::clone(&self.0))))
        }
        fn resume_completed(&self, _data_root: &Path) -> Result<()> {
            Ok(())
        }
        fn acknowledge_restart_requests(&self, _data_root: &Path) {}
    }

    #[test]
    fn installation_acknowledgement_consumes_the_service_lease() {
        let acknowledged = Arc::new(AtomicBool::new(false));
        let installation = Installation(Arc::clone(&acknowledged));
        let lease = installation
            .acquire(Path::new("data"), DaemonTrigger::Search, None, None, false)
            .unwrap()
            .unwrap();

        lease.acknowledge("install-attempt").unwrap();
        assert!(acknowledged.load(Ordering::SeqCst));
    }

    #[test]
    fn service_snapshot_is_the_single_borrowed_upgrade_policy() {
        let snapshot = DaemonConfigSnapshot {
            daemon: DaemonProductConfig {
                enabled: true,
                mode: DaemonMode::Full,
            },
            semantic_enabled: true,
            automatic_upgrade_enabled: true,
            automatic_upgrade_interval: Duration::from_secs(3_600),
            upgrade_channel: "stable".to_owned(),
        };

        assert!(snapshot.daemon_enabled());
        assert!(snapshot.semantic_enabled());
        assert!(snapshot.automatic_upgrade_enabled());
        assert_eq!(snapshot.interval(), Duration::from_secs(3_600));
        assert_eq!(snapshot.channel(), "stable");
    }

    #[test]
    fn daemon_mode_wire_names_and_parser_remain_exact() {
        assert_eq!(DaemonMode::Full.as_str(), "full");
        assert_eq!(
            DaemonMode::SourceRefreshOnly.as_str(),
            "source-refresh-only"
        );
        assert_eq!(DaemonMode::parse("FULL"), Some(DaemonMode::Full));
        assert_eq!(
            DaemonMode::parse("SOURCE-REFRESH-ONLY"),
            Some(DaemonMode::SourceRefreshOnly)
        );
        assert_eq!(DaemonMode::parse("source_refresh_only"), None);
    }
}
