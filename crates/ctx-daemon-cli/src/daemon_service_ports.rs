use std::path::Path;

use anyhow::{Context, Result};
use ctx_client_observability::analytics::PublicEventV1;
use ctx_daemon_service::{
    DaemonAvailability, DaemonAvailabilityPort, DaemonConfigPort, DaemonConfigSnapshot,
    DaemonInstallationLease, DaemonInstallationPort, DaemonMode, DaemonObservationPort,
    DaemonProductConfig, DaemonServicePorts, DaemonTrigger, ProCatchUpOutcome, ProCatchUpPort,
};
use ctx_history_capture::DiscoveryContext;
use ctx_history_index::{
    release_generation_retention_lease, GenerationRetentionLease, VerifiedIndex,
};
use ctx_pro_host_protocol::CoreMaterializationFinalizationProgress;
use ctx_semantic_model::{ArtifactFetchRequest, ArtifactFetcher, SemanticModelConfig};

use crate::{config::AppConfig, DaemonTriggerCommandArg};

pub(super) static CONFIG: CliDaemonConfigPort = CliDaemonConfigPort;
pub(super) static AVAILABILITY: CliDaemonAvailabilityPort = CliDaemonAvailabilityPort;
pub(super) static INSTALLATION: CliDaemonInstallationPort = CliDaemonInstallationPort;
pub(super) static PRO_CATCH_UP: CliProCatchUpPort = CliProCatchUpPort;
pub(crate) static OBSERVATION: CliDaemonObservationPort = CliDaemonObservationPort;
pub(super) static ARTIFACT_FETCHER: CliDaemonArtifactFetcher = CliDaemonArtifactFetcher;

pub(super) static PORTS: DaemonServicePorts<
    'static,
    dyn DaemonConfigPort,
    dyn DaemonAvailabilityPort,
    CliDaemonInstallationPort,
    dyn ProCatchUpPort<FinalizationLeaseToken = GenerationRetentionLease>,
    dyn DaemonObservationPort,
> = DaemonServicePorts {
    config: &CONFIG,
    availability: &AVAILABILITY,
    installation: &INSTALLATION,
    pro_catch_up: &PRO_CATCH_UP,
    observation: &OBSERVATION,
    artifact_fetcher: &ARTIFACT_FETCHER,
};

pub fn config_snapshot(config: &AppConfig<'_>) -> DaemonConfigSnapshot {
    config_snapshot_with_channel(config, config.upgrade_channel().to_owned())
}

fn into_config_snapshot(mut config: AppConfig<'static>) -> DaemonConfigSnapshot {
    let upgrade_channel = std::mem::take(&mut config.upgrade.channel).into_owned();
    config_snapshot_with_channel(&config, upgrade_channel)
}

fn config_snapshot_with_channel(
    config: &AppConfig<'_>,
    upgrade_channel: String,
) -> DaemonConfigSnapshot {
    DaemonConfigSnapshot {
        daemon: DaemonProductConfig {
            enabled: config.daemon.enabled,
            mode: match config.daemon.mode {
                crate::config::DaemonMode::Full => DaemonMode::Full,
                crate::config::DaemonMode::SourceRefreshOnly => DaemonMode::SourceRefreshOnly,
            },
        },
        semantic_enabled: config.semantic_search_enabled(),
        automatic_upgrade_enabled: config.auto_upgrade_enabled(),
        automatic_upgrade_interval: config.upgrade.interval,
        upgrade_channel,
    }
}

pub fn run_daemon_service<D, AP, UO>(
    request: ctx_daemon_application::DaemonHostRunRequest,
    data_root: &Path,
    config: &AppConfig<'_>,
    upgrade: &ctx_daemon_service::DaemonUpgradePorts<'_, D, AP, UO>,
) -> Result<()>
where
    D: ctx_upgrade_engine::DaemonUpgradePort + ?Sized,
    AP: ctx_upgrade_engine::AutomaticUpgradePolicyProvider<Snapshot = DaemonConfigSnapshot>,
    UO: ctx_upgrade_engine::UpgradeObserver<DaemonConfigSnapshot>,
{
    use ctx_daemon_service::{DaemonRunArgs, DaemonStartMode, DaemonSupervisor, DaemonTrigger};

    let service_args = DaemonRunArgs {
        idle_exit_seconds: request.idle_exit_seconds,
        loop_interval_seconds: request.loop_interval_seconds,
        max_chunks: request.max_chunks,
        max_seconds: None,
        force: request.force,
        start_mode: request.start_mode.map(|mode| match mode {
            ctx_daemon_application::DaemonHostStartMode::Manual => DaemonStartMode::Manual,
            ctx_daemon_application::DaemonHostStartMode::Auto => DaemonStartMode::Auto,
        }),
        trigger_command: request.trigger.map(|trigger| match trigger {
            ctx_daemon_application::DaemonTrigger::Setup => DaemonTrigger::Setup,
            ctx_daemon_application::DaemonTrigger::Import => DaemonTrigger::Import,
            ctx_daemon_application::DaemonTrigger::Search => DaemonTrigger::Search,
        }),
        supervisor: if matches!(
            request.start_mode,
            Some(ctx_daemon_application::DaemonHostStartMode::Auto)
        ) && super::health_search::semantic_env_flag(
            super::runtime_limits::DAEMON_BACKGROUND_CHILD_ENV,
        ) {
            DaemonSupervisor::CliAutostart
        } else {
            DaemonSupervisor::User
        },
    };
    ctx_daemon_service::run_daemon(
        service_args,
        data_root,
        config_snapshot(config),
        &PORTS,
        upgrade,
    )
}

pub(super) struct CliDaemonConfigPort;

impl DaemonConfigPort for CliDaemonConfigPort {
    fn load(&self, data_root: &Path) -> Result<DaemonConfigSnapshot> {
        AppConfig::load(data_root).map(into_config_snapshot)
    }

    fn semantic_model_config(&self, data_root: &Path) -> SemanticModelConfig {
        super::model_config::semantic_model_config(data_root)
    }

    fn discovery_context(&self, _data_root: &Path) -> Result<DiscoveryContext> {
        let home = crate::identity::home_dir()
            .context("resolve the user home for source-backed provider discovery")?;
        Ok(DiscoveryContext::from_process(home))
    }
}

pub(super) struct CliDaemonAvailabilityPort;

impl DaemonAvailabilityPort for CliDaemonAvailabilityPort {
    fn ensure_available(
        &self,
        data_root: &Path,
        trigger: DaemonTrigger,
    ) -> Result<DaemonAvailability> {
        let config = AppConfig::load(data_root)
            .context("load daemon configuration before availability check")?;
        if !config.daemon.enabled {
            return Ok(DaemonAvailability::Disabled);
        }
        super::daemon_autostart::autostart_daemon_and_wait(
            data_root,
            &config,
            cli_trigger(trigger),
        )?;
        Ok(DaemonAvailability::Available)
    }
}

pub(super) struct CliDaemonInstallationPort;

pub(super) struct CliDaemonInstallationLease(super::daemon_autostart::InstallationDaemonLease);

impl DaemonInstallationLease for CliDaemonInstallationLease {
    fn acknowledge(self, attempt_id: &str) -> Result<()> {
        self.0.acknowledge(attempt_id)
    }
}

impl DaemonInstallationPort for CliDaemonInstallationPort {
    type Lease = CliDaemonInstallationLease;

    fn lifecycle_blocks_current_process(&self, data_root: &Path) -> bool {
        ctx_upgrade_engine::installation_hosted_uninstall_is_active().unwrap_or(true)
            || (!super::daemon_autostart::current_process_owns_daemon_upgrade_handoff(data_root)
                && ctx_upgrade_engine::installation_upgrade_is_active().unwrap_or(false))
    }

    fn upgrade_handoff_blocks_current_process(&self, data_root: &Path) -> bool {
        super::daemon_autostart::daemon_upgrade_handoff_blocks_current_process(data_root)
    }

    fn current_process_owns_upgrade_handoff(&self, data_root: &Path) -> bool {
        super::daemon_autostart::current_process_owns_daemon_upgrade_handoff(data_root)
    }

    fn acquire(
        &self,
        data_root: &Path,
        trigger: DaemonTrigger,
        idle_exit_seconds: Option<u64>,
        loop_interval_seconds: Option<u64>,
        allow_active_upgrade: bool,
    ) -> Result<Option<Self::Lease>> {
        super::daemon_autostart::InstallationDaemonLease::acquire(
            data_root,
            cli_trigger(trigger),
            idle_exit_seconds,
            loop_interval_seconds,
            allow_active_upgrade,
        )
        .map(|lease| lease.map(CliDaemonInstallationLease))
    }

    fn resume_completed(&self, data_root: &Path) -> Result<()> {
        super::daemon_autostart::resume_completed_installation_daemons(data_root)
    }

    fn acknowledge_restart_requests(&self, data_root: &Path) {
        super::daemon_autostart::acknowledge_daemon_restart_requests(data_root);
    }
}

pub(super) struct CliProCatchUpPort;

impl ProCatchUpPort for CliProCatchUpPort {
    type FinalizationLeaseToken = GenerationRetentionLease;

    fn preflight(&self, data_root: &Path) -> Result<()> {
        crate::pro::preflight_core_materialization(data_root)
    }

    fn sync(&self, data_root: &Path, index: &VerifiedIndex) -> Result<ProCatchUpOutcome> {
        Ok(
            match crate::pro::sync_core_materialization(data_root, index)? {
                crate::pro::CoreMaterializationSyncOutcome::Finished {
                    receipt,
                    did_work,
                    helper_artifact_sha256,
                } => ProCatchUpOutcome::Finished {
                    receipt,
                    did_work,
                    helper_artifact_sha256,
                },
                crate::pro::CoreMaterializationSyncOutcome::FinalizationPending { pending } => {
                    ProCatchUpOutcome::FinalizationPending { pending }
                }
            },
        )
    }

    fn finalization_lease(&self, data_root: &Path) -> Result<Option<GenerationRetentionLease>> {
        crate::pro::core_finalization_generation_lease(data_root)
    }

    fn finalization_lease_generation<'a>(&self, lease: &'a GenerationRetentionLease) -> &'a str {
        lease.generation_id()
    }

    fn release_observed_finalization_lease(
        &self,
        data_root: &Path,
        lease: &GenerationRetentionLease,
    ) -> Result<bool> {
        release_generation_retention_lease(
            ctx_history_refresh::source_backed_index_root(data_root),
            lease,
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "invalid_response: durable Core generation lease changed before terminal release: {error}"
            )
        })
    }

    fn reconstruct_finalization_lease(
        &self,
        data_root: &Path,
        progress: &CoreMaterializationFinalizationProgress,
    ) -> Result<()> {
        crate::pro::reconstruct_core_finalization_generation_lease(data_root, progress)
    }

    fn validate_finalization_lease(
        &self,
        data_root: &Path,
        progress: &CoreMaterializationFinalizationProgress,
    ) -> Result<()> {
        crate::pro::validate_core_finalization_generation_lease(data_root, progress)
    }

    fn release_finalization_lease(
        &self,
        data_root: &Path,
        generation_id: Option<&str>,
    ) -> Result<bool> {
        crate::pro::release_core_finalization_generation_lease(data_root, generation_id)
    }

    fn selected_helper_artifact_sha256(&self, data_root: &Path) -> Result<Option<String>> {
        crate::pro::selected_helper_artifact_sha256(data_root)
    }

    fn stable_error_code(&self, error: &anyhow::Error) -> Option<&'static str> {
        crate::pro::stable_error_code(error)
    }
}

pub(crate) struct CliDaemonObservationPort;

impl DaemonObservationPort for CliDaemonObservationPort {
    fn deliver(&self, data_root: &Path, events: &[PublicEventV1]) {
        if events.is_empty() {
            return;
        }
        crate::analytics::send_batch(data_root, events);
    }
}

pub fn deliver_daemon_events(data_root: &Path, events: &[PublicEventV1]) {
    OBSERVATION.deliver(data_root, events);
}

pub(super) struct CliDaemonArtifactFetcher;

impl ArtifactFetcher for CliDaemonArtifactFetcher {
    fn fetch_to_writer(
        &self,
        request: ArtifactFetchRequest<'_>,
        mut writer: &mut dyn std::io::Write,
    ) -> Result<u64> {
        crate::net::get_to_writer_limited(
            request.endpoint(),
            request.max_bytes(),
            request.timeout(),
            &mut writer,
        )
    }
}

fn cli_trigger(trigger: DaemonTrigger) -> DaemonTriggerCommandArg {
    match trigger {
        DaemonTrigger::Setup => DaemonTriggerCommandArg::Setup,
        DaemonTrigger::Import => DaemonTriggerCommandArg::Import,
        DaemonTrigger::Search => DaemonTriggerCommandArg::Search,
    }
}
