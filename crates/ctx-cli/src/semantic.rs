//! Final-binary composition for daemon and semantic adapters.

use std::{io::Write, path::Path, time::Duration};

use anyhow::Result;
use ctx_client_observability::analytics::PublicEventV1;
use ctx_daemon_cli::{AppConfig as DaemonCliConfig, DaemonConfig, DaemonMode};
use ctx_history_index::VerifiedIndex;
use ctx_pro_application::CoreMaterializationSyncOutcome;

pub(crate) use ctx_daemon_cli::{
    begin_daemon_upgrade_handoff, begin_legacy_daemon_upgrade_handoff,
    cancel_core_finalization_generation_lease, complete_replacement_daemon_handoff,
    coordinate_import_source_backed_refresh_with_progress, coordinate_source_backed_refresh,
    coordinate_source_backed_refresh_with_progress, current_rejected_record_count,
    daemon_autostart_suppression_reason, finish_replacement_daemon_handoff,
    mark_replacement_helper_handoff, pin_active_verified_generation,
    publish_source_backed_pro_recheck, published_explicit_source_relocation_authority,
    replacement_helper_owns_daemon_handoff, semantic_managed_model_snapshot_dir,
    semantic_native_accelerator_target, semantic_provisioning_coreml_asset_matches,
    semantic_provisioning_model_contract_matches, semantic_provisioning_model_path_count,
    semantic_provisioning_model_path_matches, semantic_query_service_supported,
    semantic_required_model_file_count, semantic_required_model_file_matches,
    semantic_runtime_cache_dir, semantic_worker_cache_dir, source_backed_pro_recheck_targets,
    wait_for_daemon_query_service, wait_for_source_backed_pro_generation,
    wake_source_backed_pro_recheck, DaemonHandoff, DaemonSetupHandoff, DaemonUpgradeHandoff,
    PinnedSourceBackedGeneration, RefreshStatus, SemanticNativeAcceleratorTarget, SemanticNotReady,
    SemanticOrtModelVariant, SemanticQueryAdapter, SourceBackedRefreshDaemonUnavailable,
    SourceBackedRefreshMode, SourceBackedRefreshObservation, SourceBackedRefreshPendingPublication,
    DAEMON_IDLE_EXIT_SECONDS_CAP, SEMANTIC_WORKER_BATCH_MAX,
};

struct CtxDaemonCliHost;

static HOST: CtxDaemonCliHost = CtxDaemonCliHost;

pub(crate) fn initialize() -> Result<()> {
    ctx_daemon_cli::install_host(&HOST)
}

fn daemon_cli_config(config: &crate::config::AppConfig) -> DaemonCliConfig {
    DaemonCliConfig::new(
        config.analytics.enabled,
        config.auto_upgrade_enabled(),
        config.upgrade.channel.clone(),
        config.upgrade.interval,
        DaemonConfig {
            enabled: config.daemon.enabled,
            mode: match config.daemon.mode {
                crate::config::DaemonMode::Full => DaemonMode::Full,
                crate::config::DaemonMode::SourceRefreshOnly => DaemonMode::SourceRefreshOnly,
            },
        },
        config.semantic_search_enabled(),
        config.semantic_search_source(),
    )
}

fn daemon_trigger(
    trigger: crate::DaemonTriggerCommandArg,
) -> ctx_daemon_cli::DaemonTriggerCommandArg {
    match trigger {
        crate::DaemonTriggerCommandArg::Setup => ctx_daemon_cli::DaemonTriggerCommandArg::Setup,
        crate::DaemonTriggerCommandArg::Import => ctx_daemon_cli::DaemonTriggerCommandArg::Import,
        crate::DaemonTriggerCommandArg::Search => ctx_daemon_cli::DaemonTriggerCommandArg::Search,
    }
}

fn output_format(format: crate::output::JsonOutputFormat) -> ctx_terminal::JsonOutputFormat {
    match format {
        crate::output::JsonOutputFormat::Text => ctx_terminal::JsonOutputFormat::Text,
        crate::output::JsonOutputFormat::Json => ctx_terminal::JsonOutputFormat::Json,
    }
}

pub(crate) fn source_epoch_status_report(
    data_root: &Path,
    config: &crate::config::AppConfig,
) -> Result<ctx_daemon_cli::SourceEpochStatus> {
    ctx_daemon_cli::source_epoch_status_report(data_root, &daemon_cli_config(config))
}

pub(crate) fn autostart_daemon_and_wait(
    data_root: &Path,
    config: &crate::config::AppConfig,
    trigger: crate::DaemonTriggerCommandArg,
) -> Result<DaemonHandoff> {
    ctx_daemon_cli::autostart_daemon_and_wait(
        data_root,
        &daemon_cli_config(config),
        daemon_trigger(trigger),
    )
}

pub(crate) fn autostart_daemon_for_setup_and_wait(
    data_root: &Path,
    config: &crate::config::AppConfig,
    trigger: crate::DaemonTriggerCommandArg,
) -> Result<DaemonSetupHandoff> {
    ctx_daemon_cli::autostart_daemon_for_setup_and_wait(
        data_root,
        &daemon_cli_config(config),
        daemon_trigger(trigger),
    )
}

pub(crate) fn maybe_autostart_daemon(
    data_root: &Path,
    config: &crate::config::AppConfig,
    trigger: crate::DaemonTriggerCommandArg,
) {
    ctx_daemon_cli::maybe_autostart_daemon(
        data_root,
        &daemon_cli_config(config),
        daemon_trigger(trigger),
    );
}

pub(crate) fn begin_current_daemon_upgrade_handoff(
    data_root: &Path,
    attempt_id: &str,
    trigger: crate::DaemonTriggerCommandArg,
) -> Result<DaemonUpgradeHandoff> {
    ctx_daemon_cli::begin_current_daemon_upgrade_handoff(
        data_root,
        attempt_id,
        daemon_trigger(trigger),
    )
}

pub(crate) fn daemon_config_snapshot(
    config: &crate::config::AppConfig,
) -> ctx_daemon_cli::DaemonConfigSnapshot {
    ctx_daemon_cli::daemon_service_ports::config_snapshot(&daemon_cli_config(config))
}

pub(crate) fn deliver_daemon_events(data_root: &Path, events: &[PublicEventV1]) {
    ctx_daemon_cli::daemon_service_ports::deliver_daemon_events(data_root, events);
}

pub(crate) fn run_daemon_command(
    args: crate::DaemonArgs,
    data_root: std::path::PathBuf,
    config: &crate::config::AppConfig,
    ui: &mut crate::ui::Ui,
) -> Result<()> {
    use crate::DaemonCommand as C;

    let command = match args.command {
        C::Run(args) => ctx_daemon_cli::DaemonCommand::Run(ctx_daemon_cli::DaemonRunArgs {
            idle_exit_seconds: args.idle_exit_seconds,
            loop_interval_seconds: args.loop_interval_seconds,
            max_chunks: args.max_chunks,
            force: args.force,
            start_mode: args.start_mode.map(|mode| match mode {
                crate::DaemonStartModeArg::Auto => ctx_daemon_cli::DaemonStartModeArg::Auto,
                crate::DaemonStartModeArg::Manual => ctx_daemon_cli::DaemonStartModeArg::Manual,
            }),
            trigger_command: args.trigger_command.map(daemon_trigger),
            format: output_format(args.format),
        }),
        C::Status(args) => ctx_daemon_cli::DaemonCommand::Status(ctx_daemon_cli::FormatArgs {
            format: output_format(args.format),
        }),
        C::Enable(args) => ctx_daemon_cli::DaemonCommand::Enable(ctx_daemon_cli::FormatArgs {
            format: output_format(args.format),
        }),
        C::Disable(args) => {
            ctx_daemon_cli::DaemonCommand::Disable(ctx_daemon_cli::DaemonDisableArgs {
                format: output_format(args.format),
                prepare_uninstall: args.prepare_uninstall,
            })
        }
    };
    ctx_daemon_cli::run_daemon_command(
        ctx_daemon_cli::DaemonArgs { command },
        data_root,
        &daemon_cli_config(config),
        ui,
    )
}

impl ctx_daemon_cli::DaemonCliHost for CtxDaemonCliHost {
    fn load_config(&self, data_root: &Path) -> Result<DaemonCliConfig> {
        crate::config::AppConfig::load(data_root).map(|config| daemon_cli_config(&config))
    }

    fn set_daemon_enabled(&self, data_root: &Path, enabled: bool) -> Result<()> {
        crate::config::set_daemon_enabled(data_root, enabled)
    }

    fn home_dir(&self) -> Option<std::path::PathBuf> {
        crate::identity::home_dir()
    }

    fn run_daemon_service(
        &self,
        data_root: &Path,
        request: ctx_daemon_cli::DaemonHostRunRequest,
        config: &DaemonCliConfig,
    ) -> Result<()> {
        let engine = crate::upgrade::ports::engine();
        let upgrade = ctx_daemon_cli::DaemonUpgradePorts {
            engine: &engine,
            daemon: &crate::upgrade::ports::DAEMON_UPGRADE,
            automatic_policy: &crate::upgrade::ports::AUTOMATIC_POLICY,
            observer: &crate::upgrade::ports::UPGRADE_OBSERVER,
        };
        ctx_daemon_cli::daemon_service_ports::run_daemon_service(
            request, data_root, config, &upgrade,
        )
    }

    fn deliver_daemon_events(&self, data_root: &Path, events: &[PublicEventV1]) {
        let Ok(config) = crate::config::AppConfig::load(data_root) else {
            return;
        };
        if config.analytics.enabled {
            crate::analytics::send_batch(data_root, &config, events);
        }
    }

    fn fetch_to_writer(
        &self,
        endpoint: &str,
        max_bytes: u64,
        timeout: Duration,
        writer: &mut dyn Write,
    ) -> Result<u64> {
        struct DynWriter<'a>(&'a mut dyn Write);
        impl Write for DynWriter<'_> {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                self.0.write(buffer)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.0.flush()
            }
        }
        crate::net::get_to_writer_limited(endpoint, max_bytes, timeout, &mut DynWriter(writer))
    }

    fn preflight_core_materialization(&self, data_root: &Path) -> Result<()> {
        crate::pro::preflight_core_materialization(data_root)
    }

    fn sync_core_materialization(
        &self,
        data_root: &Path,
        index: &VerifiedIndex,
    ) -> Result<CoreMaterializationSyncOutcome> {
        crate::pro::sync_core_materialization(data_root, index)
    }

    fn selected_helper_artifact_sha256(&self, data_root: &Path) -> Result<Option<String>> {
        crate::pro::selected_helper_artifact_sha256(data_root)
    }

    fn pro_lifecycle_status(&self, data_root: &Path) -> serde_json::Value {
        crate::pro::lifecycle_status_json(data_root)
    }

    fn pro_lifecycle_status_for_core(
        &self,
        data_root: &Path,
        active_core: Option<&VerifiedIndex>,
    ) -> serde_json::Value {
        crate::pro::lifecycle_status_json_for_core(data_root, active_core)
    }
}

#[cfg(test)]
mod readiness_tests {
    use std::fs;

    use super::*;

    #[test]
    fn post_lock_initialization_failure_retains_restart_intent() -> Result<()> {
        struct RestoreUpgradeTarget(Option<std::ffi::OsString>);

        impl Drop for RestoreUpgradeTarget {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(value) => std::env::set_var("CTX_UPGRADE_TEST_TARGET", value),
                    None => std::env::remove_var("CTX_UPGRADE_TEST_TARGET"),
                }
            }
        }

        let _env_lock = crate::config::TEST_LOCAL_USAGE_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore_upgrade_target =
            RestoreUpgradeTarget(std::env::var_os("CTX_UPGRADE_TEST_TARGET"));
        let installation = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(installation.path(), fs::Permissions::from_mode(0o700))?;
        }
        let installation_executable = installation
            .path()
            .join(if cfg!(windows) { "ctx.exe" } else { "ctx" });
        fs::write(&installation_executable, b"test ctx executable")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&installation_executable, fs::Permissions::from_mode(0o700))?;
        }
        std::env::set_var("CTX_UPGRADE_TEST_TARGET", &installation_executable);

        let root = tempfile::tempdir()?;
        ctx_daemon_cli::publish_daemon_restart_intent(
            root.path(),
            ctx_daemon_cli::DaemonTriggerCommandArg::Search,
            "ua_01890f3e-2c80-7000-8000-00000000000b",
        )?;
        fs::write(
            root.path().join(".fail-daemon-before-ready-for-test"),
            b"fail",
        )?;

        let engine = crate::upgrade::ports::engine();
        let upgrade = ctx_daemon_cli::DaemonUpgradePorts {
            engine: &engine,
            daemon: &crate::upgrade::ports::DAEMON_UPGRADE,
            automatic_policy: &crate::upgrade::ports::AUTOMATIC_POLICY,
            observer: &crate::upgrade::ports::UPGRADE_OBSERVER,
        };
        let request = ctx_daemon_cli::DaemonHostRunRequest {
            idle_exit_seconds: None,
            loop_interval_seconds: None,
            max_chunks: None,
            force: false,
            start_mode: Some(ctx_daemon_application::DaemonHostStartMode::Auto),
            trigger: Some(ctx_daemon_application::DaemonTrigger::Search),
        };
        let config = crate::config::AppConfig::default();
        let error = ctx_daemon_cli::daemon_service_ports::run_daemon_service(
            request,
            root.path(),
            &daemon_cli_config(&config),
            &upgrade,
        )
        .expect_err("the injected post-lock initialization failure must surface");

        let rendered_error = error.to_string();
        assert!(
            rendered_error.contains("injected daemon failure before readiness"),
            "unexpected daemon initialization error: {rendered_error}"
        );
        assert!(ctx_daemon_cli::daemon_restart_intent_pending(root.path()));
        Ok(())
    }
}
