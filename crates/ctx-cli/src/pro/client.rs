use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ctx_pro_access::authorization::AuthorizationProvider as _;
use ctx_pro_host::{
    AuthorizationMode, AuthorizationReceipt, CoreGenerationHost, CoreGenerationPin,
    InstalledProHost,
};
use ctx_pro_host_protocol::{AuthorizationRequest, BlameTarget, AUTHORIZATION_CHALLENGE_BYTES};

use crate::analytics::{
    pro_helper_connection_outcome, ProHelperConnectionOutcomeV1, ProMaterializationModeV1,
    ProMaterializationTelemetryV1,
};

use super::{
    authorization::StoredAuthorizationProvider, commercial_config::CommercialConfig,
    commercial_lifecycle, lifecycle,
};

pub(super) use ctx_pro_host::typed_blame_diagnostic;
pub(crate) use ctx_pro_host::{
    blame_boundary_error, blame_diagnostic, core_finalization_generation_lease,
    default_helper_path, git_executable, invalid_blame_request,
    reconstruct_core_finalization_generation_lease, release_core_finalization_generation_lease,
    stable_error_code, validate_core_finalization_generation_lease, BlameResultFreshness,
    CoreMaterializationSyncOutcome, HelperSmoke, HostedBlameResult, ProSetupRepairability,
    ProStatus, RESOURCE_NOT_FOUND_DIAGNOSTIC,
};

pub(crate) type MaterializeReport = ctx_pro_host::MaterializationFinalizationReceipt;

struct CtxInstalledProHost;

const HOST: CtxInstalledProHost = CtxInstalledProHost;

impl InstalledProHost for CtxInstalledProHost {
    fn host_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn existing_installation_id(&self, data_root: &Path) -> Result<Option<String>> {
        crate::identity::existing_installation_id(data_root)
    }

    fn helper_override(&self) -> Result<Option<PathBuf>> {
        #[cfg(ctx_pro_test_helper)]
        if let Some(path) = super::test_control::helper_path()? {
            return Ok(Some(path));
        }

        #[cfg(any(test, ctx_pro_test_helper))]
        if let Some(value) = std::env::var_os("CTX_PRO_HELPER") {
            return Ok(Some(PathBuf::from(value)));
        }

        Ok(None)
    }

    fn validated_installed_helper(
        &self,
        data_root: &Path,
    ) -> Result<ctx_pro_host::VerifiedHelperExecutable> {
        lifecycle::validated_installed_helper(data_root)
    }

    fn release_trust(&self) -> Result<ctx_pro_host::lifecycle_manifest::ReleaseTrust> {
        Ok(CommercialConfig::production()?.release_trust)
    }

    fn authorization_for_challenge(
        &self,
        data_root: &Path,
        challenge: &[u8; AUTHORIZATION_CHALLENGE_BYTES],
        mode: AuthorizationMode,
    ) -> Result<AuthorizationReceipt> {
        let provider = match mode {
            AuthorizationMode::Normal => StoredAuthorizationProvider::load(data_root)?,
            AuthorizationMode::Status => StoredAuthorizationProvider::load_for_status(data_root)?,
        };
        let entitlement_schedule = Some(provider.entitlement_schedule());
        let request: AuthorizationRequest = provider.authorization_for_challenge(challenge)?;
        Ok(AuthorizationReceipt {
            request,
            entitlement_schedule,
        })
    }

    fn setup_repair_required(&self, error: &anyhow::Error) -> bool {
        lifecycle::is_setup_repair_required_error(error)
    }

    fn unix_time(&self) -> Result<i64> {
        commercial_lifecycle::unix_time()
    }
}

impl CoreGenerationPin for crate::semantic::PinnedSourceBackedGeneration {
    fn generation_id(&self) -> &str {
        crate::semantic::PinnedSourceBackedGeneration::generation_id(self)
    }
}

impl CoreGenerationHost for CtxInstalledProHost {
    type Pin = crate::semantic::PinnedSourceBackedGeneration;

    fn pin_active_core_generation(&self, data_root: &Path) -> Result<Self::Pin> {
        crate::semantic::pin_active_verified_generation(data_root)
    }
}

pub(crate) fn preflight_core_materialization(data_root: &Path) -> Result<()> {
    ctx_pro_host::preflight_core_materialization(&HOST, data_root)
}

pub(crate) fn selected_helper_artifact_sha256(data_root: &Path) -> Result<Option<String>> {
    ctx_pro_host::selected_helper_artifact_sha256(&HOST, data_root)
}

pub(crate) fn sync_core_materialization(
    data_root: &Path,
    index: &ctx_history_index::VerifiedIndex,
) -> Result<CoreMaterializationSyncOutcome> {
    ctx_pro_host::sync_core_materialization(&HOST, data_root, index)
}

pub(crate) fn smoke_helper_at_path(data_root: &Path, path: &Path) -> Result<HelperSmoke> {
    ctx_pro_host::smoke_helper_at_path(&HOST, data_root, path)
}

pub(crate) fn status(data_root: &Path) -> ProStatus {
    ctx_pro_host::status(&HOST, data_root)
}

pub(crate) fn status_for_core(
    data_root: &Path,
    active_core: Option<&ctx_history_index::VerifiedIndex>,
) -> ProStatus {
    ctx_pro_host::status_for_core(&HOST, data_root, active_core)
}

#[cfg(test)]
pub(crate) fn status_with_helper_resolver(
    data_root: &Path,
    resolve_helper: impl FnOnce(&Path) -> Result<PathBuf>,
) -> ProStatus {
    ctx_pro_host::status_with_helper_resolver(&HOST, data_root, resolve_helper)
}

pub(crate) fn materialize(
    data_root: &Path,
    telemetry: &mut ProMaterializationTelemetryV1,
) -> Result<MaterializeReport> {
    let result = materialize_once(data_root, telemetry)
        .and_then(|report| super::pending_materialization::clear_after(data_root, report));
    if let Err(error) = &result {
        telemetry.fail(stable_error_code(error));
    }
    result
}

fn materialize_once(
    data_root: &Path,
    telemetry: &mut ProMaterializationTelemetryV1,
) -> Result<MaterializeReport> {
    let start = match ctx_pro_host::start_materialization(&HOST, data_root) {
        Ok(start) => {
            telemetry.helper_connection = ProHelperConnectionOutcomeV1::Connected;
            start
        }
        Err(error) => {
            telemetry.helper_connection = pro_helper_connection_outcome(stable_error_code(&error));
            return Err(error);
        }
    };

    let config = crate::config::AppConfig::load(data_root)
        .context("source_unavailable: load daemon configuration for Pro materialization")?;
    if config.daemon.mode.runs_only_source_refresh() {
        bail!("not_materialized: source-refresh-only daemon mode excludes Pro materialization");
    }
    crate::semantic::autostart_daemon_and_wait(
        data_root,
        &config,
        crate::DaemonTriggerCommandArg::Setup,
    )
    .context("source_unavailable: start daemon-owned source materialization")?;
    let refresh = crate::semantic::coordinate_source_backed_refresh(
        data_root,
        crate::semantic::SourceBackedRefreshMode::Wait,
    )
    .context("source_unavailable: publish provider sources before Pro materialization")?;
    let core_generation_id = refresh.pin.generation_id().to_owned();

    crate::semantic::wait_for_source_backed_pro_generation(data_root, &core_generation_id)?;

    let was_unmaterialized = start.prior_core_generation_id.is_none();
    let no_op = start.prior_core_generation_id.as_deref() == Some(core_generation_id.as_str());
    let report =
        match ctx_pro_host::finish_materialization(&HOST, data_root, start, core_generation_id) {
            Ok(report) => {
                telemetry.helper_connection = ProHelperConnectionOutcomeV1::Connected;
                report
            }
            Err(error) => {
                telemetry.helper_connection =
                    pro_helper_connection_outcome(stable_error_code(&error));
                return Err(error);
            }
        };

    telemetry.mode = Some(if no_op {
        ProMaterializationModeV1::NoOp
    } else if was_unmaterialized {
        ProMaterializationModeV1::Full
    } else {
        ProMaterializationModeV1::Incremental
    });
    telemetry.complete(
        report.batches,
        if no_op { 0 } else { report.source_count },
        if no_op { 0 } else { report.source_count },
        report.replayed_batches,
        if no_op { 0 } else { report.source_count },
    );
    Ok(report)
}

fn wait_for_current_blame_generation(data_root: &Path) -> Result<String> {
    let mut materialization = ProMaterializationTelemetryV1::started();
    materialize(data_root, &mut materialization)?;

    let mut expected = crate::semantic::pin_active_verified_generation(data_root)?
        .generation_id()
        .to_owned();
    for _ in 0..3 {
        crate::semantic::wait_for_source_backed_pro_generation(data_root, &expected)?;
        let active = crate::semantic::pin_active_verified_generation(data_root)?
            .generation_id()
            .to_owned();
        if active == expected {
            return Ok(expected);
        }
        expected = active;
    }
    bail!("stale_source: active verified Core generation advanced repeatedly while preparing blame")
}

pub(crate) fn blame(
    data_root: &Path,
    target: &BlameTarget,
    limit: u32,
    cursor: Option<String>,
) -> Result<HostedBlameResult> {
    let expected_active_generation = ctx_pro_host::prepare_blame_freshness_with(
        ctx_pro_host::BlameFreshnessPolicy::LatestCommitted,
        || {
            crate::semantic::coordinate_source_backed_refresh(
                data_root,
                crate::semantic::SourceBackedRefreshMode::Background,
            )
            .map(|_| ())
        },
        || wait_for_current_blame_generation(data_root),
    )
    .map_err(|error| blame_boundary_error(error, target))?;
    ctx_pro_host::blame(
        &HOST,
        data_root,
        target,
        limit,
        cursor,
        expected_active_generation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_host_uses_the_ctx_binary_version() {
        assert_eq!(HOST.host_version(), env!("CARGO_PKG_VERSION"));
    }
}
