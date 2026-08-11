use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ctx_pro_application::AuthorizationProvider as _;
use ctx_pro_application::{
    CoreOrchestration, Identity, ProApplication, ReferralAdmission, ReferralIdentity,
    SetupCommandHost, StoredAuthorizationProvider,
};
use ctx_pro_host::{
    AuthorizationMode, AuthorizationReceipt, CoreGenerationHost, CoreGenerationPin,
    InstalledProHost,
};
use ctx_pro_host_protocol::{AuthorizationRequest, BlameTarget, AUTHORIZATION_CHALLENGE_BYTES};
use ctx_pro_lifecycle::installed_artifact::ValidatedArtifactIdentity;

use super::{
    artifact_delivery::SetupArtifactBundle, commercial_config::CommercialConfig,
    commercial_lifecycle,
};

#[cfg(test)]
pub(crate) use ctx_pro_host::default_helper_path;
pub(super) use ctx_pro_host::typed_blame_diagnostic;
pub(crate) use ctx_pro_host::{
    blame_boundary_error, blame_diagnostic, invalid_blame_request, stable_error_code,
    BlameResultFreshness, CoreMaterializationSyncOutcome, HelperSmoke, HostedBlameResult,
    ProStatus, RESOURCE_NOT_FOUND_DIAGNOSTIC,
};

pub(crate) type MaterializeReport = ctx_pro_host::MaterializationFinalizationReceipt;

pub(super) struct CtxInstalledProHost;

const HOST: CtxInstalledProHost = CtxInstalledProHost;

pub(super) const fn application() -> ProApplication<'static, CtxInstalledProHost> {
    ProApplication::new(&HOST)
}

impl Identity for CtxInstalledProHost {
    fn existing_installation_id(&self, data_root: &Path) -> Result<Option<String>> {
        <Self as InstalledProHost>::existing_installation_id(self, data_root)
    }
}

impl ReferralIdentity for CtxInstalledProHost {
    fn existing_referral_identity(&self, data_root: &Path) -> Result<Option<String>> {
        crate::identity::existing_installation_id(data_root)
    }

    fn initialize_referral_identity(&self, data_root: &Path) -> Result<()> {
        crate::identity::installation_id(data_root).map(|_| ())
    }
}

pub(super) fn admit_referral(
    data_root: &Path,
    cached_identity_only: bool,
    create_lifecycle_root: bool,
) -> Result<ReferralAdmission> {
    ctx_pro_application::admit_referral(
        &HOST,
        data_root,
        cached_identity_only,
        create_lifecycle_root,
    )
}

impl SetupCommandHost<SetupArtifactBundle> for CtxInstalledProHost {
    fn initialize_setup_identity(&self, data_root: &Path) -> Result<()> {
        crate::identity::installation_id(data_root)
            .context("key_store_unavailable: initialize local Pro installation identity")?;
        Ok(())
    }

    fn smoke_setup_artifact(
        &self,
        data_root: &Path,
        artifact: &SetupArtifactBundle,
    ) -> Result<HelperSmoke> {
        match artifact {
            SetupArtifactBundle::Release(bundle) => {
                ctx_pro_host::smoke_validated_helper(self, data_root, bundle.identity().clone())
            }
            #[cfg(ctx_pro_test_helper)]
            SetupArtifactBundle::TestControl(bundle) => {
                let helper = bundle.verified_path()?;
                ctx_pro_host::smoke_helper_at_path(self, data_root, &helper)
            }
        }
    }

    fn install_setup_artifact(
        &self,
        artifact: &SetupArtifactBundle,
        operation: &ctx_pro_lifecycle::operation::LifecycleOperation,
        trust: ctx_pro_lifecycle::release_manifest::ReleaseTrust,
    ) -> Result<bool> {
        match artifact {
            SetupArtifactBundle::Release(bundle) => {
                super::lifecycle::install_verified_bundle(bundle, operation, trust)?;
                Ok(true)
            }
            #[cfg(ctx_pro_test_helper)]
            SetupArtifactBundle::TestControl(_) => Ok(false),
        }
    }
}

pub(crate) fn setup_anonymous_trial(
    context: ctx_pro_application::AnonymousTrialContext<'_>,
    operation: &ctx_pro_lifecycle::operation::LifecycleOperation,
    data_root: &Path,
    installed_version: Option<&str>,
    referral_codename: Option<&str>,
) -> Result<ctx_pro_application::AnonymousTrialSetup> {
    ctx_pro_application::setup_anonymous_trial(
        &ProApplication::new(&HOST),
        context,
        operation,
        data_root,
        installed_version,
        referral_codename,
    )
}

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
        operation: Option<&ctx_pro_lifecycle::operation::LifecycleOperation>,
    ) -> Result<ValidatedArtifactIdentity> {
        let trust = CommercialConfig::production()?.release_trust;
        match operation {
            Some(operation) => {
                operation.require_data_root(data_root)?;
                ctx_pro_lifecycle::installation::discover_installed_artifact_in(operation, trust)
            }
            None => ctx_pro_lifecycle::installation::discover_installed_artifact(data_root, trust),
        }
    }

    fn authorization_for_challenge(
        &self,
        data_root: &Path,
        challenge: &[u8; AUTHORIZATION_CHALLENGE_BYTES],
        mode: AuthorizationMode,
    ) -> Result<AuthorizationReceipt> {
        let provider = match mode {
            AuthorizationMode::Normal => {
                StoredAuthorizationProvider::load(data_root, self, || {
                    commercial_lifecycle::CommercialLifecycleService::refresh_entitlement_if_due(
                        data_root,
                    )
                })?
            }
            AuthorizationMode::Status => {
                StoredAuthorizationProvider::load_for_status(data_root, self)?
            }
        };
        let entitlement_schedule = Some(provider.entitlement_schedule());
        let request: AuthorizationRequest = provider.authorization_for_challenge(challenge)?;
        Ok(AuthorizationReceipt {
            request,
            entitlement_schedule,
        })
    }

    fn unix_time(&self) -> Result<i64> {
        commercial_lifecycle::unix_time()
    }
}

// Keep the daemon-service generation lease owned for the full host operation.
// This local adapter also prevents either extracted crate from depending on the
// other solely to satisfy Rust's trait coherence rules.
pub(super) struct CtxCoreGenerationPin(crate::semantic::PinnedSourceBackedGeneration);

impl CoreGenerationPin for CtxCoreGenerationPin {
    fn generation_id(&self) -> &str {
        self.0.generation_id()
    }
}

impl CoreGenerationHost for CtxInstalledProHost {
    type Pin = CtxCoreGenerationPin;

    fn pin_active_core_generation(&self, data_root: &Path) -> Result<Self::Pin> {
        crate::semantic::pin_active_verified_generation(data_root).map(CtxCoreGenerationPin)
    }
}

impl CoreOrchestration for CtxInstalledProHost {
    fn prepare_materialization_generation(&self, data_root: &Path) -> Result<String> {
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
        let generation_id = refresh.pin.generation_id().to_owned();
        self.wait_for_pro_generation(data_root, &generation_id)?;
        Ok(generation_id)
    }

    fn wait_for_pro_generation(&self, data_root: &Path, generation_id: &str) -> Result<()> {
        crate::semantic::wait_for_source_backed_pro_generation(data_root, generation_id)
    }

    fn wake_blame_refresh(&self, data_root: &Path) -> Result<()> {
        crate::semantic::coordinate_source_backed_refresh(
            data_root,
            crate::semantic::SourceBackedRefreshMode::Background,
        )
        .map(|_| ())
    }

    fn cancel_core_finalization(&self, data_root: &Path, reason: &str) -> Result<()> {
        crate::semantic::cancel_core_finalization_generation_lease(data_root, reason).map(drop)
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

pub(crate) fn status(data_root: &Path) -> ProStatus {
    ProApplication::new(&HOST).status(data_root)
}

pub(crate) fn status_for_core(
    data_root: &Path,
    active_core: Option<&ctx_history_index::VerifiedIndex>,
) -> ProStatus {
    ProApplication::new(&HOST).status_for_core(data_root, active_core)
}

pub(crate) fn blame(
    data_root: &Path,
    target: &BlameTarget,
    limit: u32,
    cursor: Option<String>,
) -> Result<HostedBlameResult> {
    ProApplication::new(&HOST).blame(data_root, target, limit, cursor)
}

pub(crate) fn uninstall(
    data_root: &Path,
    deletion: Option<&mut dyn ctx_pro_application::ProDeletionService>,
    disposition: ctx_pro_application::UninstallDataDisposition,
) -> Result<ctx_pro_application::UninstallOutcome> {
    ProApplication::new(&HOST).uninstall(data_root, deletion, disposition)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_host_uses_the_ctx_binary_version() {
        assert_eq!(HOST.host_version(), env!("CARGO_PKG_VERSION"));
    }
}
