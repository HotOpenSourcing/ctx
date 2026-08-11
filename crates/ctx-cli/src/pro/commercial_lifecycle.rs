use std::{
    cell::Cell,
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use ctx_pro_application::{
    acquire_latest_artifact, AnonymousTrialRefresh, ArtifactDeliveryConfig,
    CommercialArtifactDelivery, CommercialClock, CommercialEvent, CommercialInteraction,
    CommercialLifecycle, CommercialService, CommercialVault, InstallationChallengeSigner,
    SetupAccessPolicy,
};
use ctx_pro_host_protocol::INSTALLATION_PUBLIC_KEY_BYTES;
use ctx_pro_lifecycle::{
    artifact_delivery::VerifiedArtifactBundle, operation::LifecycleOperation,
    release_manifest::ReleaseTrust,
};

mod render;

use super::{
    anonymous_trial,
    artifact_delivery::SetupArtifactBundle,
    commercial_api::{
        CheckoutResult, CommercialApiClient, CommercialClock as CommercialApiClock,
        CommercialState, IssuedEntitlement, PortalResult,
    },
    commercial_config::CommercialConfig,
    credential_vault::{
        vault_error, AnonymousTrialMaterial, CredentialRecord, CredentialRecordKind,
        CredentialVaultError, PlatformCredentialVault, VaultInstallationChallengeSigner,
        VaultScope, WorkOsSessionMaterial,
    },
    lifecycle::{ProLifecycleService, ProManagePlan, ProSetupPlan},
    workos_device::{DeviceAuthorization, WorkOsAccessToken, WorkOsDeviceClient, WorkOsTokens},
};
use crate::ui::Ui;
use render::{
    browser_notice as render_browser_notice, checkout_progress as render_checkout_progress,
    device_sign_in as render_device_sign_in, paid_checkout_prompt as render_paid_checkout_prompt,
    trial_conversion as render_trial_conversion,
};

pub(super) struct CommercialLifecycleService {
    pub(super) config: CommercialConfig,
    workos: WorkOsDeviceClient,
    pub(super) api: CommercialApiClient,
    pub(super) vault: PlatformCredentialVault,
}

#[derive(Debug)]
struct CliCommercialApiClock;

impl CommercialApiClock for CliCommercialApiClock {
    fn unix_time(&self) -> Result<i64> {
        unix_time()
    }
}

#[derive(Debug)]
struct CliLifecycleClock {
    monotonic_origin: Cell<Option<Instant>>,
}

impl CliLifecycleClock {
    fn new() -> Self {
        Self {
            monotonic_origin: Cell::new(None),
        }
    }
}

impl CommercialClock for CliLifecycleClock {
    fn unix_time(&self) -> Result<i64> {
        unix_time()
    }

    fn monotonic_now(&self) -> Duration {
        match self.monotonic_origin.get() {
            Some(origin) => origin.elapsed(),
            None => {
                self.monotonic_origin.set(Some(Instant::now()));
                Duration::ZERO
            }
        }
    }

    fn sleep(&self, duration: Duration) {
        thread::sleep(duration);
    }
}

struct CliCommercialInteraction<'a> {
    ui: &'a mut Ui,
    human_output: bool,
    browser_enabled: bool,
}

impl CommercialInteraction for CliCommercialInteraction<'_> {
    fn human_output(&self) -> bool {
        self.human_output
    }

    fn browser_enabled(&self) -> bool {
        self.browser_enabled
    }

    fn event(&mut self, event: CommercialEvent<'_>) -> Result<()> {
        let document = match event {
            CommercialEvent::DeviceSignIn {
                verification_uri,
                user_code,
            } => render_device_sign_in(self.ui.stderr_context(), verification_uri, user_code),
            CommercialEvent::OpenBrowser { url, destination } => {
                let browser_opened = open_browser(url).is_ok();
                render_browser_notice(self.ui.stderr_context(), browser_opened, destination)
            }
            CommercialEvent::TrialConversion => render_trial_conversion(self.ui.stderr_context()),
            CommercialEvent::CheckoutPrompt { url } => {
                render_paid_checkout_prompt(self.ui.stderr_context(), url)
            }
            CommercialEvent::WaitingForCheckout => {
                render_checkout_progress(self.ui.stderr_context(), "Waiting for checkout", None)
            }
            CommercialEvent::WaitingForSubscription {
                elapsed_minutes,
                checkout_complete,
            } => {
                let elapsed = elapsed_minutes.map(|minutes| format!("{minutes} minute(s) elapsed"));
                let detail = if checkout_complete {
                    Some("Checkout is complete.")
                } else {
                    elapsed.as_deref()
                };
                render_checkout_progress(
                    self.ui.stderr_context(),
                    "Waiting for subscription access",
                    detail,
                )
            }
            CommercialEvent::SubscriptionAccessActive => render_checkout_progress(
                self.ui.stderr_context(),
                "Subscription access is active",
                Some("Finishing ctx Pro setup."),
            ),
        };
        self.ui.write_stderr(&document)?;
        Ok(())
    }
}

impl CommercialLifecycleService {
    pub(super) fn production(data_root: &Path) -> Result<Self> {
        let config = CommercialConfig::production()?;
        let workos = WorkOsDeviceClient::new(config.workos.clone())?;
        let api = CommercialApiClient::new(config.api.clone(), Arc::new(CliCommercialApiClock))?;
        let installation_id = crate::identity::existing_installation_id(data_root)
            .map_err(|_| vault_error(CredentialVaultError::InvalidDataRoot))?
            .ok_or_else(|| vault_error(CredentialVaultError::NotFound))?;
        let vault = PlatformCredentialVault::production(
            VaultScope {
                data_root,
                installation_id: &installation_id,
            },
            config.vault_namespace,
        )
        .map_err(vault_error)?;
        Ok(Self {
            config,
            workos,
            api,
            vault,
        })
    }

    fn application(&self) -> CommercialLifecycle<'_, Self> {
        CommercialLifecycle::new(&self.config, self)
    }

    pub(super) fn refresh_entitlement_if_due(data_root: &Path) -> Result<()> {
        let service = Self::production(data_root)?;
        service
            .application()
            .refresh_entitlement_if_due(&CliLifecycleClock::new())
    }

    pub(super) fn access_token(
        &self,
        ui: &mut Ui,
        human_output: bool,
        browser_enabled: bool,
    ) -> Result<WorkOsAccessToken> {
        let mut interaction = CliCommercialInteraction {
            ui,
            human_output,
            browser_enabled,
        };
        self.application()
            .access_token(&CliLifecycleClock::new(), &mut interaction)
    }

    pub(super) fn access_token_noninteractive(&self) -> Result<WorkOsAccessToken> {
        self.application()
            .access_token_noninteractive(&CliLifecycleClock::new())
    }
}

impl CommercialService for CommercialLifecycleService {
    type AccessToken = WorkOsAccessToken;

    fn begin_device_sign_in(&self) -> Result<DeviceAuthorization> {
        self.workos.begin()
    }

    fn poll_device_sign_in(&self, authorization: &DeviceAuthorization) -> Result<WorkOsTokens> {
        self.workos.poll(authorization)
    }

    fn refresh_session(&self, session: &WorkOsSessionMaterial) -> Result<WorkOsTokens> {
        self.workos.refresh_session(session)
    }

    fn refresh_for_organization(
        &self,
        tokens: &WorkOsTokens,
        organization_id: &str,
    ) -> Result<WorkOsTokens> {
        self.workos
            .refresh_for_organization(tokens, organization_id)
    }

    fn session_access_token(&self, session: &WorkOsSessionMaterial) -> Result<WorkOsAccessToken> {
        self.workos.session_access_token(session)
    }

    fn session_matches_access_token(
        &self,
        session: &WorkOsSessionMaterial,
        access_token: &WorkOsAccessToken,
    ) -> bool {
        session.matches_access_token(access_token)
    }

    fn bootstrap_pending(&self, tokens: &WorkOsTokens) -> Result<bool> {
        self.workos.bootstrap_pending(tokens)
    }

    fn persistable_session(
        &self,
        tokens: WorkOsTokens,
    ) -> Result<(WorkOsSessionMaterial, WorkOsAccessToken)> {
        self.workos.persistable_session(tokens)
    }

    fn bootstrap_personal_organization(&self, tokens: &WorkOsTokens) -> Result<String> {
        self.api.bootstrap_workos_personal_organization(tokens)
    }

    fn account(&self, access_token: &WorkOsAccessToken) -> Result<CommercialState> {
        self.api.account(access_token)
    }

    fn checkout(
        &self,
        access_token: &WorkOsAccessToken,
        anonymous_trial: Option<&AnonymousTrialMaterial>,
    ) -> Result<CheckoutResult> {
        self.api.checkout(access_token, anonymous_trial)
    }

    fn portal(&self, access_token: &WorkOsAccessToken) -> Result<PortalResult> {
        self.api.portal(access_token)
    }

    fn entitlement(
        &self,
        access_token: &WorkOsAccessToken,
        installation_public_key_base64url: &str,
    ) -> Result<IssuedEntitlement> {
        self.api
            .entitlement(access_token, installation_public_key_base64url)
    }
}

impl CommercialVault for CommercialLifecycleService {
    fn load_credential(
        &self,
        kind: CredentialRecordKind,
    ) -> std::result::Result<CredentialRecord, CredentialVaultError> {
        self.vault.load(kind)
    }

    fn store_credential(
        &self,
        record: &CredentialRecord,
    ) -> std::result::Result<(), CredentialVaultError> {
        self.vault.store(record)
    }

    fn delete_credential(
        &self,
        kind: CredentialRecordKind,
    ) -> std::result::Result<(), CredentialVaultError> {
        self.vault.delete(kind)
    }

    fn load_or_create_installation_public_key(
        &self,
    ) -> Result<[u8; INSTALLATION_PUBLIC_KEY_BYTES]> {
        self.vault
            .load_or_create_installation_signing_key()
            .map_err(vault_error)?;
        VaultInstallationChallengeSigner::new(&self.vault)
            .public_key()
            .context("key_store_unavailable: load installation public key")
    }

    fn installation_public_key(&self) -> Result<[u8; INSTALLATION_PUBLIC_KEY_BYTES]> {
        VaultInstallationChallengeSigner::new(&self.vault).public_key()
    }
}

impl CommercialArtifactDelivery for CommercialLifecycleService {
    fn acquire_latest_artifact(
        &self,
        operation: &LifecycleOperation,
        data_root: &Path,
        installed_version: Option<&str>,
        release_trust: ReleaseTrust,
    ) -> Result<VerifiedArtifactBundle> {
        acquire_latest_artifact(
            operation,
            data_root,
            installed_version,
            ArtifactDeliveryConfig::new(self.api.config(), release_trust),
        )
    }
}

impl AnonymousTrialRefresh for CommercialLifecycleService {
    fn refresh_anonymous_trial_entitlement(&self) -> Result<()> {
        anonymous_trial::refresh_entitlement(self)
    }

    fn defer_anonymous_trial_refresh(&self, now: i64) {
        anonymous_trial::defer_refresh(self, now);
    }
}

impl ProLifecycleService for CommercialLifecycleService {
    fn release_trust(&self) -> Result<ReleaseTrust> {
        Ok(self.config.release_trust)
    }

    fn setup(
        &mut self,
        operation: &LifecycleOperation,
        data_root: &Path,
        installed_version: Option<&str>,
        trial_only: bool,
        referral_codename: Option<&str>,
        ui: &mut Ui,
        human_output: bool,
        browser_enabled: bool,
    ) -> Result<ProSetupPlan> {
        // A WorkOS session proves identity for referral management; it does not
        // prove that this installation consumed or converted its anonymous trial.
        let application = self.application();
        match ctx_pro_application::setup_with_access_policy(
            trial_only,
            referral_codename.is_some(),
            application.stored_access_kind()?,
            || {
                anonymous_trial::setup(
                    self,
                    operation,
                    data_root,
                    installed_version,
                    referral_codename,
                )
            },
        )? {
            SetupAccessPolicy::Complete(plan) => Ok(plan),
            SetupAccessPolicy::PaidRequired { trial_unavailable } => {
                let mut interaction = CliCommercialInteraction {
                    ui,
                    human_output,
                    browser_enabled,
                };
                let outcome = application.setup_with_paid_access(
                    operation,
                    data_root,
                    installed_version,
                    trial_unavailable,
                    &CliLifecycleClock::new(),
                    &mut interaction,
                )?;
                Ok(ProSetupPlan {
                    artifact: Some(SetupArtifactBundle::Release(outcome.artifact)),
                    account_state: outcome.account_state,
                })
            }
        }
    }

    fn manage(
        &mut self,
        _data_root: &Path,
        ui: &mut Ui,
        human_output: bool,
        browser_enabled: bool,
    ) -> Result<ProManagePlan> {
        let mut interaction = CliCommercialInteraction {
            ui,
            human_output,
            browser_enabled,
        };
        let outcome = self
            .application()
            .manage(&CliLifecycleClock::new(), &mut interaction)?;
        Ok(ProManagePlan {
            portal_url: outcome.portal_url,
            access_state: outcome.access_state,
            refresh_after_unix: outcome.refresh_after_unix,
            access_deadline_unix: outcome.access_deadline_unix,
            grace_deadline_unix: outcome.grace_deadline_unix,
        })
    }
}

pub(super) fn open_browser(url: &str) -> Result<()> {
    #[cfg(ctx_pro_test_helper)]
    if let Some(result) = crate::pro::test_control::browser_result_if_active(url) {
        return result;
    }

    let mut command = if cfg!(target_os = "macos") {
        let mut command = Command::new("open");
        command.arg(url);
        command
    } else if cfg!(windows) {
        let mut command = Command::new("rundll32.exe");
        command.args(["url.dll,FileProtocolHandler", url]);
        command
    } else {
        let mut command = Command::new("xdg-open");
        command.arg(url);
        command
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("open browser")?;
    Ok(())
}

pub(super) fn unix_time() -> Result<i64> {
    #[cfg(ctx_pro_test_helper)]
    if let Some(result) = crate::pro::test_control::unix_time_if_active() {
        return result;
    }

    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("invalid_request: system clock is before Unix epoch")?
            .as_secs(),
    )
    .context("invalid_request: system time is invalid")
}

#[cfg(ctx_pro_test_helper)]
pub(super) fn test_device_sign_in(
    context: &crate::ui::RenderContext,
    verification_uri: &str,
    user_code: &str,
) -> crate::ui::Document {
    render_device_sign_in(context, verification_uri, user_code)
}

#[cfg(ctx_pro_test_helper)]
pub(super) fn test_paid_checkout_prompt(
    context: &crate::ui::RenderContext,
    url: &str,
) -> crate::ui::Document {
    render_paid_checkout_prompt(context, url)
}

#[cfg(ctx_pro_test_helper)]
pub(super) fn test_trial_conversion(context: &crate::ui::RenderContext) -> crate::ui::Document {
    render_trial_conversion(context)
}

#[cfg(ctx_pro_test_helper)]
pub(super) fn test_checkout_progress(
    context: &crate::ui::RenderContext,
    label: &str,
    detail: Option<&str>,
) -> crate::ui::Document {
    render_checkout_progress(context, label, detail)
}

#[cfg(ctx_pro_test_helper)]
pub(super) fn test_browser_notice(
    context: &crate::ui::RenderContext,
    browser_opened: bool,
    destination: &str,
) -> crate::ui::Document {
    render_browser_notice(context, browser_opened, destination)
}

#[cfg(test)]
#[path = "commercial_lifecycle/tests.rs"]
mod tests;
