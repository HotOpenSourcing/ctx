use std::{path::Path, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use ctx_pro_access::{
    commercial_api::{
        checkout_retry_after, is_retryable_checkout_failure, validate_https_url, CheckoutResult,
        CommercialState, IssuedEntitlement, PortalResult,
    },
    credential_vault::{
        vault_error, AnonymousTrialMaterial, BoundedSignedEntitlement, CredentialRecord,
        CredentialRecordKind, CredentialVaultError, WorkOsSessionMaterial,
    },
    workos_device::{DeviceAuthorization, WorkOsTokens},
};
use ctx_pro_host::stable_error_code;
use ctx_pro_host_protocol::{base64url, EntitlementAccessKind, INSTALLATION_PUBLIC_KEY_BYTES};
use ctx_pro_lifecycle::{
    artifact_delivery::VerifiedArtifactBundle, operation::LifecycleOperation,
    release_manifest::ReleaseTrust,
};

use super::CommercialConfig;
use crate::ReferralAuthMode;
use checkout_poll::{poll_checkout_access, CheckoutPoll};

mod checkout_poll;

#[cfg(test)]
use checkout_poll::CHECKOUT_POLL_MAX_SECONDS;

const ENTITLEMENT_REFRESH_RETRY_SECONDS: i64 = 60 * 60;

/// Concrete HTTP/session operations. The CLI owns the clients and transport;
/// application policy owns the exact call order and state transitions.
pub trait CommercialService {
    type AccessToken;

    fn begin_device_sign_in(&self) -> Result<DeviceAuthorization>;
    fn poll_device_sign_in(&self, authorization: &DeviceAuthorization) -> Result<WorkOsTokens>;
    fn refresh_session(&self, session: &WorkOsSessionMaterial) -> Result<WorkOsTokens>;
    fn refresh_for_organization(
        &self,
        tokens: &WorkOsTokens,
        organization_id: &str,
    ) -> Result<WorkOsTokens>;
    fn session_access_token(&self, session: &WorkOsSessionMaterial) -> Result<Self::AccessToken>;
    fn session_matches_access_token(
        &self,
        session: &WorkOsSessionMaterial,
        access_token: &Self::AccessToken,
    ) -> bool;
    fn bootstrap_pending(&self, tokens: &WorkOsTokens) -> Result<bool>;
    fn persistable_session(
        &self,
        tokens: WorkOsTokens,
    ) -> Result<(WorkOsSessionMaterial, Self::AccessToken)>;
    fn bootstrap_personal_organization(&self, tokens: &WorkOsTokens) -> Result<String>;
    fn account(&self, access_token: &Self::AccessToken) -> Result<CommercialState>;
    fn checkout(
        &self,
        access_token: &Self::AccessToken,
        anonymous_trial: Option<&AnonymousTrialMaterial>,
    ) -> Result<CheckoutResult>;
    fn portal(&self, access_token: &Self::AccessToken) -> Result<PortalResult>;
    fn entitlement(
        &self,
        access_token: &Self::AccessToken,
        installation_public_key_base64url: &str,
    ) -> Result<IssuedEntitlement>;
}

/// Typed native-vault boundary. Record selection and fail-closed transition
/// policy stay here; the platform backend remains a CLI composition detail.
pub trait CommercialVault {
    fn load_credential(
        &self,
        kind: CredentialRecordKind,
    ) -> std::result::Result<CredentialRecord, CredentialVaultError>;
    fn store_credential(
        &self,
        record: &CredentialRecord,
    ) -> std::result::Result<(), CredentialVaultError>;
    fn delete_credential(
        &self,
        kind: CredentialRecordKind,
    ) -> std::result::Result<(), CredentialVaultError>;
    fn load_or_create_installation_public_key(&self)
        -> Result<[u8; INSTALLATION_PUBLIC_KEY_BYTES]>;
    fn installation_public_key(&self) -> Result<[u8; INSTALLATION_PUBLIC_KEY_BYTES]>;
}

/// Release delivery is an operation-sized port so application policy never
/// owns an HTTP transport or serializes an artifact boundary.
pub trait CommercialArtifactDelivery {
    fn acquire_latest_artifact(
        &self,
        operation: &LifecycleOperation,
        data_root: &Path,
        installed_version: Option<&str>,
        release_trust: ReleaseTrust,
    ) -> Result<VerifiedArtifactBundle>;
}

/// Anonymous-trial refresh is already a separate application workflow. This
/// port preserves its independent retry clock and exact vault transition.
pub trait AnonymousTrialRefresh {
    fn refresh_anonymous_trial_entitlement(&self) -> Result<()>;
    fn defer_anonymous_trial_refresh(&self, now: i64);
}

pub trait CommercialHost:
    CommercialService + CommercialVault + CommercialArtifactDelivery + AnonymousTrialRefresh
{
}

impl<T> CommercialHost for T where
    T: CommercialService
        + CommercialVault
        + CommercialArtifactDelivery
        + AnonymousTrialRefresh
        + ?Sized
{
}

/// Wall/monotonic time and bounded sleeping. Implementations may use the
/// system clock or deterministic test control, but policy sees no concrete I/O.
pub trait CommercialClock {
    fn unix_time(&self) -> Result<i64>;
    fn monotonic_now(&self) -> Duration;
    fn sleep(&self, duration: Duration);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommercialEvent<'a> {
    DeviceSignIn {
        verification_uri: &'a str,
        user_code: &'a str,
    },
    OpenBrowser {
        url: &'a str,
        destination: &'a str,
    },
    TrialConversion,
    CheckoutPrompt {
        url: &'a str,
    },
    WaitingForCheckout,
    WaitingForSubscription {
        elapsed_minutes: Option<u64>,
        checkout_complete: bool,
    },
    SubscriptionAccessActive,
}

/// Neutral interaction facts. Rendering, terminal routing, browser process
/// behavior, and output suppression remain in the CLI adapter.
pub trait CommercialInteraction {
    fn human_output(&self) -> bool;
    fn browser_enabled(&self) -> bool;
    fn event(&mut self, event: CommercialEvent<'_>) -> Result<()>;
}

#[derive(Debug)]
pub struct CommercialSetupOutcome {
    pub artifact: VerifiedArtifactBundle,
    pub account_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommercialManageOutcome {
    pub portal_url: String,
    pub access_state: String,
    pub refresh_after_unix: Option<i64>,
    pub access_deadline_unix: Option<i64>,
    pub grace_deadline_unix: Option<i64>,
}

#[derive(Debug)]
pub enum SetupAccessPolicy<T> {
    Complete(T),
    PaidRequired { trial_unavailable: bool },
}

/// Borrowed, construction-only application facade. Construction performs no
/// allocation, network access, vault read, clock read, or presentation.
#[derive(Clone, Copy)]
pub struct CommercialLifecycle<'a, H: CommercialHost + ?Sized> {
    config: &'a CommercialConfig,
    host: &'a H,
}

impl<'a, H: CommercialHost + ?Sized> CommercialLifecycle<'a, H> {
    pub const fn new(config: &'a CommercialConfig, host: &'a H) -> Self {
        Self { config, host }
    }

    pub fn refresh_entitlement_if_due<C: CommercialClock + ?Sized>(&self, clock: &C) -> Result<()> {
        let current = match self
            .host
            .load_credential(CredentialRecordKind::SignedEntitlement)
        {
            Ok(CredentialRecord::SignedEntitlement(value)) => value,
            Ok(_) => bail!("key_store_unavailable: entitlement record mismatch"),
            Err(CredentialVaultError::NotFound) => {
                bail!("entitlement_required: run `ctx pro`")
            }
            Err(error) => return Err(vault_error(error)),
        };
        let now = clock.unix_time()?;
        if now < current.schedule().refresh_after_unix {
            return Ok(());
        }
        if matches!(
            self.host
                .load_credential(CredentialRecordKind::AnonymousTrial),
            Ok(CredentialRecord::AnonymousTrial(_))
        ) {
            return match self.host.refresh_anonymous_trial_entitlement() {
                Ok(()) => Ok(()),
                Err(_) => {
                    self.host.defer_anonymous_trial_refresh(now);
                    entitlement_still_usable(&current, now)
                }
            };
        }
        if let Ok(CredentialRecord::WorkOsSession(session)) = self
            .host
            .load_credential(CredentialRecordKind::WorkOsSession)
        {
            if session
                .entitlement_refresh_not_before_unix()
                .is_some_and(|not_before| now < not_before)
            {
                return entitlement_still_usable(&current, now);
            }
        }
        match self.refresh_entitlement_noninteractive(clock) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.defer_entitlement_refresh(now);
                entitlement_still_usable(&current, now)
            }
        }
    }

    pub fn access_token<C, I>(&self, clock: &C, interaction: &mut I) -> Result<H::AccessToken>
    where
        C: CommercialClock + ?Sized,
        I: CommercialInteraction + ?Sized,
    {
        match self
            .host
            .load_credential(CredentialRecordKind::WorkOsSession)
        {
            Ok(CredentialRecord::WorkOsSession(session)) => {
                self.resume_session(session, clock, interaction)
            }
            Ok(_) => Err(anyhow!(
                "key_store_unavailable: WorkOS session record mismatch"
            )),
            Err(CredentialVaultError::NotFound) => self.device_sign_in(interaction),
            Err(CredentialVaultError::Corrupt) => {
                self.delete_if_present(CredentialRecordKind::WorkOsSession)?;
                self.device_sign_in(interaction)
            }
            Err(error) => Err(vault_error(error)),
        }
    }

    pub fn access_token_noninteractive<C: CommercialClock + ?Sized>(
        &self,
        clock: &C,
    ) -> Result<H::AccessToken> {
        let session = match self
            .host
            .load_credential(CredentialRecordKind::WorkOsSession)
        {
            Ok(CredentialRecord::WorkOsSession(session)) => session,
            Ok(_) => bail!("key_store_unavailable: WorkOS session record mismatch"),
            Err(CredentialVaultError::NotFound) => {
                bail!("authentication_required: run `ctx pro`")
            }
            Err(error) => return Err(vault_error(error)),
        };
        if session.access_expires_at_unix() > clock.unix_time()? {
            if let Ok(access_token) = self.host.session_access_token(&session) {
                return Ok(access_token);
            }
        }
        self.persist_tokens(self.host.refresh_session(&session)?)
    }

    pub fn referral_access_token<C, I>(
        &self,
        auth_mode: ReferralAuthMode,
        clock: &C,
        interaction: &mut I,
    ) -> Result<H::AccessToken>
    where
        C: CommercialClock + ?Sized,
        I: CommercialInteraction + ?Sized,
    {
        match auth_mode {
            ReferralAuthMode::Interactive { .. } => self.access_token(clock, interaction),
            ReferralAuthMode::CachedOnly => {
                self.access_token_noninteractive(clock).map_err(|error| {
                    if stable_error_code(&error) == Some("authentication_required") {
                        anyhow!(
                            "authentication_required: rerun the referral command without --format json to sign in"
                        )
                    } else {
                        error
                    }
                })
            }
        }
    }

    pub fn stored_access_kind(&self) -> Result<Option<EntitlementAccessKind>> {
        match self
            .host
            .load_credential(CredentialRecordKind::SignedEntitlement)
        {
            Ok(CredentialRecord::SignedEntitlement(entitlement)) => {
                Ok(Some(entitlement.access_kind()))
            }
            Ok(_) => bail!("key_store_unavailable: entitlement record mismatch"),
            Err(CredentialVaultError::NotFound) => Ok(None),
            Err(error) => Err(vault_error(error)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn setup_with_paid_access<C, I>(
        &self,
        operation: &LifecycleOperation,
        data_root: &Path,
        installed_version: Option<&str>,
        trial_unavailable: bool,
        clock: &C,
        interaction: &mut I,
    ) -> Result<CommercialSetupOutcome>
    where
        C: CommercialClock + ?Sized,
        I: CommercialInteraction + ?Sized,
    {
        if trial_unavailable && interaction.human_output() {
            interaction.event(CommercialEvent::TrialConversion)?;
        }
        let mut access_token = self.access_token(clock, interaction)?;
        let anonymous_trial = self.checkout_anonymous_trial()?;
        let state = self.active_state(
            &mut access_token,
            anonymous_trial.as_ref(),
            clock,
            interaction,
        )?;
        let public_key = self.host.load_or_create_installation_public_key()?;
        let entitlement = self
            .host
            .entitlement(&access_token, &base64url(&public_key))?;
        if !entitlement.matches_account(&state) {
            bail!("invalid_response: entitlement identity does not match commercial account");
        }
        self.store_entitlement(entitlement, &public_key)?;
        let artifact = self.host.acquire_latest_artifact(
            operation,
            data_root,
            installed_version,
            self.config.release_trust,
        )?;
        Ok(CommercialSetupOutcome {
            artifact,
            account_state: state.access_state,
        })
    }

    pub fn manage<C, I>(&self, clock: &C, interaction: &mut I) -> Result<CommercialManageOutcome>
    where
        C: CommercialClock + ?Sized,
        I: CommercialInteraction + ?Sized,
    {
        let access_token = self.access_token(clock, interaction)?;
        let state = self.host.account(&access_token)?;
        let portal = self.host.portal(&access_token)?;
        let (refresh_after_unix, access_deadline_unix, grace_deadline_unix) =
            self.local_entitlement_deadlines(&state)?;
        let access_state = match state.access_state.as_str() {
            "trial" => "trial",
            "active" => "active",
            "canceling_paid" => "canceling_paid",
            "locked" | "none" => "locked",
            _ => bail!("invalid_response: commercial access state is invalid"),
        }
        .to_owned();
        Ok(CommercialManageOutcome {
            portal_url: portal.url,
            access_state,
            refresh_after_unix,
            access_deadline_unix,
            grace_deadline_unix,
        })
    }

    fn resume_session<C, I>(
        &self,
        session: WorkOsSessionMaterial,
        clock: &C,
        interaction: &mut I,
    ) -> Result<H::AccessToken>
    where
        C: CommercialClock + ?Sized,
        I: CommercialInteraction + ?Sized,
    {
        if session.access_expires_at_unix() > clock.unix_time()? {
            if let Ok(access_token) = self.host.session_access_token(&session) {
                return Ok(access_token);
            }
        }
        if !session.has_refresh_token() {
            return self.device_sign_in(interaction);
        }
        match self.host.refresh_session(&session) {
            Ok(tokens) => self.persist_tokens(tokens),
            Err(error) if error.to_string().starts_with("authentication_failed:") => {
                self.device_sign_in(interaction)
            }
            Err(error) => Err(error),
        }
    }

    fn refresh_rejected_access_token_noninteractive<C: CommercialClock + ?Sized>(
        &self,
        rejected_access_token: &H::AccessToken,
        clock: &C,
    ) -> Result<H::AccessToken> {
        let session = match self
            .host
            .load_credential(CredentialRecordKind::WorkOsSession)
        {
            Ok(CredentialRecord::WorkOsSession(session)) => session,
            Ok(_) => bail!("key_store_unavailable: WorkOS session record mismatch"),
            Err(CredentialVaultError::NotFound) => {
                bail!("authentication_required: run `ctx pro`")
            }
            Err(error) => return Err(vault_error(error)),
        };
        if !self
            .host
            .session_matches_access_token(&session, rejected_access_token)
            && session.access_expires_at_unix() > clock.unix_time()?
        {
            if let Ok(access_token) = self.host.session_access_token(&session) {
                return Ok(access_token);
            }
        }
        self.persist_tokens(self.host.refresh_session(&session)?)
    }

    fn device_sign_in<I: CommercialInteraction + ?Sized>(
        &self,
        interaction: &mut I,
    ) -> Result<H::AccessToken> {
        let authorization = self.host.begin_device_sign_in()?;
        if interaction.human_output() {
            interaction.event(CommercialEvent::DeviceSignIn {
                verification_uri: &authorization.verification_uri,
                user_code: &authorization.user_code,
            })?;
        }
        if interaction.browser_enabled() {
            interaction.event(CommercialEvent::OpenBrowser {
                url: &authorization.verification_uri_complete,
                destination: "ctx Pro sign-in",
            })?;
        }
        self.complete_device_sign_in(self.host.poll_device_sign_in(&authorization)?)
    }

    fn complete_device_sign_in(&self, tokens: WorkOsTokens) -> Result<H::AccessToken> {
        if !self.host.bootstrap_pending(&tokens)? {
            return self.persist_tokens(tokens);
        }
        let organization_id = self.host.bootstrap_personal_organization(&tokens)?;
        let refreshed = self
            .host
            .refresh_for_organization(&tokens, &organization_id)?;
        self.persist_tokens(refreshed)
    }

    fn persist_tokens(&self, tokens: WorkOsTokens) -> Result<H::AccessToken> {
        let (session, access_token) = self.host.persistable_session(tokens)?;
        self.host
            .store_credential(&CredentialRecord::WorkOsSession(session))
            .map_err(vault_error)?;
        Ok(access_token)
    }

    fn active_state<C, I>(
        &self,
        access_token: &mut H::AccessToken,
        anonymous_trial: Option<&AnonymousTrialMaterial>,
        clock: &C,
        interaction: &mut I,
    ) -> Result<CommercialState>
    where
        C: CommercialClock + ?Sized,
        I: CommercialInteraction + ?Sized,
    {
        resolve_active_state(
            access_token,
            |access_token| self.host.account(access_token),
            |access_token| self.host.checkout(access_token, anonymous_trial),
            |access_token, state, checkout| {
                self.await_checkout_access(access_token, state, checkout, clock, interaction)
            },
        )
    }

    fn await_checkout_access<C, I>(
        &self,
        access_token: &mut H::AccessToken,
        initial_state: &CommercialState,
        checkout: CheckoutResult,
        clock: &C,
        interaction: &mut I,
    ) -> Result<CommercialState>
    where
        C: CommercialClock + ?Sized,
        I: CommercialInteraction + ?Sized,
    {
        let expires_at_unix = checkout
            .expires_at_unix
            .ok_or_else(|| anyhow!("invalid_response: Checkout result has no expiry"))?;
        if let Some(url) = checkout.url {
            validate_https_url(&url, "Checkout")?;
            if interaction.human_output() {
                interaction.event(CommercialEvent::CheckoutPrompt { url: &url })?;
            }
            if interaction.browser_enabled() {
                interaction.event(CommercialEvent::OpenBrowser {
                    url: &url,
                    destination: "ctx Pro checkout",
                })?;
            }
            if interaction.human_output() {
                interaction.event(CommercialEvent::WaitingForCheckout)?;
            }
        } else if interaction.human_output() {
            interaction.event(CommercialEvent::WaitingForSubscription {
                elapsed_minutes: None,
                checkout_complete: true,
            })?;
        }
        let poll_started = clock.monotonic_now();
        let state = poll_checkout_access(
            expires_at_unix,
            || clock.unix_time(),
            || clock.monotonic_now().saturating_sub(poll_started),
            |duration| clock.sleep(duration),
            || {
                poll_checkout_account(
                    access_token,
                    initial_state,
                    |access_token| self.host.account(access_token),
                    |rejected_access_token| {
                        self.refresh_rejected_access_token_noninteractive(
                            rejected_access_token,
                            clock,
                        )
                    },
                )
            },
            |elapsed_seconds| {
                if interaction.human_output() {
                    let _ = interaction.event(CommercialEvent::WaitingForSubscription {
                        elapsed_minutes: Some(elapsed_seconds / 60),
                        checkout_complete: false,
                    });
                }
            },
        )?;
        if interaction.human_output() {
            interaction.event(CommercialEvent::SubscriptionAccessActive)?;
        }
        Ok(state)
    }

    fn store_entitlement(
        &self,
        entitlement: IssuedEntitlement,
        public_key: &[u8; INSTALLATION_PUBLIC_KEY_BYTES],
    ) -> Result<()> {
        let entitlement =
            BoundedSignedEntitlement::bind(entitlement, public_key, self.config.entitlement_trust)?;
        self.host
            .store_credential(&CredentialRecord::SignedEntitlement(entitlement))
            .map_err(vault_error)
    }

    fn refresh_entitlement_noninteractive<C: CommercialClock + ?Sized>(
        &self,
        clock: &C,
    ) -> Result<()> {
        let access_token = self.access_token_noninteractive(clock)?;
        let state = self.host.account(&access_token)?;
        if !state.grants_access() {
            bail!("commercial_access_locked: an active trial or subscription is required");
        }
        let public_key = self
            .host
            .installation_public_key()
            .context("key_store_unavailable: load installation public key")?;
        let entitlement = self
            .host
            .entitlement(&access_token, &base64url(&public_key))?;
        if !entitlement.matches_account(&state) {
            bail!("invalid_response: entitlement identity does not match commercial account");
        }
        self.store_entitlement(entitlement, &public_key)?;
        self.clear_refresh_backoff();
        Ok(())
    }

    fn clear_refresh_backoff(&self) {
        let Ok(CredentialRecord::WorkOsSession(session)) = self
            .host
            .load_credential(CredentialRecordKind::WorkOsSession)
        else {
            return;
        };
        let Ok(session) = session.with_entitlement_refresh_not_before_unix(None) else {
            return;
        };
        let _ = self
            .host
            .store_credential(&CredentialRecord::WorkOsSession(session));
    }

    fn defer_entitlement_refresh(&self, now: i64) {
        let Ok(CredentialRecord::WorkOsSession(session)) = self
            .host
            .load_credential(CredentialRecordKind::WorkOsSession)
        else {
            return;
        };
        let Ok(session) = session.with_entitlement_refresh_not_before_unix(Some(
            now.saturating_add(ENTITLEMENT_REFRESH_RETRY_SECONDS),
        )) else {
            return;
        };
        let _ = self
            .host
            .store_credential(&CredentialRecord::WorkOsSession(session));
    }

    fn delete_if_present(&self, kind: CredentialRecordKind) -> Result<()> {
        match self.host.delete_credential(kind) {
            Ok(()) | Err(CredentialVaultError::NotFound) => Ok(()),
            Err(error) => Err(vault_error(error)),
        }
    }

    fn checkout_anonymous_trial(&self) -> Result<Option<AnonymousTrialMaterial>> {
        match self
            .host
            .load_credential(CredentialRecordKind::AnonymousTrial)
        {
            Ok(CredentialRecord::AnonymousTrial(trial)) => Ok(Some(trial)),
            Ok(_) => bail!("key_store_unavailable: anonymous trial record mismatch"),
            Err(CredentialVaultError::NotFound) => Ok(None),
            Err(error) => Err(vault_error(error)),
        }
    }

    fn local_entitlement_deadlines(
        &self,
        state: &CommercialState,
    ) -> Result<(Option<i64>, Option<i64>, Option<i64>)> {
        if !state.grants_access() {
            return Ok((None, None, None));
        }
        match self
            .host
            .load_credential(CredentialRecordKind::SignedEntitlement)
        {
            Ok(CredentialRecord::SignedEntitlement(entitlement)) => {
                if !entitlement.matches_account(&state.subject, &state.account_id) {
                    bail!("key_store_unavailable: entitlement identity mismatch");
                }
                let schedule = entitlement.schedule();
                Ok((
                    Some(schedule.refresh_after_unix),
                    Some(schedule.access_deadline_unix),
                    Some(schedule.grace_deadline_unix),
                ))
            }
            Ok(_) => bail!("key_store_unavailable: entitlement record mismatch"),
            Err(CredentialVaultError::NotFound) => Ok((None, state.access_deadline_unix, None)),
            Err(error) => Err(vault_error(error)),
        }
    }
}

pub fn setup_with_access_policy<T>(
    trial_only: bool,
    referral_requested: bool,
    stored_access_kind: Option<EntitlementAccessKind>,
    anonymous_setup: impl FnOnce() -> Result<T>,
) -> Result<SetupAccessPolicy<T>> {
    let anonymous_precedes_paid = anonymous_trial_precedes_paid_conversion(stored_access_kind);
    if referral_requested && !anonymous_precedes_paid {
        bail!("invalid_request: a referral can only start a new anonymous Pro trial");
    }
    if trial_only || referral_requested || anonymous_precedes_paid {
        match anonymous_setup() {
            Ok(plan) => return Ok(SetupAccessPolicy::Complete(plan)),
            Err(error)
                if !trial_only
                    && !referral_requested
                    && anonymous_trial_requires_conversion(&error) =>
            {
                return Ok(SetupAccessPolicy::PaidRequired {
                    trial_unavailable: true,
                });
            }
            Err(error) => return Err(error),
        }
    }
    Ok(SetupAccessPolicy::PaidRequired {
        trial_unavailable: false,
    })
}

fn anonymous_trial_requires_conversion(error: &anyhow::Error) -> bool {
    matches!(
        stable_error_code(error),
        Some(
            "anonymous_trial_already_consumed"
                | "anonymous_trial_identity_ambiguous"
                | "anonymous_trial_installation_limit"
                | "commercial_access_locked"
        )
    )
}

fn anonymous_trial_precedes_paid_conversion(
    stored_access_kind: Option<EntitlementAccessKind>,
) -> bool {
    matches!(
        stored_access_kind,
        None | Some(EntitlementAccessKind::Trial)
    )
}

fn resolve_active_state<C>(
    context: &mut C,
    mut account: impl FnMut(&C) -> Result<CommercialState>,
    mut checkout: impl FnMut(&C) -> Result<CheckoutResult>,
    mut await_checkout: impl FnMut(&mut C, &CommercialState, CheckoutResult) -> Result<CommercialState>,
) -> Result<CommercialState> {
    let state = account(context)?;
    if state.grants_access() {
        return Ok(state);
    }
    let checkout = checkout(context)?;
    match checkout.kind.as_str() {
        "already_subscribed" => {
            let state = checkout.state.ok_or_else(|| {
                anyhow!("invalid_response: subscription result has no account state")
            })?;
            if state.grants_access() {
                return Ok(state);
            }
        }
        "checkout_created" | "checkout_pending" => {
            return await_checkout(context, &state, checkout)
        }
        _ => bail!("invalid_response: commercial API returned an invalid Checkout result"),
    }
    bail!("commercial_access_locked: an active trial or subscription is required")
}

fn poll_checkout_account<C>(
    access_token: &mut C,
    initial_state: &CommercialState,
    mut account: impl FnMut(&C) -> Result<CommercialState>,
    mut refresh: impl FnMut(&C) -> Result<C>,
) -> CheckoutPoll<CommercialState> {
    match account(access_token) {
        Ok(state) => classify_checkout_account_state(initial_state, state),
        Err(error) if is_checkout_authentication_failure(&error) => {
            let refreshed_access_token = match refresh(access_token) {
                Ok(access_token) => access_token,
                Err(error) if is_retryable_checkout_failure(&error) => {
                    return CheckoutPoll::Retryable(checkout_retry_after(&error))
                }
                Err(error) => return CheckoutPoll::Fatal(error),
            };
            *access_token = refreshed_access_token;
            match account(access_token) {
                Ok(state) => classify_checkout_account_state(initial_state, state),
                Err(error) if is_retryable_checkout_failure(&error) => {
                    CheckoutPoll::Retryable(checkout_retry_after(&error))
                }
                Err(error) => CheckoutPoll::Fatal(error),
            }
        }
        Err(error) if is_retryable_checkout_failure(&error) => {
            CheckoutPoll::Retryable(checkout_retry_after(&error))
        }
        Err(error) => CheckoutPoll::Fatal(error),
    }
}

fn classify_checkout_account_state(
    initial_state: &CommercialState,
    state: CommercialState,
) -> CheckoutPoll<CommercialState> {
    if state.subject != initial_state.subject || state.account_id != initial_state.account_id {
        CheckoutPoll::Fatal(anyhow!(
            "invalid_response: commercial account changed during Checkout"
        ))
    } else if state.grants_access() {
        CheckoutPoll::Granted(state)
    } else {
        CheckoutPoll::Pending
    }
}

fn is_checkout_authentication_failure(error: &anyhow::Error) -> bool {
    error.to_string().starts_with("authentication_required:")
}

fn entitlement_still_usable(entitlement: &BoundedSignedEntitlement, now: i64) -> Result<()> {
    if now <= entitlement.schedule().grace_deadline_unix {
        Ok(())
    } else {
        bail!("entitlement_expired: run `ctx pro manage` to restore access")
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        time::Duration,
    };

    use ctx_pro_access::commercial_api::BillingState;

    use super::*;

    fn elapsed_since(clock: &Cell<i64>, start: i64) -> Duration {
        Duration::from_secs(u64::try_from(clock.get() - start).unwrap())
    }

    fn commercial_state(access_state: &str, access_deadline_unix: Option<i64>) -> CommercialState {
        CommercialState {
            subject: "user_123".to_owned(),
            account_id: "org_123".to_owned(),
            access_state: access_state.to_owned(),
            access_deadline_unix,
            billing: BillingState {
                customer_associated: true,
                subscription_status: None,
                trial_end_unix: None,
                current_period_end_unix: None,
                cancel_at_period_end: false,
                canceled_at_unix: None,
                latest_invoice_status: None,
                latest_payment_state: "unknown".to_owned(),
            },
        }
    }

    #[derive(Default)]
    struct ManageHost {
        calls: RefCell<Vec<&'static str>>,
    }

    impl ManageHost {
        fn record(&self, call: &'static str) {
            self.calls.borrow_mut().push(call);
        }
    }

    impl CommercialService for ManageHost {
        type AccessToken = String;

        fn begin_device_sign_in(&self) -> Result<DeviceAuthorization> {
            self.record("service.begin_device_sign_in");
            bail!("unexpected device sign-in")
        }

        fn poll_device_sign_in(
            &self,
            _authorization: &DeviceAuthorization,
        ) -> Result<WorkOsTokens> {
            bail!("unexpected device sign-in poll")
        }

        fn refresh_session(&self, _session: &WorkOsSessionMaterial) -> Result<WorkOsTokens> {
            self.record("service.refresh_session");
            bail!("unexpected session refresh")
        }

        fn refresh_for_organization(
            &self,
            _tokens: &WorkOsTokens,
            _organization_id: &str,
        ) -> Result<WorkOsTokens> {
            bail!("unexpected organization refresh")
        }

        fn session_access_token(
            &self,
            _session: &WorkOsSessionMaterial,
        ) -> Result<Self::AccessToken> {
            self.record("service.session_access_token");
            Ok("stored-access-token".to_owned())
        }

        fn session_matches_access_token(
            &self,
            _session: &WorkOsSessionMaterial,
            access_token: &Self::AccessToken,
        ) -> bool {
            access_token == "stored-access-token"
        }

        fn bootstrap_pending(&self, _tokens: &WorkOsTokens) -> Result<bool> {
            bail!("unexpected bootstrap check")
        }

        fn persistable_session(
            &self,
            _tokens: WorkOsTokens,
        ) -> Result<(WorkOsSessionMaterial, Self::AccessToken)> {
            bail!("unexpected session persistence")
        }

        fn bootstrap_personal_organization(&self, _tokens: &WorkOsTokens) -> Result<String> {
            bail!("unexpected personal organization bootstrap")
        }

        fn account(&self, access_token: &Self::AccessToken) -> Result<CommercialState> {
            self.record("service.account");
            assert_eq!(access_token, "stored-access-token");
            Ok(commercial_state("none", None))
        }

        fn checkout(
            &self,
            _access_token: &Self::AccessToken,
            _anonymous_trial: Option<&AnonymousTrialMaterial>,
        ) -> Result<CheckoutResult> {
            bail!("unexpected checkout")
        }

        fn portal(&self, access_token: &Self::AccessToken) -> Result<PortalResult> {
            self.record("service.portal");
            assert_eq!(access_token, "stored-access-token");
            Ok(PortalResult {
                kind: "portal_created".to_owned(),
                url: "https://billing.example.test/session".to_owned(),
            })
        }

        fn entitlement(
            &self,
            _access_token: &Self::AccessToken,
            _installation_public_key_base64url: &str,
        ) -> Result<IssuedEntitlement> {
            bail!("unexpected entitlement request")
        }
    }

    impl CommercialVault for ManageHost {
        fn load_credential(
            &self,
            kind: CredentialRecordKind,
        ) -> std::result::Result<CredentialRecord, CredentialVaultError> {
            match kind {
                CredentialRecordKind::WorkOsSession => {
                    self.record("vault.load_workos_session");
                    WorkOsSessionMaterial::new(
                        "stored-access-token".to_owned(),
                        Some("stored-refresh-token".to_owned()),
                        2_000,
                    )
                    .map(CredentialRecord::WorkOsSession)
                }
                _ => {
                    self.record("vault.load_other");
                    Err(CredentialVaultError::NotFound)
                }
            }
        }

        fn store_credential(
            &self,
            _record: &CredentialRecord,
        ) -> std::result::Result<(), CredentialVaultError> {
            self.record("vault.store");
            Ok(())
        }

        fn delete_credential(
            &self,
            _kind: CredentialRecordKind,
        ) -> std::result::Result<(), CredentialVaultError> {
            self.record("vault.delete");
            Ok(())
        }

        fn load_or_create_installation_public_key(
            &self,
        ) -> Result<[u8; INSTALLATION_PUBLIC_KEY_BYTES]> {
            bail!("unexpected installation key creation")
        }

        fn installation_public_key(&self) -> Result<[u8; INSTALLATION_PUBLIC_KEY_BYTES]> {
            bail!("unexpected installation key read")
        }
    }

    impl CommercialArtifactDelivery for ManageHost {
        fn acquire_latest_artifact(
            &self,
            _operation: &LifecycleOperation,
            _data_root: &Path,
            _installed_version: Option<&str>,
            _release_trust: ReleaseTrust,
        ) -> Result<VerifiedArtifactBundle> {
            bail!("unexpected artifact delivery")
        }
    }

    impl AnonymousTrialRefresh for ManageHost {
        fn refresh_anonymous_trial_entitlement(&self) -> Result<()> {
            bail!("unexpected anonymous trial refresh")
        }

        fn defer_anonymous_trial_refresh(&self, _now: i64) {
            self.record("anonymous.defer_refresh");
        }
    }

    struct ManageClock<'a>(&'a ManageHost);

    impl CommercialClock for ManageClock<'_> {
        fn unix_time(&self) -> Result<i64> {
            self.0.record("clock.unix_time");
            Ok(1_000)
        }

        fn monotonic_now(&self) -> Duration {
            panic!("manage must not read the monotonic clock")
        }

        fn sleep(&self, _duration: Duration) {
            panic!("manage must not sleep")
        }
    }

    struct SilentInteraction;

    impl CommercialInteraction for SilentInteraction {
        fn human_output(&self) -> bool {
            false
        }

        fn browser_enabled(&self) -> bool {
            false
        }

        fn event(&mut self, _event: CommercialEvent<'_>) -> Result<()> {
            bail!("manage must not emit interaction events for a valid session")
        }
    }

    #[test]
    fn manage_preserves_one_account_one_portal_and_exact_operation_order() {
        let host = ManageHost::default();
        let config = CommercialConfig::for_channel(
            ctx_pro_lifecycle::release_manifest::ReleaseChannel::Stable,
        )
        .unwrap();
        let mut interaction = SilentInteraction;
        let outcome = CommercialLifecycle::new(&config, &host)
            .manage(&ManageClock(&host), &mut interaction)
            .unwrap();

        assert_eq!(outcome.access_state, "locked");
        assert_eq!(outcome.portal_url, "https://billing.example.test/session");
        assert_eq!(outcome.refresh_after_unix, None);
        assert_eq!(outcome.access_deadline_unix, None);
        assert_eq!(outcome.grace_deadline_unix, None);
        assert_eq!(
            host.calls.into_inner(),
            [
                "vault.load_workos_session",
                "clock.unix_time",
                "service.session_access_token",
                "service.account",
                "service.portal",
            ]
        );
    }

    #[test]
    fn only_terminal_anonymous_trial_states_enter_paid_conversion() {
        for code in [
            "anonymous_trial_already_consumed",
            "anonymous_trial_identity_ambiguous",
            "anonymous_trial_installation_limit",
            "commercial_access_locked",
        ] {
            assert!(anonymous_trial_requires_conversion(&anyhow!(
                "{code}: denied"
            )));
        }
        for code in ["service_unavailable", "rate_limited", "invalid_response"] {
            assert!(!anonymous_trial_requires_conversion(&anyhow!(
                "{code}: failed"
            )));
        }
    }

    #[test]
    fn trial_only_never_enters_paid_auth_with_an_existing_session() {
        let anonymous_calls = Cell::new(0);
        let error = setup_with_access_policy(
            true,
            false,
            Some(EntitlementAccessKind::Active),
            || -> Result<()> {
                anonymous_calls.set(anonymous_calls.get() + 1);
                bail!("anonymous_trial_identity_ambiguous: denied")
            },
        )
        .unwrap_err();

        assert_eq!(
            stable_error_code(&error),
            Some("anonymous_trial_identity_ambiguous")
        );
        assert_eq!(anonymous_calls.get(), 1);
    }

    #[test]
    fn terminal_trial_state_requests_paid_conversion_without_claiming_completion() {
        let result = setup_with_access_policy(
            false,
            false,
            Some(EntitlementAccessKind::Trial),
            || -> Result<()> { bail!("anonymous_trial_already_consumed: denied") },
        )
        .unwrap();
        assert!(matches!(
            result,
            SetupAccessPolicy::PaidRequired {
                trial_unavailable: true
            }
        ));
    }

    #[test]
    fn already_subscribed_uses_embedded_state_without_a_second_account_request() {
        let account_calls = Cell::new(0_u32);
        let checkout_calls = Cell::new(0_u32);
        let await_calls = Cell::new(0_u32);
        let initial = commercial_state("none", None);
        let subscribed = commercial_state("active", Some(2_000));
        let mut context = ();

        let state = resolve_active_state(
            &mut context,
            |_| {
                account_calls.set(account_calls.get() + 1);
                if account_calls.get() > 1 {
                    bail!("unexpected second account request");
                }
                Ok(initial.clone())
            },
            |_| {
                checkout_calls.set(checkout_calls.get() + 1);
                Ok(CheckoutResult {
                    kind: "already_subscribed".to_owned(),
                    url: None,
                    expires_at_unix: None,
                    state: Some(subscribed.clone()),
                })
            },
            |_, _, _| {
                await_calls.set(await_calls.get() + 1);
                bail!("Checkout polling must not run for an existing subscription")
            },
        )
        .unwrap();

        assert_eq!(state.access_state, "active");
        assert_eq!(account_calls.get(), 1);
        assert_eq!(checkout_calls.get(), 1);
        assert_eq!(await_calls.get(), 0);
    }

    #[test]
    fn url_less_pending_checkout_uses_the_polling_path() {
        let await_calls = Cell::new(0_u32);
        let initial = commercial_state("none", None);
        let active = commercial_state("active", Some(2_000));
        let mut context = ();

        let state = resolve_active_state(
            &mut context,
            |_| Ok(initial.clone()),
            |_| {
                Ok(CheckoutResult {
                    kind: "checkout_pending".to_owned(),
                    url: None,
                    expires_at_unix: Some(1_500),
                    state: None,
                })
            },
            |_, observed, checkout| {
                await_calls.set(await_calls.get() + 1);
                assert_eq!(observed.access_state, "none");
                assert_eq!(checkout.kind, "checkout_pending");
                assert!(checkout.url.is_none());
                assert_eq!(checkout.expires_at_unix, Some(1_500));
                Ok(active.clone())
            },
        )
        .unwrap();

        assert_eq!(state.access_state, "active");
        assert_eq!(await_calls.get(), 1);
    }

    #[test]
    fn checkout_poll_refreshes_an_expired_token_during_a_long_poll() {
        let clock = Cell::new(1_000_i64);
        let account_calls = Cell::new(0_u32);
        let refresh_calls = Cell::new(0_u32);
        let initial = commercial_state("none", None);
        let active = commercial_state("active", Some(2_000));
        let mut access_token = "original-access-token".to_owned();

        let state = poll_checkout_access(
            2_000,
            || Ok(clock.get()),
            || elapsed_since(&clock, 1_000),
            |duration| {
                clock.set(clock.get() + i64::try_from(duration.as_secs()).unwrap());
            },
            || {
                poll_checkout_account(
                    &mut access_token,
                    &initial,
                    |observed_access_token| {
                        account_calls.set(account_calls.get() + 1);
                        if observed_access_token == "original-access-token" {
                            if clock.get() < 1_360 {
                                Ok(initial.clone())
                            } else {
                                bail!("authentication_required: access token expired")
                            }
                        } else if observed_access_token == "refreshed-access-token" {
                            Ok(active.clone())
                        } else {
                            bail!("invalid_response: unexpected access token")
                        }
                    },
                    |rejected_access_token| {
                        refresh_calls.set(refresh_calls.get() + 1);
                        assert_eq!(rejected_access_token, "original-access-token");
                        Ok("refreshed-access-token".to_owned())
                    },
                )
            },
            |_| {},
        )
        .unwrap();

        assert_eq!(state.access_state, "active");
        assert!(clock.get() >= 1_360);
        assert_eq!(refresh_calls.get(), 1);
        assert_eq!(access_token, "refreshed-access-token");
        assert!(account_calls.get() > 2);
    }

    #[test]
    fn checkout_poll_retries_transient_refresh_failures() {
        let clock = Cell::new(1_000_i64);
        let refresh_calls = Cell::new(0_u32);
        let initial = commercial_state("none", None);
        let active = commercial_state("active", Some(2_000));
        let mut access_token = "expired-access-token".to_owned();

        let state = poll_checkout_access(
            2_000,
            || Ok(clock.get()),
            || elapsed_since(&clock, 1_000),
            |duration| {
                clock.set(clock.get() + i64::try_from(duration.as_secs()).unwrap());
            },
            || {
                poll_checkout_account(
                    &mut access_token,
                    &initial,
                    |observed_access_token| {
                        if observed_access_token == "fresh-access-token" {
                            Ok(active.clone())
                        } else {
                            bail!("authentication_required: access token expired")
                        }
                    },
                    |_| {
                        refresh_calls.set(refresh_calls.get() + 1);
                        if refresh_calls.get() == 1 {
                            bail!("service_unavailable: WorkOS token refresh failed")
                        }
                        Ok("fresh-access-token".to_owned())
                    },
                )
            },
            |_| {},
        )
        .unwrap();

        assert_eq!(state.access_state, "active");
        assert_eq!(refresh_calls.get(), 2);
        assert_eq!(access_token, "fresh-access-token");
    }

    #[test]
    fn checkout_poll_stops_after_one_fatal_refresh_failure() {
        let clock = Cell::new(1_000_i64);
        let account_calls = Cell::new(0_u32);
        let refresh_calls = Cell::new(0_u32);
        let initial = commercial_state("none", None);
        let mut access_token = "expired-access-token".to_owned();

        let error = poll_checkout_access::<CommercialState>(
            2_000,
            || Ok(clock.get()),
            || elapsed_since(&clock, 1_000),
            |duration| {
                clock.set(clock.get() + i64::try_from(duration.as_secs()).unwrap());
            },
            || {
                poll_checkout_account(
                    &mut access_token,
                    &initial,
                    |_| {
                        account_calls.set(account_calls.get() + 1);
                        bail!("authentication_required: access token expired")
                    },
                    |_| {
                        refresh_calls.set(refresh_calls.get() + 1);
                        bail!("authentication_failed: WorkOS refresh token was rejected")
                    },
                )
            },
            |_| {},
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "authentication_failed: WorkOS refresh token was rejected"
        );
        assert_eq!(clock.get(), 1_000);
        assert_eq!(account_calls.get(), 1);
        assert_eq!(refresh_calls.get(), 1);
        assert_eq!(access_token, "expired-access-token");
    }

    #[test]
    fn checkout_poll_rejects_identity_changes_after_token_refresh() {
        let initial = commercial_state("none", None);
        let mut changed = commercial_state("active", Some(2_000));
        changed.subject = "user_456".to_owned();
        let mut access_token = "expired-access-token".to_owned();

        let outcome = poll_checkout_account(
            &mut access_token,
            &initial,
            |observed_access_token| {
                if observed_access_token == "fresh-access-token" {
                    Ok(changed.clone())
                } else {
                    bail!("authentication_required: access token expired")
                }
            },
            |_| Ok("fresh-access-token".to_owned()),
        );

        let CheckoutPoll::Fatal(error) = outcome else {
            panic!("identity changes must fail closed");
        };
        assert_eq!(
            error.to_string(),
            "invalid_response: commercial account changed during Checkout"
        );
        assert_eq!(access_token, "fresh-access-token");
    }

    #[test]
    fn key_store_error_vocabulary_is_exact_and_does_not_expose_old_tokens() {
        let cases = [
            (
                CredentialVaultError::Unavailable { platform: "linux" },
                "key_store_unavailable:",
            ),
            (CredentialVaultError::Corrupt, "key_store_unavailable:"),
            (CredentialVaultError::Locked, "key_store_locked:"),
        ];
        for (error, expected) in cases {
            let rendered = vault_error(error).to_string();
            assert!(rendered.starts_with(expected));
            assert!(!rendered.contains("credential_vault_"));
        }
    }

    #[test]
    fn browser_urls_are_validated_before_launch() {
        assert!(validate_https_url("file:///tmp/session", "Checkout").is_err());
        assert!(validate_https_url("https://checkout.stripe.com/session", "Checkout").is_ok());
    }

    #[test]
    fn checkout_poll_uses_bounded_adaptive_backoff_without_real_sleep() {
        let clock = Cell::new(1_000_i64);
        let sleeps = RefCell::new(Vec::new());
        let attempts = Cell::new(0_u32);
        let result = poll_checkout_access(
            2_000,
            || Ok(clock.get()),
            || elapsed_since(&clock, 1_000),
            |duration| {
                sleeps.borrow_mut().push(duration);
                clock.set(clock.get() + i64::try_from(duration.as_secs()).unwrap());
            },
            || {
                let attempt = attempts.get() + 1;
                attempts.set(attempt);
                match attempt {
                    1 => CheckoutPoll::Retryable(None),
                    2..=5 => CheckoutPoll::Pending,
                    _ => CheckoutPoll::Granted("active"),
                }
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(result, "active");
        assert_eq!(attempts.get(), 6);
        assert_eq!(
            sleeps.into_inner(),
            [
                Duration::from_secs(3),
                Duration::from_secs(6),
                Duration::from_secs(12),
                Duration::from_secs(15),
                Duration::from_secs(15),
            ]
        );
    }

    #[test]
    fn checkout_poll_respects_retry_after_across_progress_wakes() {
        let clock = Cell::new(1_000_i64);
        let sleeps = RefCell::new(Vec::new());
        let attempts = Cell::new(0_u32);
        let result = poll_checkout_access(
            2_000,
            || Ok(clock.get()),
            || elapsed_since(&clock, 1_000),
            |duration| {
                sleeps.borrow_mut().push(duration);
                clock.set(clock.get() + i64::try_from(duration.as_secs()).unwrap());
            },
            || {
                attempts.set(attempts.get() + 1);
                if attempts.get() == 1 {
                    CheckoutPoll::Retryable(Some(Duration::from_secs(120)))
                } else {
                    CheckoutPoll::Granted("active")
                }
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(result, "active");
        assert_eq!(attempts.get(), 2);
        assert_eq!(
            sleeps.into_inner(),
            [Duration::from_secs(60), Duration::from_secs(60)]
        );
    }

    #[test]
    fn checkout_poll_stops_at_expiry_or_thirty_minutes() {
        for (expires_at, expected_error, expected_elapsed) in [
            (1_005, "checkout_expired:", 5_i64),
            (
                5_000,
                "checkout_timeout:",
                i64::try_from(CHECKOUT_POLL_MAX_SECONDS).unwrap(),
            ),
        ] {
            let clock = Cell::new(1_000_i64);
            let attempts = Cell::new(0_u32);
            let error = poll_checkout_access::<()>(
                expires_at,
                || Ok(clock.get()),
                || elapsed_since(&clock, 1_000),
                |duration| {
                    clock.set(clock.get() + i64::try_from(duration.as_secs()).unwrap());
                },
                || {
                    attempts.set(attempts.get() + 1);
                    CheckoutPoll::Pending
                },
                |_| {},
            )
            .unwrap_err();
            assert!(error.to_string().starts_with(expected_error), "{error:#}");
            assert!(error.to_string().contains("rerun `ctx pro`"));
            assert_eq!(clock.get() - 1_000, expected_elapsed);
            assert!(attempts.get() > 0);
        }
    }

    #[test]
    fn checkout_poll_rejects_a_grant_returned_after_the_deadline() {
        let clock = Cell::new(1_000_i64);
        let error = poll_checkout_access(
            1_005,
            || Ok(clock.get()),
            || elapsed_since(&clock, 1_000),
            |_| {},
            || {
                clock.set(1_005);
                CheckoutPoll::Granted("late grant")
            },
            |_| {},
        )
        .unwrap_err();
        assert!(error.to_string().starts_with("checkout_expired:"));
    }

    #[test]
    fn checkout_poll_timeout_is_monotonic_when_the_wall_clock_moves_backward() {
        let wall_clock = Cell::new(1_000_i64);
        let elapsed = Cell::new(Duration::ZERO);
        let error = poll_checkout_access::<()>(
            5_000,
            || Ok(wall_clock.get()),
            || elapsed.get(),
            |duration| {
                elapsed.set(elapsed.get().saturating_add(duration));
                wall_clock.set(wall_clock.get().saturating_sub(1));
            },
            || CheckoutPoll::Pending,
            |_| {},
        )
        .unwrap_err();
        assert!(error.to_string().starts_with("checkout_timeout:"));
        assert_eq!(
            elapsed.get(),
            Duration::from_secs(CHECKOUT_POLL_MAX_SECONDS)
        );
    }

    #[test]
    fn checkout_poll_fails_closed_and_reports_bounded_progress() {
        let clock = Cell::new(1_000_i64);
        let progress = RefCell::new(Vec::new());
        let error = poll_checkout_access::<()>(
            2_000,
            || Ok(clock.get()),
            || elapsed_since(&clock, 1_000),
            |duration| {
                clock.set(clock.get() + i64::try_from(duration.as_secs()).unwrap());
            },
            || {
                if clock.get() < 1_063 {
                    CheckoutPoll::Pending
                } else {
                    CheckoutPoll::Fatal(anyhow!("authentication_required: sign in again"))
                }
            },
            |elapsed| progress.borrow_mut().push(elapsed),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "authentication_required: sign in again");
        assert_eq!(progress.into_inner(), [60]);
        assert_eq!(clock.get(), 1_066);
    }
}
