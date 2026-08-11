use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use ctx_pro_host_protocol::base64url;
use ctx_pro_lifecycle::operation::LifecycleOperation;

use ctx_pro_access::{
    authorization::InstallationChallengeSigner,
    commercial_api::{CommercialApiClient, TrialChallengeRequest},
    credential_vault::{
        vault_error, AnonymousTrialMaterial, BoundedSignedEntitlement, CredentialRecord,
        CredentialRecordKind, CredentialVaultError, PlatformCredentialVault,
        VaultInstallationChallengeSigner,
    },
};

use super::{
    acquire_latest_artifact, ArtifactDeliveryConfig, CommercialConfig, ProApplication,
    ProApplicationHost, VerifiedArtifactBundle,
};

const ENTITLEMENT_REFRESH_RETRY_SECONDS: i64 = 60 * 60;

fn store_anonymous_state(
    vault: &PlatformCredentialVault,
    entitlement: BoundedSignedEntitlement,
    trial: AnonymousTrialMaterial,
) -> Result<()> {
    vault
        .store_anonymous_trial_state(entitlement, trial)
        .map_err(anonymous_state_store_error)
}

fn anonymous_state_store_error(error: CredentialVaultError) -> anyhow::Error {
    match error {
        CredentialVaultError::SecretTooLarge { .. } => {
            anyhow!("invalid_response: anonymous trial state exceeds portable vault bounds")
        }
        error => vault_error(error),
    }
}

pub struct AnonymousTrialContext<'a> {
    pub config: &'a CommercialConfig,
    pub api: &'a CommercialApiClient,
    pub vault: &'a PlatformCredentialVault,
}

#[derive(Debug)]
pub struct AnonymousTrialSetup {
    pub artifact: VerifiedArtifactBundle,
    pub account_state: &'static str,
}

pub fn refresh_anonymous_trial_entitlement(
    context: AnonymousTrialContext<'_>,
    now: i64,
) -> Result<()> {
    let record = context
        .vault
        .load(CredentialRecordKind::AnonymousTrial)
        .map_err(vault_error)?;
    let CredentialRecord::AnonymousTrial(trial) = record else {
        bail!("key_store_unavailable: anonymous trial record mismatch");
    };
    if trial
        .refresh_not_before_unix()
        .is_some_and(|not_before| now < not_before)
    {
        bail!("service_unavailable: anonymous trial refresh is deferred");
    }
    let public_key = VaultInstallationChallengeSigner::new(context.vault)
        .public_key()
        .context("key_store_unavailable: load installation public key")?;
    let refresh = context.api.refresh_trial(&trial, &base64url(&public_key))?;
    let (entitlement, trial) =
        refresh.apply_to(trial, &public_key, context.config.entitlement_trust)?;
    store_anonymous_state(context.vault, entitlement, trial)
}

pub fn defer_anonymous_trial_refresh(context: AnonymousTrialContext<'_>, now: i64) {
    let Ok(CredentialRecord::AnonymousTrial(trial)) =
        context.vault.load(CredentialRecordKind::AnonymousTrial)
    else {
        return;
    };
    let Ok(trial) = trial
        .with_refresh_not_before_unix(Some(now.saturating_add(ENTITLEMENT_REFRESH_RETRY_SECONDS)))
    else {
        return;
    };
    let _ = context
        .vault
        .store(&CredentialRecord::AnonymousTrial(trial));
}

pub fn setup_anonymous_trial<H: ProApplicationHost + ?Sized>(
    application: &ProApplication<'_, H>,
    context: AnonymousTrialContext<'_>,
    operation: &LifecycleOperation,
    data_root: &Path,
    installed_version: Option<&str>,
    referral_codename: Option<&str>,
) -> Result<AnonymousTrialSetup> {
    context
        .vault
        .load_or_create_installation_signing_key()
        .map_err(vault_error)?;
    let public_key = VaultInstallationChallengeSigner::new(context.vault)
        .public_key()
        .context("key_store_unavailable: load installation public key")?;
    let encoded_public_key = base64url(&public_key);
    if let Ok(CredentialRecord::AnonymousTrial(trial)) =
        context.vault.load(CredentialRecordKind::AnonymousTrial)
    {
        if referral_codename.is_some() {
            bail!("invalid_request: a referral cannot be added after a Pro trial has started");
        }
        let refresh = context.api.refresh_trial(&trial, &encoded_public_key)?;
        let (entitlement, trial) =
            refresh.apply_to(trial, &public_key, context.config.entitlement_trust)?;
        let artifact = acquire_latest_artifact(
            operation,
            data_root,
            installed_version,
            ArtifactDeliveryConfig::new(context.api.config(), context.config.release_trust),
        )?;
        store_anonymous_state(context.vault, entitlement, trial)?;
        return Ok(AnonymousTrialSetup {
            artifact,
            account_state: "trial",
        });
    }

    let target = ctx_pro_lifecycle::release_manifest::platform_target();
    let challenge = context.api.trial_challenge(TrialChallengeRequest {
        schema_version: 1,
        channel: context.config.release_trust.channel().wire_name(),
        target: &target,
        current_version: installed_version,
        protocol_version: ctx_pro_host_protocol::PROTOCOL_VERSION,
        protocol_fingerprint: ctx_pro_host_protocol::PROTOCOL_FINGERPRINT,
        installation_public_key_base64url: &encoded_public_key,
        referral_codename,
    })?;
    let artifact = acquire_latest_artifact(
        operation,
        data_root,
        installed_version,
        ArtifactDeliveryConfig::new(context.api.config(), context.config.release_trust),
    )?;
    let evidence = application.activation_material(
        data_root,
        artifact.identity().clone(),
        challenge.challenge_base64url(),
        &encoded_public_key,
    )?;
    let activation = context
        .api
        .activate_trial(&challenge, &encoded_public_key, &evidence)?;
    if referral_codename.is_some() != activation.has_referral_claim() {
        bail!("invalid_response: referral attribution result is inconsistent");
    }
    let (entitlement, trial) =
        activation.into_anonymous_state(&public_key, context.config.entitlement_trust)?;
    store_anonymous_state(context.vault, entitlement, trial)?;
    Ok(AnonymousTrialSetup {
        artifact,
        account_state: "trial",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_anonymous_state_keeps_invalid_response_classification() {
        let error =
            anonymous_state_store_error(CredentialVaultError::SecretTooLarge { max: 1, actual: 2 });
        assert_eq!(
            error.to_string(),
            "invalid_response: anonymous trial state exceeds portable vault bounds"
        );
    }

    #[test]
    fn ordinary_vault_failures_keep_machine_error_classification() {
        assert!(anonymous_state_store_error(CredentialVaultError::Locked)
            .to_string()
            .starts_with("key_store_locked:"));
        assert!(anonymous_state_store_error(CredentialVaultError::Corrupt)
            .to_string()
            .starts_with("key_store_unavailable:"));
    }
}
