use std::path::Path;

use anyhow::{bail, Context, Result};
use ctx_pro_host_protocol::base64url;
use ctx_pro_lifecycle::operation::LifecycleOperation;

use super::{
    artifact_delivery::{acquire_latest, ArtifactDeliveryConfig},
    authorization::InstallationChallengeSigner,
    commercial_api::TrialChallengeRequest,
    commercial_lifecycle::{vault_error, CommercialLifecycleService},
    credential_vault::{CredentialRecord, CredentialRecordKind, VaultInstallationChallengeSigner},
    lifecycle::{lifecycle_manifest::platform_target, ProSetupPlan},
};

const ENTITLEMENT_REFRESH_RETRY_SECONDS: i64 = 60 * 60;

pub(super) fn refresh_entitlement(service: &CommercialLifecycleService) -> Result<()> {
    let record = service
        .vault
        .load(CredentialRecordKind::AnonymousTrial)
        .map_err(vault_error)?;
    let CredentialRecord::AnonymousTrial(trial) = record else {
        bail!("key_store_unavailable: anonymous trial record mismatch");
    };
    let now = super::commercial_lifecycle::unix_time()?;
    if trial
        .refresh_not_before_unix()
        .is_some_and(|not_before| now < not_before)
    {
        bail!("service_unavailable: anonymous trial refresh is deferred");
    }
    let public_key = VaultInstallationChallengeSigner::new(&service.vault)
        .public_key()
        .context("key_store_unavailable: load installation public key")?;
    let refresh = service.api.refresh_trial(&trial, &base64url(&public_key))?;
    let (entitlement, trial) =
        refresh.apply_to(trial, &public_key, service.config.entitlement_trust)?;
    service.store_anonymous_state(entitlement, trial)
}

pub(super) fn defer_refresh(service: &CommercialLifecycleService, now: i64) {
    let Ok(CredentialRecord::AnonymousTrial(trial)) =
        service.vault.load(CredentialRecordKind::AnonymousTrial)
    else {
        return;
    };
    let Ok(trial) = trial
        .with_refresh_not_before_unix(Some(now.saturating_add(ENTITLEMENT_REFRESH_RETRY_SECONDS)))
    else {
        return;
    };
    let _ = service
        .vault
        .store(&CredentialRecord::AnonymousTrial(trial));
}

pub(super) fn setup(
    service: &CommercialLifecycleService,
    operation: &LifecycleOperation,
    data_root: &Path,
    installed_version: Option<&str>,
    referral_codename: Option<&str>,
) -> Result<ProSetupPlan> {
    let public_key = service.installation_public_key()?;
    let encoded_public_key = base64url(&public_key);
    if let Ok(CredentialRecord::AnonymousTrial(trial)) =
        service.vault.load(CredentialRecordKind::AnonymousTrial)
    {
        if referral_codename.is_some() {
            bail!("invalid_request: a referral cannot be added after a Pro trial has started");
        }
        let refresh = service.api.refresh_trial(&trial, &encoded_public_key)?;
        let (entitlement, trial) =
            refresh.apply_to(trial, &public_key, service.config.entitlement_trust)?;
        let artifact = acquire_latest(
            operation,
            data_root,
            installed_version,
            ArtifactDeliveryConfig::new(service.api.config(), service.config.release_trust),
        )?;
        service.store_anonymous_state(entitlement, trial)?;
        return Ok(ProSetupPlan {
            artifact: Some(artifact),
            account_state: "trial".to_owned(),
        });
    }

    let target = platform_target();
    let challenge = service.api.trial_challenge(TrialChallengeRequest {
        schema_version: 1,
        channel: service.config.release_trust.channel().wire_name(),
        target: &target,
        current_version: installed_version,
        protocol_version: ctx_pro_host_protocol::PROTOCOL_VERSION,
        protocol_fingerprint: ctx_pro_host_protocol::PROTOCOL_FINGERPRINT,
        installation_public_key_base64url: &encoded_public_key,
        referral_codename,
    })?;
    let artifact = acquire_latest(
        operation,
        data_root,
        installed_version,
        ArtifactDeliveryConfig::new(service.api.config(), service.config.release_trust),
    )?;
    let evidence = super::client::activation_material(
        data_root,
        artifact.verified_helper_identity()?,
        challenge.challenge_base64url(),
        &encoded_public_key,
    )?;
    let activation = service
        .api
        .activate_trial(&challenge, &encoded_public_key, &evidence)?;
    if referral_codename.is_some() != activation.has_referral_claim() {
        bail!("invalid_response: referral attribution result is inconsistent");
    }
    let (entitlement, trial) =
        activation.into_anonymous_state(&public_key, service.config.entitlement_trust)?;
    service.store_anonymous_state(entitlement, trial)?;
    Ok(ProSetupPlan {
        artifact: Some(artifact),
        account_state: "trial".to_owned(),
    })
}
