use std::path::Path;

use anyhow::Result;
use ctx_pro_access::{
    authorization::VaultAuthorizationProvider,
    credential_vault::{vault_error, CredentialVaultError, VaultScope},
};
use ctx_pro_host_protocol::{AuthorizationRequest, AUTHORIZATION_CHALLENGE_BYTES};

#[cfg(ctx_pro_qualification)]
pub(crate) use ctx_pro_access::authorization::QualificationAuthorizationProvider;
pub(crate) use ctx_pro_access::authorization::{
    AuthorizationProvider, EntitlementSchedule, InstallationChallengeSigner,
};

use super::{
    commercial_config::CommercialConfig, commercial_lifecycle::CommercialLifecycleService,
};

/// Host refresh-policy wrapper around the access crate's vault-backed grant.
/// Normal helper use refreshes first; passive status reads deliberately do not.
pub(crate) struct StoredAuthorizationProvider {
    inner: VaultAuthorizationProvider,
}

impl StoredAuthorizationProvider {
    pub(crate) fn load(data_root: &Path) -> Result<Self> {
        CommercialLifecycleService::refresh_entitlement_if_due(data_root)?;
        Self::load_for_status(data_root)
    }

    pub(crate) fn load_for_status(data_root: &Path) -> Result<Self> {
        let installation_id = crate::identity::existing_installation_id(data_root)
            .map_err(|_| vault_error(CredentialVaultError::InvalidDataRoot))?
            .ok_or_else(|| vault_error(CredentialVaultError::NotFound))?;
        let config = CommercialConfig::production()?;
        let inner = VaultAuthorizationProvider::load(
            VaultScope {
                data_root,
                installation_id: &installation_id,
            },
            config.vault_namespace,
            config.entitlement_trust,
        )?;
        Ok(Self { inner })
    }

    pub(crate) fn entitlement_schedule(&self) -> EntitlementSchedule {
        self.inner.entitlement_schedule()
    }
}

impl AuthorizationProvider for StoredAuthorizationProvider {
    fn authorization_for_challenge(
        &self,
        challenge: &[u8; AUTHORIZATION_CHALLENGE_BYTES],
    ) -> Result<AuthorizationRequest> {
        self.inner.authorization_for_challenge(challenge)
    }
}
