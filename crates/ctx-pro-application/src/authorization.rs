use std::path::Path;

use anyhow::Result;
use ctx_pro_access::{
    authorization::{AuthorizationProvider, EntitlementSchedule, VaultAuthorizationProvider},
    credential_vault::{vault_error, CredentialVaultError, VaultScope},
};
use ctx_pro_host_protocol::{AuthorizationRequest, AUTHORIZATION_CHALLENGE_BYTES};

use super::CommercialConfig;

/// Minimal identity boundary used by vault-backed application policy.
pub trait Identity {
    fn existing_installation_id(&self, data_root: &Path) -> Result<Option<String>>;
}

/// Host refresh-policy wrapper around the access crate's vault-backed grant.
/// Normal helper use refreshes first; passive status reads deliberately do not.
pub struct StoredAuthorizationProvider {
    inner: VaultAuthorizationProvider,
}

impl StoredAuthorizationProvider {
    pub fn load<I: Identity + ?Sized>(
        data_root: &Path,
        identity: &I,
        refresh_entitlement_if_due: impl FnOnce() -> Result<()>,
    ) -> Result<Self> {
        refresh_entitlement_if_due()?;
        Self::load_for_status(data_root, identity)
    }

    pub fn load_for_status<I: Identity + ?Sized>(data_root: &Path, identity: &I) -> Result<Self> {
        let installation_id = identity
            .existing_installation_id(data_root)
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

    pub fn entitlement_schedule(&self) -> EntitlementSchedule {
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

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use anyhow::anyhow;

    use super::*;

    struct FailingIdentity<'a> {
        called: &'a Cell<bool>,
    }

    impl Identity for FailingIdentity<'_> {
        fn existing_installation_id(&self, _data_root: &Path) -> Result<Option<String>> {
            self.called.set(true);
            Err(anyhow!("identity marker"))
        }
    }

    #[test]
    fn normal_authorization_runs_refresh_before_reading_identity_or_vault() {
        let refresh_called = Cell::new(false);
        let identity_called = Cell::new(false);
        let identity = FailingIdentity {
            called: &identity_called,
        };
        let error = StoredAuthorizationProvider::load(Path::new("/unused"), &identity, || {
            refresh_called.set(true);
            Err(anyhow!("refresh marker"))
        })
        .err()
        .unwrap();
        assert!(refresh_called.get());
        assert!(!identity_called.get());
        assert_eq!(error.to_string(), "refresh marker");
    }

    #[test]
    fn passive_authorization_maps_identity_failure_without_refresh_authority() {
        let identity_called = Cell::new(false);
        let identity = FailingIdentity {
            called: &identity_called,
        };
        let error = StoredAuthorizationProvider::load_for_status(Path::new("/unused"), &identity)
            .err()
            .unwrap();
        assert!(identity_called.get());
        assert!(error.to_string().starts_with("key_store_unavailable:"));
        assert!(!error.to_string().contains("identity marker"));
    }
}
