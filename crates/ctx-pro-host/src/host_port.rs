use std::path::{Path, PathBuf};

use anyhow::Result;
use ctx_pro_access::authorization::EntitlementSchedule;
use ctx_pro_host_protocol::{AuthorizationRequest, AUTHORIZATION_CHALLENGE_BYTES};

use ctx_pro_lifecycle::{
    installed_artifact::ValidatedArtifactIdentity, operation::LifecycleOperation,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationMode {
    Normal,
    Status,
}

pub struct AuthorizationReceipt {
    pub request: AuthorizationRequest,
    pub entitlement_schedule: Option<EntitlementSchedule>,
}

pub trait CoreGenerationPin {
    fn generation_id(&self) -> &str;
}

/// Supplies policy and installation authority retained by the `ctx` binary.
///
/// Calls occur only while preparing a helper process, authorization handshake,
/// status/query operation, or finalization burst. The per-event Core feed does
/// not call through this port.
pub trait InstalledProHost {
    fn host_version(&self) -> &str;

    fn existing_installation_id(&self, data_root: &Path) -> Result<Option<String>>;

    fn helper_override(&self) -> Result<Option<PathBuf>> {
        Ok(None)
    }

    fn validated_installed_helper(
        &self,
        data_root: &Path,
        operation: Option<&LifecycleOperation>,
    ) -> Result<ValidatedArtifactIdentity>;

    fn authorization_for_challenge(
        &self,
        data_root: &Path,
        challenge: &[u8; AUTHORIZATION_CHALLENGE_BYTES],
        mode: AuthorizationMode,
    ) -> Result<AuthorizationReceipt>;

    fn unix_time(&self) -> Result<i64>;
}

pub trait CoreGenerationHost: InstalledProHost {
    type Pin: CoreGenerationPin;

    fn pin_active_core_generation(&self, data_root: &Path) -> Result<Self::Pin>;
}
