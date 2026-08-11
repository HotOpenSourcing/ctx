use anyhow::{bail, Result};
use ctx_pro_host_protocol::{Capability, PROTOCOL_FINGERPRINT, PROTOCOL_VERSION};

use crate::HelperSmoke;

/// Whether setup is retaining an already-current installation or must install
/// a helper artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupInstallationDisposition {
    Current,
    InstallOrRepair,
}

/// Validates the lifecycle-independent artifact presence contract while
/// preserving the caller-owned artifact without copying it.
pub fn setup_artifact<T>(
    installation: SetupInstallationDisposition,
    artifact: Option<T>,
) -> Result<Option<T>> {
    if artifact.is_none() && installation != SetupInstallationDisposition::Current {
        bail!("invalid_response: Pro setup returned no helper artifact for an install or repair");
    }
    Ok(artifact)
}

pub fn validate_staged_helper(smoke: &HelperSmoke) -> Result<()> {
    if smoke.protocol_version != PROTOCOL_VERSION
        || smoke.protocol_fingerprint != PROTOCOL_FINGERPRINT
        || smoke.helper_version.is_empty()
        || smoke.helper_version.len() > 128
        || !smoke
            .capabilities
            .contains(&Capability::EntitlementAuthorization)
        || !smoke.capabilities.contains(&Capability::Status)
    {
        bail!("protocol_mismatch: staged Pro helper failed the activation smoke contract");
    }
    Ok(())
}

pub fn validate_account_state(value: &str) -> Result<()> {
    if !matches!(value, "trial" | "active" | "canceling_paid") {
        bail!("invalid_response: Pro setup returned an unknown account state");
    }
    Ok(())
}
