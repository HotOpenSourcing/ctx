use anyhow::Result;

use ctx_pro_lifecycle::installation::SetupInstallation;

pub use ctx_pro_host::setup_validation::{validate_account_state, validate_staged_helper};

pub fn setup_artifact<T>(
    installation: &SetupInstallation,
    artifact: Option<T>,
) -> Result<Option<T>> {
    let disposition = if matches!(installation, SetupInstallation::Current(_)) {
        ctx_pro_host::setup_validation::SetupInstallationDisposition::Current
    } else {
        ctx_pro_host::setup_validation::SetupInstallationDisposition::InstallOrRepair
    };
    ctx_pro_host::setup_validation::setup_artifact(disposition, artifact)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use ctx_pro_host::HelperSmoke;
    use ctx_pro_host_protocol::{Capability, PROTOCOL_FINGERPRINT, PROTOCOL_VERSION};

    use super::*;

    #[test]
    fn repair_required_setup_rejects_a_missing_artifact() {
        let error = setup_artifact::<()>(&SetupInstallation::RepairRequired, None)
            .err()
            .unwrap()
            .to_string();
        assert_eq!(
            error,
            "invalid_response: Pro setup returned no helper artifact for an install or repair"
        );
    }

    #[test]
    fn staged_activation_requires_exact_protocol_authorization_and_status() {
        let mut smoke = HelperSmoke {
            protocol_version: PROTOCOL_VERSION,
            protocol_fingerprint: PROTOCOL_FINGERPRINT.to_owned(),
            helper_version: "0.1.0".to_owned(),
            capabilities: BTreeSet::from([
                Capability::EntitlementAuthorization,
                Capability::Status,
            ]),
        };
        validate_staged_helper(&smoke).unwrap();

        smoke
            .capabilities
            .remove(&Capability::EntitlementAuthorization);
        assert_eq!(
            validate_staged_helper(&smoke).unwrap_err().to_string(),
            "protocol_mismatch: staged Pro helper failed the activation smoke contract"
        );

        smoke
            .capabilities
            .insert(Capability::EntitlementAuthorization);
        smoke.protocol_fingerprint = "0".repeat(64);
        assert_eq!(
            validate_staged_helper(&smoke).unwrap_err().to_string(),
            "protocol_mismatch: staged Pro helper failed the activation smoke contract"
        );
    }
}
