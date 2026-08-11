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
