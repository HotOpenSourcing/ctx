use anyhow::Result;

use super::{artifact_delivery::SetupArtifactBundle, lifecycle::SetupInstallation};

pub(super) use ctx_pro_host::setup_validation::{validate_account_state, validate_staged_helper};

pub(super) fn setup_artifact(
    installation: &SetupInstallation,
    artifact: Option<SetupArtifactBundle>,
) -> Result<Option<SetupArtifactBundle>> {
    let disposition = if matches!(installation, SetupInstallation::Current(_)) {
        ctx_pro_host::setup_validation::SetupInstallationDisposition::Current
    } else {
        ctx_pro_host::setup_validation::SetupInstallationDisposition::InstallOrRepair
    };
    ctx_pro_host::setup_validation::setup_artifact(disposition, artifact)
}
