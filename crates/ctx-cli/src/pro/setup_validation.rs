use anyhow::Result;

use super::{artifact_delivery::SetupArtifactBundle, lifecycle::SetupInstallation};

pub(super) use ctx_pro_application::{validate_account_state, validate_staged_helper};

pub(super) fn setup_artifact(
    installation: &SetupInstallation,
    artifact: Option<SetupArtifactBundle>,
) -> Result<Option<SetupArtifactBundle>> {
    ctx_pro_application::setup_artifact(installation, artifact)
}
