use std::path::Path;

use anyhow::Result;
use ctx_pro_lifecycle::{artifact_delivery::fetch_latest, operation::LifecycleOperation};

pub use ctx_pro_lifecycle::artifact_delivery::{ArtifactDeliveryConfig, VerifiedArtifactBundle};

pub fn acquire_latest_artifact(
    operation: &LifecycleOperation,
    data_root: &Path,
    installed_version: Option<&str>,
    config: ArtifactDeliveryConfig<'_>,
) -> Result<VerifiedArtifactBundle> {
    fetch_latest(operation, data_root, installed_version, config)
}
