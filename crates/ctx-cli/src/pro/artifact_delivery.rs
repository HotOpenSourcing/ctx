use std::path::Path;

use anyhow::Result;
use ctx_pro_lifecycle::operation::LifecycleOperation;

pub(super) use ctx_pro_application::ArtifactDeliveryConfig;
pub(crate) use ctx_pro_application::VerifiedArtifactBundle;

#[derive(Debug)]
#[cfg_attr(test, allow(dead_code))]
pub(crate) enum SetupArtifactBundle {
    Release(VerifiedArtifactBundle),
    #[cfg(ctx_pro_test_helper)]
    TestControl(crate::pro::test_control::TestControlHelperBundle),
}

pub(super) fn acquire_latest(
    operation: &LifecycleOperation,
    data_root: &Path,
    installed_version: Option<&str>,
    config: ArtifactDeliveryConfig<'_>,
) -> Result<SetupArtifactBundle> {
    ctx_pro_application::acquire_latest_artifact(operation, data_root, installed_version, config)
        .map(SetupArtifactBundle::Release)
}
