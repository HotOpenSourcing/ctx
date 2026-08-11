use std::path::Path;

use anyhow::Result;
use ctx_pro_lifecycle::{
    artifact_delivery::fetch_latest, installed_artifact::ValidatedArtifactIdentity,
    operation::LifecycleOperation,
};

pub(super) use ctx_pro_lifecycle::artifact_delivery::ArtifactDeliveryConfig;

#[derive(Debug)]
#[cfg_attr(test, allow(dead_code))]
pub(crate) enum SetupArtifactBundle {
    Release(VerifiedArtifactBundle),
    #[cfg(ctx_pro_test_helper)]
    TestControl(crate::pro::test_control::TestControlHelperBundle),
}

impl SetupArtifactBundle {
    pub(crate) fn verified_helper_identity(&self) -> Result<ValidatedArtifactIdentity> {
        match self {
            Self::Release(bundle) => Ok(bundle.identity().clone()),
            #[cfg(ctx_pro_test_helper)]
            Self::TestControl(bundle) => {
                let _ = bundle;
                anyhow::bail!(
                    "invalid_request: scripted helpers do not have a signed release identity"
                )
            }
        }
    }

    #[cfg(ctx_pro_test_helper)]
    pub(crate) fn test_control_path(&self) -> Result<&Path> {
        match self {
            Self::Release(bundle) => Ok(bundle.artifact_path()),
            Self::TestControl(bundle) => bundle.verified_path_ref(),
        }
    }
}

pub(super) fn acquire_latest(
    operation: &LifecycleOperation,
    data_root: &Path,
    installed_version: Option<&str>,
    config: ArtifactDeliveryConfig<'_>,
) -> Result<SetupArtifactBundle> {
    fetch_latest(operation, data_root, installed_version, config).map(SetupArtifactBundle::Release)
}

pub(crate) use ctx_pro_lifecycle::artifact_delivery::VerifiedArtifactBundle;
