use std::path::Path;

use anyhow::Result;
use ctx_pro_lifecycle::{
    artifact_delivery::VerifiedArtifactBundle,
    installation::{self, InstallRecheckPort},
    operation::LifecycleOperation,
    release_manifest::ReleaseTrust,
};

pub(super) use ctx_pro_lifecycle::release_manifest as lifecycle_manifest;

#[path = "lifecycle_commands.rs"]
mod commands;
pub(crate) use commands::{
    lifecycle_status_json, lifecycle_status_json_for_core, run_lifecycle, ProArgs,
};
pub(super) use commands::{ProDeletionService, ProLifecycleService, ProManagePlan, ProSetupPlan};

struct DaemonRecheckPort;

impl InstallRecheckPort for DaemonRecheckPort {
    fn publish_recheck_intent(&self, data_root: &Path, artifact_sha256: &str) -> Result<()> {
        crate::semantic::publish_source_backed_pro_recheck(data_root, artifact_sha256)
    }

    fn recheck_targets(&self, data_root: &Path, artifact_sha256: &str) -> Result<bool> {
        crate::semantic::source_backed_pro_recheck_targets(data_root, artifact_sha256)
    }

    fn wake_recheck(&self, data_root: &Path) {
        crate::semantic::wake_source_backed_pro_recheck(data_root);
    }
}

pub(super) fn install_verified_bundle(
    bundle: &VerifiedArtifactBundle,
    operation: &LifecycleOperation,
    trust: ReleaseTrust,
) -> Result<serde_json::Value> {
    installation::install_verified_bundle(bundle, operation, trust, &DaemonRecheckPort)
}
