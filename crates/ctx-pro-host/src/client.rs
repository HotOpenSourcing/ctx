use std::{
    collections::BTreeSet,
    io::Read,
    ops::Deref,
    path::Path,
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use ctx_pro_host_protocol::{
    read_frame, write_frame, BlameResult, BlameTarget, Capability, EntitlementAccessState,
    HelloRequest, HelperEnvelope, HelperMessage, HostMessage, QuerySnapshotExpectation,
    StatusRequest, StatusResult, PROTOCOL_FINGERPRINT, PROTOCOL_VERSION,
};
use serde::Serialize;
use uuid::Uuid;

#[cfg(feature = "qualification")]
use ctx_pro_access::authorization::QualificationAuthorizationProvider;
use ctx_pro_access::authorization::{AuthorizationProvider, EntitlementSchedule};

use crate::{CoreGenerationHost, InstalledProHost, VerifiedHelperExecutable};

#[path = "client_support.rs"]
mod support;
use crate::helper_command;
pub use support::{default_helper_path, git_executable};
use support::{helper_executable, helper_path};

#[path = "client_errors.rs"]
mod errors;
pub use errors::typed_blame_diagnostic;
pub use errors::{blame_boundary_error, invalid_blame_request};
pub use errors::{blame_diagnostic, stable_error_code, RESOURCE_NOT_FOUND_DIAGNOSTIC};
use errors::{protocol_blame_error, protocol_error};

#[path = "client_output.rs"]
mod core_materialization;
pub use core_materialization::{
    core_finalization_generation_lease, reconstruct_core_finalization_generation_lease,
    release_core_finalization_generation_lease, sync_core_materialization,
    validate_core_finalization_generation_lease, CoreMaterializationSyncOutcome,
};

/// Verifies that this installation has a selectable Pro helper before callers
/// perform expensive Core index admission work. The eventual connection still
/// performs the complete executable verification and protocol handshake.
pub fn preflight_core_materialization(
    host: &(impl InstalledProHost + ?Sized),
    data_root: &Path,
) -> Result<()> {
    helper_path(host, data_root).map(drop)
}

pub fn selected_helper_artifact_sha256(
    host: &(impl InstalledProHost + ?Sized),
    data_root: &Path,
) -> Result<Option<String>> {
    match helper_executable(host, data_root) {
        Ok(helper) => Ok(Some(helper.artifact_sha256().to_owned())),
        Err(error) if stable_error_code(&error) == Some("pro_not_installed") => Ok(None),
        Err(error) => Err(error),
    }
}

#[path = "client_status.rs"]
mod client_status;
#[cfg(any(test, feature = "test-support"))]
pub use client_status::status_with_helper_resolver;
pub use client_status::{
    smoke_helper_at_path, status, status_for_core, HelperSmoke, ProSetupRepairability, ProStatus,
};

#[cfg(unix)]
use std::os::unix::process::CommandExt as _;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
const BLAME_TIMEOUT: Duration = Duration::from_secs(30);
const BATCH_TIMEOUT: Duration = Duration::from_secs(60);
const STDERR_MAX_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct MaterializationStartReceipt {
    pub prior_core_generation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MaterializationFinalizationReceipt {
    pub schema_version: u32,
    pub payload_type: &'static str,
    pub core_generation_id: String,
    pub source_count: u64,
    pub batches: u64,
    pub observations: u64,
    pub replayed_batches: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlameResultFreshness {
    Current,
    StaleCommitted,
}

#[derive(Debug, Clone)]
pub struct HostedBlameResult {
    pub result: BlameResult,
    pub freshness: BlameResultFreshness,
}

impl Deref for HostedBlameResult {
    type Target = BlameResult;

    fn deref(&self) -> &Self::Target {
        &self.result
    }
}

mod materialization;
mod operations;
mod transport;

use materialization::*;
pub use materialization::{
    finish_materialization, prepare_blame_freshness_with, start_materialization,
    BlameFreshnessPolicy,
};
pub use operations::blame;
#[cfg(test)]
use operations::*;
pub use transport::ProClient;

impl ProClient {
    pub(super) fn helper_artifact_sha256(&self) -> Result<&str> {
        self._execution_guard
            .as_ref()
            .map(VerifiedHelperExecutable::artifact_sha256)
            .ok_or_else(|| anyhow!("invalid_response: Pro helper execution identity is missing"))
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
