//! Low-level host runtime for an installed ctx Pro helper.
//!
//! Product policy, data-root selection, daemon/refresh orchestration,
//! observability, and presentation remain in the `ctx` binary. Lifecycle
//! mutation and release trust live in `ctx-pro-lifecycle`; this crate consumes
//! its validated artifact identity while owning OS executable verification,
//! authenticated transport, protocol operations, and the generation-pinned
//! Core feed.

mod activation;
mod client;
mod core_worker_budget;
pub mod diagnostic;
pub mod evidence_preview;
pub mod helper_command;
pub mod setup_validation;
mod verified_executable;

mod host_port;

pub use activation::activation_material;
pub use client::{
    blame, blame_boundary_error, blame_diagnostic, core_finalization_generation_lease,
    finish_materialization, finish_materialization_in, invalid_blame_request,
    preflight_core_materialization, prepare_blame_freshness_with,
    reconstruct_core_finalization_generation_lease, release_core_finalization_generation_lease,
    selected_helper_artifact_sha256, smoke_helper_at_path, smoke_validated_helper,
    stable_error_code, start_materialization, start_materialization_in, status, status_for_core,
    sync_core_materialization, typed_blame_diagnostic, validate_core_finalization_generation_lease,
    BlameFreshnessPolicy, BlameResultFreshness, CoreMaterializationSyncOutcome, HelperSmoke,
    HostedBlameResult, MaterializationFinalizationReceipt, MaterializationStartReceipt,
    ProSetupRepairability, ProStatus, RESOURCE_NOT_FOUND_DIAGNOSTIC,
};
pub use client::{default_helper_path, git_executable};
pub use host_port::{
    AuthorizationMode, AuthorizationReceipt, CoreGenerationHost, CoreGenerationPin,
    InstalledProHost,
};
pub use verified_executable::VerifiedHelperExecutable;

#[cfg(any(test, feature = "test-support"))]
pub use client::status_with_helper_resolver;
