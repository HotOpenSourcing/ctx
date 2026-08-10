//! Low-level host runtime for an installed ctx Pro helper.
//!
//! Product policy, data-root selection, daemon/refresh orchestration,
//! observability, presentation, and lifecycle mutation remain in the `ctx`
//! binary. This crate receives those decisions through explicit values and a
//! borrowed host port while it owns executable verification, authenticated
//! transport, protocol operations, and the generation-pinned Core feed.

mod client;
mod client_output;
mod client_status;
mod client_support;
mod core_worker_budget;
pub mod diagnostic;
pub mod evidence_preview;
pub mod helper_command;
pub mod installed_helper;
pub mod lifecycle_manifest;
pub mod setup_validation;
mod verified_executable;

mod host_port;

pub use client::{
    blame, blame_boundary_error, blame_diagnostic, core_finalization_generation_lease,
    finish_materialization, invalid_blame_request, preflight_core_materialization,
    prepare_blame_freshness_with, reconstruct_core_finalization_generation_lease,
    release_core_finalization_generation_lease, selected_helper_artifact_sha256, stable_error_code,
    start_materialization, sync_core_materialization, typed_blame_diagnostic,
    validate_core_finalization_generation_lease, BlameFreshnessPolicy, BlameResultFreshness,
    CoreMaterializationSyncOutcome, HostedBlameResult, MaterializationFinalizationReceipt,
    MaterializationStartReceipt, ProClient, RESOURCE_NOT_FOUND_DIAGNOSTIC,
};
pub use client_status::{
    smoke_helper_at_path, status, status_for_core, HelperSmoke, ProSetupRepairability, ProStatus,
};
pub use client_support::{default_helper_path, git_executable};
pub use host_port::{
    AuthorizationMode, AuthorizationReceipt, CoreGenerationHost, CoreGenerationPin,
    InstalledProHost,
};
pub use verified_executable::{PreparedHelperExecution, VerifiedHelperExecutable};

#[cfg(any(test, feature = "test-support"))]
pub use client_status::status_with_helper_resolver;
