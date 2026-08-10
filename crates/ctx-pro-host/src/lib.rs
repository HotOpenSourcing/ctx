//! Low-level host runtime for an installed ctx Pro helper.
//!
//! Product policy, data-root selection, daemon/refresh orchestration,
//! observability, presentation, lifecycle mutation, release trust, and signed
//! manifest interpretation remain in the `ctx` binary. This crate receives
//! those decisions through narrow validated values and a borrowed host port
//! while it owns executable/process verification, authenticated transport,
//! protocol operations, and the generation-pinned Core feed.

mod client;
mod core_worker_budget;
pub mod diagnostic;
pub mod evidence_preview;
pub mod helper_command;
pub mod setup_validation;
mod verified_executable;

mod host_port;

pub use ctx_pro_lifecycle::installed_artifact as installed_helper;
pub use ctx_pro_lifecycle::release_manifest as lifecycle_manifest;

pub use client::{
    blame, blame_boundary_error, blame_diagnostic, core_finalization_generation_lease,
    finish_materialization, invalid_blame_request, preflight_core_materialization,
    prepare_blame_freshness_with, reconstruct_core_finalization_generation_lease,
    release_core_finalization_generation_lease, selected_helper_artifact_sha256,
    smoke_helper_at_path, stable_error_code, start_materialization, status, status_for_core,
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
pub use verified_executable::{LifecycleValidatedHelper, VerifiedHelperExecutable};

#[cfg(any(test, feature = "test-support"))]
pub use client::status_with_helper_resolver;
