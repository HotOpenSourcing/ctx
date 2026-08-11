//! Headless public Pro application policy.
//!
//! The executable supplies the installed-helper, Core orchestration, identity,
//! interaction, and presentation adapters.  This crate deliberately owns no
//! CLI parsing, terminal rendering, daemon lifecycle, provider reads, or
//! release/test-host authority.

mod application;
mod evidence;
mod status;
mod uninstall;

pub use application::{
    CoreOrchestration, MaterializationMode, MaterializationOutcome, ProApplication,
    ProApplicationHost,
};
pub use evidence::hydrate_evidence_previews;
pub use status::{lifecycle_status_value, LifecycleStatus};
pub use uninstall::{
    LocalProDataOutcome, ProDeletionService, UninstallDataDisposition, UninstallOutcome,
};

pub use ctx_pro_host::{
    blame_boundary_error, blame_diagnostic, invalid_blame_request, stable_error_code,
    BlameResultFreshness, CoreGenerationHost, CoreGenerationPin, CoreMaterializationSyncOutcome,
    HelperSmoke, HostedBlameResult, InstalledProHost, ProSetupRepairability, ProStatus,
    RESOURCE_NOT_FOUND_DIAGNOSTIC,
};
pub use ctx_pro_host_protocol::{BlameTarget, LineRange};
pub use ctx_pro_lifecycle::operation::LifecycleOperation;
