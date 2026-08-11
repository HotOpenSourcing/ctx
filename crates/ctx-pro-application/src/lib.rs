//! Headless public Pro application policy.
//!
//! The executable supplies the installed-helper, Core orchestration, identity,
//! interaction, and presentation adapters.  This crate deliberately owns no
//! CLI parsing, terminal rendering, daemon lifecycle, provider reads, or
//! release/test-host authority.

mod anonymous_trial;
mod application;
mod artifact_delivery;
mod authorization;
mod commercial_config;
mod commercial_lifecycle;
mod commercial_production_record;
mod evidence;
mod lifecycle_commands;
mod referral;
mod setup_validation;
mod status;
mod uninstall;
mod validation;

pub use anonymous_trial::{
    defer_anonymous_trial_refresh, refresh_anonymous_trial_entitlement, setup_anonymous_trial,
    AnonymousTrialContext, AnonymousTrialSetup,
};
pub use application::{
    CoreOrchestration, MaterializationMode, MaterializationOutcome, ProApplication,
    ProApplicationHost,
};
pub use artifact_delivery::{
    acquire_latest_artifact, ArtifactDeliveryConfig, VerifiedArtifactBundle,
};
pub use authorization::{Identity, StoredAuthorizationProvider};
pub use commercial_config::{selected_channel, CommercialConfig};
pub use commercial_lifecycle::{
    setup_with_access_policy, AnonymousTrialRefresh, CommercialArtifactDelivery, CommercialClock,
    CommercialEvent, CommercialHost, CommercialInteraction, CommercialLifecycle,
    CommercialManageOutcome, CommercialService, CommercialSetupOutcome, CommercialVault,
    SetupAccessPolicy,
};
pub use ctx_pro_access::authorization::{
    AuthorizationProvider, EntitlementSchedule, InstallationChallengeSigner,
};
pub use evidence::hydrate_evidence_previews;
pub use lifecycle_commands::{
    reusable_setup_access_state, HelperConnectionFact, LifecycleCommandFacts, LifecycleExecution,
    ManageAccess, ManageCommandOutcome, ManagePlan, MaterializationFact, ReconcileFact,
    SetupAccess, SetupAccessRequest, SetupAdmission, SetupCommandHost, SetupCommandOutcome,
    SetupCompletion, SetupPlan, SetupStart,
};
pub use referral::{
    admit_referral, execute_referral, is_iso_country_code, retry_referral_payout,
    validate_referral_codename, validate_referral_country, ReferralAdmission, ReferralAuthMode,
    ReferralClock, ReferralCommand, ReferralIdentity, ReferralOutcome, ReferralPayoutResponse,
    ReferralPayoutRetry, ReferralRequest, ReferralService,
};
pub use setup_validation::{setup_artifact, validate_account_state, validate_staged_helper};
pub use status::{lifecycle_status_value, LifecycleStatus};
pub use uninstall::{
    LocalProDataOutcome, ProDeletionService, UninstallDataDisposition, UninstallOutcome,
};
pub use validation::{validate_access_status, validate_portal_url};

pub use ctx_pro_host::{
    blame_boundary_error, blame_diagnostic, invalid_blame_request, stable_error_code,
    BlameResultFreshness, CoreGenerationHost, CoreGenerationPin, CoreMaterializationSyncOutcome,
    HelperSmoke, HostedBlameResult, InstalledProHost, ProSetupRepairability, ProStatus,
    RESOURCE_NOT_FOUND_DIAGNOSTIC,
};
pub use ctx_pro_host_protocol::{BlameTarget, LineRange};
pub use ctx_pro_lifecycle::operation::LifecycleOperation;
