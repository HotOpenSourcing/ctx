use serde_json::{json, Value};

use ctx_pro_host::{ProSetupRepairability, ProStatus};

#[derive(Debug, Clone)]
pub struct LifecycleStatus {
    pub helper: ProStatus,
    pub preserved_data: bool,
}

impl LifecycleStatus {
    pub const fn new(helper: ProStatus, preserved_data: bool) -> Self {
        Self { helper, preserved_data }
    }

    pub fn into_json(self) -> Value {
        lifecycle_status_value(self.helper, self.preserved_data)
    }
}

/// Stable, presentation-neutral projection of one passive helper status.
pub fn lifecycle_status_value(helper: ProStatus, preserved_data: bool) -> Value {
    let helper_response_valid = !matches!(
        helper.error_code.as_deref(),
        Some("invalid_response" | "protocol_mismatch")
    );
    let ready = helper_response_valid && helper.ready;
    let materialized = helper_response_valid && helper.materialized;
    let (state, next_command, next_reason) = if !helper.installed {
        match helper.setup_repairability {
            ProSetupRepairability::Automated => ("repair_required", Some("ctx pro"), "helper_artifacts_invalid"),
            ProSetupRepairability::ManualDiagnosis => ("unavailable", None, "manual_diagnosis_required"),
            ProSetupRepairability::NotNeeded if preserved_data => (
                "uninstalled_data_preserved",
                Some("ctx pro"),
                "restore_preserved_pro_data",
            ),
            ProSetupRepairability::NotNeeded => ("not_setup", Some("ctx pro"), "helper_missing"),
        }
    } else {
        match helper.error_code.as_deref() {
            None if ready => ("ready", Some("ctx pro manage"), "billing_and_account"),
            Some("entitlement_expired") => ("locked", Some("ctx pro manage"), "subscription_or_trial_ended"),
            Some("not_materialized" | "needs_rebuild" | "partial" | "finalizing" | "needs_resume") => (
                "catch_up_required", Some("ctx pro"), "graph_not_current",
            ),
            Some("helper_upgrade_required" | "protocol_mismatch") => (
                "repair_required", Some("ctx pro"), "helper_incompatible",
            ),
            Some("key_store_unavailable" | "key_store_locked" | "corrupt_graph") => (
                "repair_required", Some("ctx pro"), "local_pro_unavailable",
            ),
            None if materialized => ("not_blame_ready", None, "no_available_blame_operations"),
            Some(_) | None => ("unavailable", Some("ctx pro"), "helper_unavailable"),
        }
    };
    json!({
        "schema_version": 2,
        "payload_type": "pro_status",
        "state": state,
        "installed": helper.installed,
        "ready": ready,
        "materialized": materialized,
        "helper_version": helper.helper_version,
        "protocol_version": helper.protocol_version,
        "capabilities": helper.capabilities,
        "error_code": helper.error_code,
        "projection_currentness": helper.projection_currentness,
        "materialized_coverage": helper.materialized_coverage,
        "repository_coverage": helper.repository_coverage,
        "core_preparation_peak_workers": helper.core_preparation_peak_workers,
        "storage_evidence": helper.storage_evidence,
        "supported_operations": helper.supported_operations,
        "available_operations": helper.available_operations,
        "access_state": helper.access_state,
        "refresh_after_unix": helper.refresh_after_unix,
        "access_deadline_unix": helper.access_deadline_unix,
        "grace_deadline_unix": helper.grace_deadline_unix,
        "next_action": { "command": next_command, "reason": next_reason },
    })
}
