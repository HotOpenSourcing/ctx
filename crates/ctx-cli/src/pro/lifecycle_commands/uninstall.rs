use std::path::Path;

use anyhow::{bail, Context, Result};
use ctx_pro_host_protocol::ProFilesystemLayout;
use serde_json::json;

use super::super::lifecycle_lock::LifecycleLock;
use super::render::uninstall as render_uninstall_human;
use super::{LocalProDataOutcome, ProDeletionService, UninstallDataDisposition};
use crate::pro::{
    local_deletion::{
        clear_local_pro_initialization_indicator, local_pro_graph_data_exists,
        local_pro_graph_key_cleanup_phase_exists, local_pro_initialization_indicator_exists,
    },
    pending_materialization,
};
use crate::ui::Ui;

pub(super) fn run_uninstall(
    data_root: &Path,
    service: Option<&mut dyn ProDeletionService>,
    disposition: UninstallDataDisposition,
    json_output: bool,
    ui: &mut Ui,
) -> Result<serde_json::Value> {
    let delete_data = disposition == UninstallDataDisposition::Delete;
    let initial_state = inspect_local_pro_uninstall_state(data_root)?;
    if !initial_state.data_artifact() && !initial_state.lifecycle_lock {
        crate::semantic::cancel_core_finalization_generation_lease(
            data_root,
            "Pro was uninstalled",
        )?;
        return emit_uninstall_result(false, LocalProDataOutcome::Absent, json_output, ui);
    }
    let Some(lifecycle_operation) = LifecycleLock::begin(data_root, false)? else {
        return emit_uninstall_result(false, LocalProDataOutcome::Absent, json_output, ui);
    };
    let state = inspect_local_pro_uninstall_state(data_root)?;
    crate::semantic::cancel_core_finalization_generation_lease(data_root, "Pro was uninstalled")?;
    pending_materialization::clear(&lifecycle_operation)?;
    if !delete_data && state.cleanup_phase {
        bail!(
            "key_store_unavailable: interrupted Pro deletion must be completed with `ctx pro uninstall --delete-data`"
        );
    }
    let helper_removed = if delete_data {
        let helper_removed = if state.initialized
            || state.graph_data
            || state.helper_files
            || state.cleanup_phase
        {
            let service = service.ok_or_else(|| {
                anyhow::anyhow!("key_store_unavailable: local deletion service is unavailable")
            })?;
            // The public delete-only adapter verifies and removes the exact current
            // graph inventory before destroying its native key record. It does not
            // launch or retain the private helper and remains available after an
            // ordinary uninstall.
            service.delete_graph_data(data_root)?;
            service.delete_commercial_credentials(data_root)?;
            let helper_removed = ctx_pro_lifecycle::installation::remove_installation_artifacts(
                &lifecycle_operation,
            )?;
            service.finish_deletion(data_root)?;
            helper_removed
        } else {
            ctx_pro_lifecycle::installation::remove_installation_artifacts(&lifecycle_operation)?
        };
        clear_local_pro_initialization_indicator(&lifecycle_operation)?;
        ctx_pro_lifecycle::state_markers::clear_data_preserved(&lifecycle_operation)?;
        if inspect_local_pro_uninstall_state(data_root)?.data_artifact() {
            bail!("key_store_unavailable: local Pro data deletion could not be verified");
        }
        helper_removed
    } else if state.graph_data {
        ctx_pro_lifecycle::state_markers::mark_data_preserved(&lifecycle_operation)?;
        ctx_pro_lifecycle::installation::remove_installation_artifacts(&lifecycle_operation)?
    } else {
        ctx_pro_lifecycle::state_markers::clear_data_preserved(&lifecycle_operation)?;
        ctx_pro_lifecycle::installation::remove_installation_artifacts(&lifecycle_operation)?
    };
    let data_outcome = if state.graph_data {
        if delete_data {
            LocalProDataOutcome::Deleted
        } else {
            LocalProDataOutcome::Preserved
        }
    } else {
        LocalProDataOutcome::Absent
    };
    emit_uninstall_result(helper_removed, data_outcome, json_output, ui)
}

fn emit_uninstall_result(
    helper_removed: bool,
    data_outcome: LocalProDataOutcome,
    json_output: bool,
    ui: &mut Ui,
) -> Result<serde_json::Value> {
    let value = uninstall_payload(helper_removed, data_outcome);
    if json_output {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        let document = render_uninstall_human(ui.stdout_context(), helper_removed, data_outcome);
        ui.write_stdout(&document)?;
    }
    Ok(value)
}

pub(super) fn uninstall_payload(
    helper_removed: bool,
    data_outcome: LocalProDataOutcome,
) -> serde_json::Value {
    let next_action = match data_outcome {
        LocalProDataOutcome::Deleted => Some(json!({
            "command": "ctx pro",
            "reason": "rebuild_pro_data",
        })),
        LocalProDataOutcome::Preserved => Some(json!({
            "command": "ctx pro",
            "reason": "restore_preserved_pro_data",
        })),
        LocalProDataOutcome::Absent => None,
    };
    json!({
        "schema_version": 1,
        "payload_type": "pro_uninstall",
        "uninstalled": true,
        "helper_removed": helper_removed,
        "local_pro_data": match data_outcome {
            LocalProDataOutcome::Absent => "absent",
            LocalProDataOutcome::Deleted => "deleted",
            LocalProDataOutcome::Preserved => "preserved",
        },
        "canonical_history_preserved": true,
        "next_action": next_action,
    })
}

pub(super) fn preserved_data_marker_is_set(data_root: &Path) -> bool {
    ctx_pro_lifecycle::state_markers::preserved_data_marker_is_set(data_root)
}

#[derive(Debug, Clone, Copy)]
struct LocalProUninstallState {
    initialized: bool,
    cleanup_phase: bool,
    graph_data: bool,
    helper_files: bool,
    preserved_marker: bool,
    pending_materialization: bool,
    lifecycle_lock: bool,
}

impl LocalProUninstallState {
    const fn data_artifact(self) -> bool {
        self.initialized
            || self.cleanup_phase
            || self.graph_data
            || self.helper_files
            || self.preserved_marker
            || self.pending_materialization
    }
}

fn inspect_local_pro_uninstall_state(data_root: &Path) -> Result<LocalProUninstallState> {
    let layout = ProFilesystemLayout::new(data_root);
    let helper_files =
        ctx_pro_lifecycle::installed_artifact::installation_artifacts_present(data_root);
    Ok(LocalProUninstallState {
        initialized: local_pro_initialization_indicator_exists(data_root)?,
        cleanup_phase: local_pro_graph_key_cleanup_phase_exists(data_root)?,
        graph_data: local_pro_graph_data_exists(data_root)?,
        helper_files,
        preserved_marker: ctx_pro_lifecycle::state_markers::preserved_data_marker_present(
            data_root,
        )?,
        pending_materialization: pending_materialization::pending(data_root)?,
        lifecycle_lock: regular_file_exists(&layout.lifecycle_lock_path(), "Pro lifecycle lock")?,
    })
}

fn regular_file_exists(path: &Path, label: &str) -> Result<bool> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => bail!("invalid_request: {label} is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {label}")),
    }
}
