use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use ctx_pro_host_protocol::ProFilesystemLayout;
use serde::Serialize;
use serde_json::{json, Value};

use crate::ProApplicationHost;

/// Local-only destruction boundary. The concrete CLI adapter may reach the
/// selected native vault, but commercial configuration is not required.
pub trait ProDeletionService {
    fn delete_graph_data(&mut self, data_root: &Path) -> Result<()>;
    fn delete_commercial_credentials(&mut self, data_root: &Path) -> Result<()>;
    fn finish_deletion(&mut self, data_root: &Path) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UninstallDataDisposition {
    Delete,
    Keep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalProDataOutcome {
    Absent,
    Deleted,
    Preserved,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UninstallOutcome {
    pub helper_removed: bool,
    pub local_pro_data: LocalProDataOutcome,
}

impl UninstallOutcome {
    pub fn json(&self) -> Value {
        let next_action = match self.local_pro_data {
            LocalProDataOutcome::Deleted => {
                Some(json!({"command": "ctx pro", "reason": "rebuild_pro_data"}))
            }
            LocalProDataOutcome::Preserved => {
                Some(json!({"command": "ctx pro", "reason": "restore_preserved_pro_data"}))
            }
            LocalProDataOutcome::Absent => None,
        };
        json!({
            "schema_version": 1,
            "payload_type": "pro_uninstall",
            "uninstalled": true,
            "helper_removed": self.helper_removed,
            "local_pro_data": self.local_pro_data,
            "canonical_history_preserved": true,
            "next_action": next_action,
        })
    }
}

pub(crate) fn uninstall<H: ProApplicationHost + ?Sized>(
    host: &H,
    data_root: &Path,
    deletion: Option<&mut dyn ProDeletionService>,
    disposition: UninstallDataDisposition,
) -> Result<UninstallOutcome> {
    let delete_data = disposition == UninstallDataDisposition::Delete;
    let initial = inspect(data_root)?;
    if !initial.data_artifact() && !initial.lifecycle_lock {
        host.cancel_core_finalization(data_root, "Pro was uninstalled")?;
        return Ok(UninstallOutcome {
            helper_removed: false,
            local_pro_data: LocalProDataOutcome::Absent,
        });
    }
    let Some(operation) =
        ctx_pro_lifecycle::operation::LifecycleOperation::begin(data_root, false)?
    else {
        return Ok(UninstallOutcome {
            helper_removed: false,
            local_pro_data: LocalProDataOutcome::Absent,
        });
    };
    let state = inspect(data_root)?;
    host.cancel_core_finalization(data_root, "Pro was uninstalled")?;
    ctx_pro_lifecycle::state_markers::clear_materialization(&operation)?;
    if !delete_data && state.cleanup_phase {
        bail!("key_store_unavailable: interrupted Pro deletion must be completed with `ctx pro uninstall --delete-data`");
    }
    let helper_removed = if delete_data {
        let helper_removed =
            if state.initialized || state.graph_data || state.helper_files || state.cleanup_phase {
                let deletion = deletion.ok_or_else(|| {
                    anyhow!("key_store_unavailable: local deletion service is unavailable")
                })?;
                deletion.delete_graph_data(data_root)?;
                deletion.delete_commercial_credentials(data_root)?;
                let removed =
                    ctx_pro_lifecycle::installation::remove_installation_artifacts(&operation)?;
                deletion.finish_deletion(data_root)?;
                removed
            } else {
                ctx_pro_lifecycle::installation::remove_installation_artifacts(&operation)?
            };
        ctx_pro_lifecycle::deletion::clear_local_pro_initialization_indicator(&operation)?;
        ctx_pro_lifecycle::state_markers::clear_data_preserved(&operation)?;
        if inspect(data_root)?.data_artifact() {
            bail!("key_store_unavailable: local Pro data deletion could not be verified");
        }
        helper_removed
    } else if state.graph_data {
        ctx_pro_lifecycle::state_markers::mark_data_preserved(&operation)?;
        ctx_pro_lifecycle::installation::remove_installation_artifacts(&operation)?
    } else {
        ctx_pro_lifecycle::state_markers::clear_data_preserved(&operation)?;
        ctx_pro_lifecycle::installation::remove_installation_artifacts(&operation)?
    };
    Ok(UninstallOutcome {
        helper_removed,
        local_pro_data: if state.graph_data {
            if delete_data {
                LocalProDataOutcome::Deleted
            } else {
                LocalProDataOutcome::Preserved
            }
        } else {
            LocalProDataOutcome::Absent
        },
    })
}

#[derive(Debug, Clone, Copy)]
struct LocalState {
    initialized: bool,
    cleanup_phase: bool,
    graph_data: bool,
    helper_files: bool,
    preserved_marker: bool,
    pending_materialization: bool,
    lifecycle_lock: bool,
}

impl LocalState {
    const fn data_artifact(self) -> bool {
        self.initialized
            || self.cleanup_phase
            || self.graph_data
            || self.helper_files
            || self.preserved_marker
            || self.pending_materialization
    }
}

fn inspect(data_root: &Path) -> Result<LocalState> {
    let layout = ProFilesystemLayout::new(data_root);
    Ok(LocalState {
        initialized: ctx_pro_lifecycle::deletion::local_pro_initialization_indicator_exists(
            data_root,
        )?,
        cleanup_phase: ctx_pro_lifecycle::deletion::local_pro_graph_key_cleanup_phase_exists(
            data_root,
        )?,
        graph_data: ctx_pro_lifecycle::deletion::local_pro_graph_data_exists(data_root)?,
        helper_files: ctx_pro_lifecycle::installed_artifact::installation_artifacts_present(
            data_root,
        ),
        preserved_marker: ctx_pro_lifecycle::state_markers::preserved_data_marker_present(
            data_root,
        )?,
        pending_materialization: ctx_pro_lifecycle::state_markers::materialization_pending(
            data_root,
        )?,
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
