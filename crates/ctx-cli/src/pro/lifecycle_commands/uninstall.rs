use std::path::Path;

use anyhow::Result;
use serde_json::Value;

use super::{LocalProDataOutcome, ProDeletionService, UninstallDataDisposition};
use crate::{pro::client, ui::Ui};

/// CLI output adapter for the headless local-uninstall operation.
pub(super) fn run_uninstall(
    data_root: &Path,
    service: Option<&mut dyn ProDeletionService>,
    disposition: UninstallDataDisposition,
    json_output: bool,
    ui: &mut Ui,
) -> Result<Value> {
    let outcome = client::uninstall(
        data_root,
        service,
        match disposition {
            UninstallDataDisposition::Delete => {
                ctx_pro_application::UninstallDataDisposition::Delete
            }
            UninstallDataDisposition::Keep => ctx_pro_application::UninstallDataDisposition::Keep,
        },
    )?;
    let data_outcome = match outcome.local_pro_data {
        ctx_pro_application::LocalProDataOutcome::Absent => LocalProDataOutcome::Absent,
        ctx_pro_application::LocalProDataOutcome::Deleted => LocalProDataOutcome::Deleted,
        ctx_pro_application::LocalProDataOutcome::Preserved => LocalProDataOutcome::Preserved,
    };
    emit_uninstall_result(outcome.helper_removed, data_outcome, json_output, ui)
}

fn emit_uninstall_result(
    helper_removed: bool,
    data_outcome: LocalProDataOutcome,
    json_output: bool,
    ui: &mut Ui,
) -> Result<Value> {
    let value = uninstall_payload(helper_removed, data_outcome);
    if json_output {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        let document = super::render::uninstall(ui.stdout_context(), helper_removed, data_outcome);
        ui.write_stdout(&document)?;
    }
    Ok(value)
}

pub(super) fn uninstall_payload(helper_removed: bool, data_outcome: LocalProDataOutcome) -> Value {
    ctx_pro_application::UninstallOutcome {
        helper_removed,
        local_pro_data: match data_outcome {
            LocalProDataOutcome::Absent => ctx_pro_application::LocalProDataOutcome::Absent,
            LocalProDataOutcome::Deleted => ctx_pro_application::LocalProDataOutcome::Deleted,
            LocalProDataOutcome::Preserved => ctx_pro_application::LocalProDataOutcome::Preserved,
        },
    }
    .json()
}

pub(super) fn preserved_data_marker_is_set(data_root: &Path) -> bool {
    ctx_pro_lifecycle::state_markers::preserved_data_marker_is_set(data_root)
}
