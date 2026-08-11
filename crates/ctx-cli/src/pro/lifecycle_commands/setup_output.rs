use super::*;

pub(super) fn write_setup_result(
    data_root: &Path,
    account_state: &str,
    helper_updated: bool,
    report: &crate::pro::client::MaterializeReport,
    json_output: bool,
    ui: &mut Ui,
) -> Result<()> {
    let value = json!({
        "schema_version": 1,
        "payload_type": "pro_setup",
        "ok": true,
        "account_state": account_state,
        "helper_updated": helper_updated,
        "graph": report,
        "status": lifecycle_status_json(data_root),
    });
    if json_output {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        let document = render_setup_human(ui.stdout_context(), account_state);
        ui.write_stdout(&document)?;
    }
    Ok(())
}
