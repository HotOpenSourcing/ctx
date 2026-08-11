use std::path::Path;

use anyhow::Result;
use serde_json::json;

use super::lifecycle::lifecycle_status_json;
use crate::{
    pro::PRO_MONTHLY_PRICE_DISPLAY,
    ui::{
        fields, hint, outcome, section, Document, Field, Hint, Outcome as UiOutcome, OutcomeState,
        RenderContext, Ui,
    },
};

pub(super) fn write_deferred_setup_result(
    data_root: &Path,
    account_state: &str,
    helper_updated: bool,
    json_output: bool,
    ui: &mut Ui,
) -> Result<()> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&deferred_setup_payload(
                account_state,
                helper_updated,
                lifecycle_status_json(data_root),
            ))?
        );
    } else {
        let document = render_deferred_setup_human(ui.stdout_context(), account_state);
        ui.write_stdout(&document)?;
    }
    Ok(())
}

fn deferred_setup_payload(
    account_state: &str,
    helper_updated: bool,
    status: serde_json::Value,
) -> serde_json::Value {
    json!({
        "schema_version": 1,
        "payload_type": "pro_setup",
        "ok": true,
        "account_state": account_state,
        "helper_updated": helper_updated,
        "materialization_deferred": true,
        "status": status,
    })
}

fn render_deferred_setup_human(context: &RenderContext, account_state: &str) -> Document {
    let product = if account_state == "trial" {
        "Free ctx Pro trial"
    } else {
        PRO_MONTHLY_PRICE_DISPLAY
    };
    let access = match account_state {
        "trial" => "Trial active",
        "active" => "Active",
        "canceling_paid" => "Active; cancellation scheduled",
        _ => "Unavailable",
    };
    let mut document = outcome(
        context,
        UiOutcome {
            state: OutcomeState::Success,
            title: "ctx Pro access is ready",
            detail: Some("The local Pro graph is not ready yet."),
        },
    );
    document.push_blank();
    document.append(section(
        "Pro",
        fields(
            context,
            &[
                Field::new("Product", product),
                Field::new("Access", access),
                Field::new("Work graph", "Pending the initial Core import"),
            ],
        ),
    ));
    document.push_blank();
    document.append(hint(
        context,
        Hint {
            text: "Continue the initial Core import; Pro indexing will run with it.",
        },
        None,
    ));
    document
}

#[cfg(test)]
mod tests {
    use unicode_width::UnicodeWidthStr as _;

    use super::*;
    use crate::ui::{ColorMode, StreamKind, TestContext};

    #[test]
    fn deferred_setup_is_truthful_about_the_pending_graph() {
        let context = RenderContext::for_test(
            TestContext::tty(StreamKind::Stdout, 80).color(ColorMode::Never),
        );
        assert_eq!(
            render_deferred_setup_human(&context, "trial").render_plain(),
            "✓ ctx Pro access is ready\n\
             The local Pro graph is not ready yet.\n\n\
             Pro\n\
             Product     Free ctx Pro trial\n\
             Access      Trial active\n\
             Work graph  Pending the initial Core import\n\n\
             Hint: Continue the initial Core import; Pro indexing will run with it.\n"
        );
    }

    #[test]
    fn deferred_setup_fits_supported_widths_and_json_stays_ansi_free() {
        for width in [32, 48, 80, 120] {
            let context = RenderContext::for_test(
                TestContext::tty(StreamKind::Stdout, width).color(ColorMode::Never),
            );
            let rendered = render_deferred_setup_human(&context, "trial").render_plain();
            let maximum = context.content_width().unwrap_or(1);
            assert!(rendered.lines().all(|line| line.width() <= maximum));
        }

        let json = serde_json::to_string_pretty(&deferred_setup_payload(
            "trial",
            false,
            json!({"state": "catch_up_required"}),
        ))
        .unwrap();
        assert!(!json.contains('\u{1b}'));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).unwrap(),
            json!({
                "schema_version": 1,
                "payload_type": "pro_setup",
                "ok": true,
                "account_state": "trial",
                "helper_updated": false,
                "materialization_deferred": true,
                "status": {"state": "catch_up_required"},
            })
        );
    }
}
