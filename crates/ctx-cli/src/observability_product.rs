//! Product and presentation mappings retained in the CLI composition root.

use std::collections::BTreeSet;

use ctx_client_observability::{
    analytics::{
        ImportSourceMode, ImportTelemetry, ProBlameTargetV1, ProgressMode, RenderFormat,
        TranscriptModeKind,
    },
    local_usage::{
        McpCompletionFacts, McpContextTarget, McpCorrelationFact, McpToolUsageFacts, ProOutcome,
        SearchContextObservation, TargetType,
    },
};
use ctx_pro_host_protocol::{BlameAttribution, BlameResult, BlameTarget};
use serde_json::Value;

pub(crate) const fn progress_mode(value: crate::progress::ProgressArg) -> ProgressMode {
    match value {
        crate::progress::ProgressArg::Auto => ProgressMode::Auto,
        crate::progress::ProgressArg::Plain => ProgressMode::Plain,
        crate::progress::ProgressArg::Json => ProgressMode::Json,
        crate::progress::ProgressArg::None => ProgressMode::None,
    }
}

pub(crate) fn import_telemetry(args: &crate::ImportArgs) -> ImportTelemetry {
    ImportTelemetry {
        resume: args.resume,
        all_sources: args.all,
        no_daemon: args.no_daemon,
        source_mode: if args.input_format.is_some() {
            ImportSourceMode::ExplicitFormat
        } else if args.history_source.is_some() || !args.history_source_manifest.is_empty() {
            ImportSourceMode::HistorySourcePlugin
        } else if args.path.is_some() {
            ImportSourceMode::ExplicitPath
        } else if args.all {
            ImportSourceMode::AllDiscovered
        } else if args.provider.is_some() {
            ImportSourceMode::DiscoveredProvider
        } else {
            ImportSourceMode::AutoDiscovered
        },
        provider_filter: args.provider.map(|provider| provider.capture_provider()),
        reset_cursor: args.reset_cursor,
        progress_mode: progress_mode(args.progress),
        sources_seen: None,
        source_bytes: None,
        source_files: None,
        failed_sources: None,
        sessions_imported: None,
        events_imported: None,
        edges_imported: None,
        skipped: None,
        rejected_records: None,
        outcome: None,
        failure_scope: None,
        failure_type: None,
    }
}

pub(crate) fn setup_import_telemetry(
    progress: crate::progress::ProgressArg,
    no_daemon: bool,
) -> ImportTelemetry {
    ImportTelemetry {
        resume: false,
        all_sources: true,
        no_daemon,
        source_mode: ImportSourceMode::AllDiscovered,
        provider_filter: None,
        reset_cursor: false,
        progress_mode: progress_mode(progress),
        sources_seen: None,
        source_bytes: None,
        source_files: None,
        failed_sources: None,
        sessions_imported: None,
        events_imported: None,
        edges_imported: None,
        skipped: None,
        rejected_records: None,
        outcome: None,
        failure_scope: None,
        failure_type: None,
    }
}

pub(crate) const fn render_format(value: crate::output::OutputFormat) -> RenderFormat {
    match value {
        crate::output::OutputFormat::Text => RenderFormat::Text,
        crate::output::OutputFormat::Json => RenderFormat::Json,
        crate::output::OutputFormat::Jsonl => RenderFormat::Jsonl,
        crate::output::OutputFormat::Markdown => RenderFormat::Markdown,
    }
}

pub(crate) const fn json_render_format(value: crate::output::JsonOutputFormat) -> RenderFormat {
    match value {
        crate::output::JsonOutputFormat::Text => RenderFormat::Text,
        crate::output::JsonOutputFormat::Json => RenderFormat::Json,
    }
}

pub(crate) const fn transcript_mode(
    value: crate::transcript::TranscriptMode,
) -> TranscriptModeKind {
    match value {
        crate::transcript::TranscriptMode::Lite => TranscriptModeKind::Lite,
        crate::transcript::TranscriptMode::Full => TranscriptModeKind::Full,
        crate::transcript::TranscriptMode::Log => TranscriptModeKind::Log,
    }
}

pub(crate) const fn blame_analytics_target(target: &BlameTarget) -> ProBlameTargetV1 {
    match target {
        BlameTarget::File { .. } => ProBlameTargetV1::File,
        BlameTarget::Commit { .. } => ProBlameTargetV1::Commit,
        BlameTarget::PullRequest { .. } => ProBlameTargetV1::PullRequest,
    }
}

pub(crate) const fn blame_usage_target(target: &BlameTarget) -> TargetType {
    match target {
        BlameTarget::File { .. } => TargetType::File,
        BlameTarget::Commit { .. } => TargetType::Commit,
        BlameTarget::PullRequest { .. } => TargetType::PullRequest,
    }
}

const fn blame_usage_outcome(attribution: BlameAttribution) -> ProOutcome {
    match attribution {
        BlameAttribution::Proven => ProOutcome::Produced,
        BlameAttribution::Possible | BlameAttribution::Conflicting => ProOutcome::Possible,
        BlameAttribution::None => ProOutcome::None,
    }
}

pub(crate) fn blame_usage(result: &BlameResult) -> (usize, usize, ProOutcome) {
    let citations = result
        .evidence
        .iter()
        .map(|evidence| evidence.number)
        .collect::<BTreeSet<_>>()
        .len();
    let outcome = blame_usage_outcome(result.outcome.attribution);
    (result.matches.len(), citations, outcome)
}

pub(crate) fn mcp_tool_usage(usage: crate::tool_backend::ToolUsageFacts) -> McpToolUsageFacts {
    let search_context = usage.search.map(|search| {
        if search.context_complete {
            SearchContextObservation::complete(
                usize::try_from(search.delivered_context_bytes).unwrap_or(usize::MAX),
                usize::try_from(search.matched_normalized_session_bytes).unwrap_or(usize::MAX),
            )
            .unwrap_or_else(SearchContextObservation::unavailable)
        } else {
            SearchContextObservation::unavailable()
        }
    });
    let blame_target = usage.blame_target.map(|target| match target {
        crate::tool_backend::ToolBlameTargetKind::File => TargetType::File,
        crate::tool_backend::ToolBlameTargetKind::Commit => TargetType::Commit,
        crate::tool_backend::ToolBlameTargetKind::PullRequest => TargetType::PullRequest,
    });
    McpToolUsageFacts {
        search_context,
        blame_target,
    }
}

pub(crate) fn mcp_completion_facts(
    operation: crate::operation_descriptor::ObservedMcpProductOperation,
    response: &Value,
    delivered_output_bytes: usize,
) -> McpCompletionFacts {
    let failed = response.get("error").is_some()
        || response.pointer("/result/isError").and_then(Value::as_bool) == Some(true);
    let structured = response.pointer("/result/structuredContent");
    let result_count = structured.and_then(|structured| {
        let field = match operation {
            crate::operation_descriptor::ObservedMcpProductOperation::Sources => "sources",
            crate::operation_descriptor::ObservedMcpProductOperation::Search => "results",
            crate::operation_descriptor::ObservedMcpProductOperation::ShowSession
            | crate::operation_descriptor::ObservedMcpProductOperation::ShowEvent
            | crate::operation_descriptor::ObservedMcpProductOperation::QueryEvents => "events",
            crate::operation_descriptor::ObservedMcpProductOperation::Blame => "matches",
            _ => return None,
        };
        structured
            .get(field)
            .and_then(Value::as_array)
            .map(Vec::len)
    });
    let citation_count = structured
        .and_then(|value| value.get("evidence"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.get("number").and_then(Value::as_u64))
                .collect::<BTreeSet<_>>()
                .len() as u64
        })
        .unwrap_or(0);
    let pro_outcome =
        (operation == crate::operation_descriptor::ObservedMcpProductOperation::Blame && !failed)
            .then(|| {
                match structured
                    .and_then(|value| value.pointer("/outcome/attribution"))
                    .and_then(Value::as_str)
                {
                    Some("proven") => ProOutcome::Produced,
                    Some("possible" | "conflicting") => ProOutcome::Possible,
                    Some("none") | None | Some(_) => ProOutcome::None,
                }
            });
    let mut correlation = Vec::new();
    if !failed {
        match operation {
            crate::operation_descriptor::ObservedMcpProductOperation::Search => {
                if let Some(results) = structured
                    .and_then(|value| value.get("results"))
                    .and_then(Value::as_array)
                {
                    for result in results {
                        let target = match (
                            result.get("result_scope").and_then(Value::as_str),
                            result.get("result_type").and_then(Value::as_str),
                        ) {
                            (Some("session"), Some("session_result")) => result
                                .get("ctx_session_id")
                                .and_then(Value::as_str)
                                .and_then(|id| uuid::Uuid::parse_str(id).ok())
                                .map(McpContextTarget::Session),
                            (Some("event"), Some("event")) => result
                                .get("ctx_event_id")
                                .and_then(Value::as_str)
                                .and_then(|id| uuid::Uuid::parse_str(id).ok())
                                .map(McpContextTarget::Event),
                            _ => None,
                        };
                        if let Some(target) = target {
                            correlation.push(McpCorrelationFact::Found(target));
                        }
                    }
                }
            }
            crate::operation_descriptor::ObservedMcpProductOperation::ShowSession => {
                if let Some(target) = structured
                    .and_then(|value| value.get("ctx_session_id"))
                    .and_then(Value::as_str)
                    .and_then(|id| uuid::Uuid::parse_str(id).ok())
                    .map(McpContextTarget::Session)
                {
                    correlation.push(McpCorrelationFact::Opened(target));
                }
            }
            crate::operation_descriptor::ObservedMcpProductOperation::ShowEvent
            | crate::operation_descriptor::ObservedMcpProductOperation::QueryEvents => {
                if let Some(target) = structured
                    .and_then(|value| value.get("ctx_event_id"))
                    .and_then(Value::as_str)
                    .and_then(|id| uuid::Uuid::parse_str(id).ok())
                    .map(McpContextTarget::Event)
                {
                    correlation.push(McpCorrelationFact::Opened(target));
                }
            }
            _ => {}
        }
    }
    McpCompletionFacts {
        failed,
        result_count,
        citation_count,
        pro_outcome,
        delivered_output_bytes,
        correlation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn blame_attribution_policy_matches_cli_and_mcp_adapters() {
        for (attribution, wire_attribution, expected) in [
            (BlameAttribution::Proven, "proven", ProOutcome::Produced),
            (BlameAttribution::Possible, "possible", ProOutcome::Possible),
            (
                BlameAttribution::Conflicting,
                "conflicting",
                ProOutcome::Possible,
            ),
            (BlameAttribution::None, "none", ProOutcome::None),
        ] {
            assert_eq!(blame_usage_outcome(attribution), expected);

            let response = json!({
                "result": {
                    "structuredContent": {
                        "outcome": {"attribution": wire_attribution},
                        "matches": []
                    }
                }
            });
            assert_eq!(
                mcp_completion_facts(
                    crate::operation_descriptor::ObservedMcpProductOperation::Blame,
                    &response,
                    0,
                )
                .pro_outcome,
                Some(expected),
            );
        }

        let missing_attribution = json!({
            "result": {"structuredContent": {"outcome": {}, "matches": []}}
        });
        assert_eq!(
            mcp_completion_facts(
                crate::operation_descriptor::ObservedMcpProductOperation::Blame,
                &missing_attribution,
                0,
            )
            .pro_outcome,
            Some(ProOutcome::None),
        );

        let failed = json!({"error": {"code": -32603, "message": "failed"}});
        assert_eq!(
            mcp_completion_facts(
                crate::operation_descriptor::ObservedMcpProductOperation::Blame,
                &failed,
                0,
            )
            .pro_outcome,
            None,
        );
    }
}
