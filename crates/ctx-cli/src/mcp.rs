use std::{
    io::{self, BufRead, Write},
    path::PathBuf,
    time::Instant,
};

use anyhow::Result;
use clap::{Args, Subcommand};
use ctx_agent_integrations::{
    mcp::{
        encode_response_line, error_response, handle_protocol_message, read_mcp_input_line,
        McpHandled, McpInputLine, McpServerIdentity, McpUsage, RequestDescriptor,
        MCP_MAX_LINE_BYTES,
    },
    tool_backend::{ToolBackend, ToolBlameTargetKind, ToolIntegrationReceipt, ToolTransportFacts},
};
use serde_json::{json, Value};

#[cfg(test)]
use std::path::Path;

mod telemetry;
pub(crate) mod text;

use telemetry::McpTelemetry;

use super::config;
use crate::{
    analytics::{
        pro_helper_connection_outcome, pro_operation_event, McpErrorClassV1, McpStopReasonV1,
        Outcome, ProAccessStateV1, ProBlameTargetV1, ProBlameTelemetryV1,
        ProHelperConnectionOutcomeV1, ProHostOperationV1, ProStatusTelemetryV1, ProSurfaceV1,
        PublicEventV1,
    },
    local_usage::{McpInvocation, McpUsageRecorder},
    operation_descriptor::observed_mcp_product_operation,
    tool_backend::LocalToolBackend,
};

#[cfg(test)]
mod tests;

#[derive(Debug, Args)]
pub(crate) struct McpArgs {
    #[command(subcommand)]
    command: McpCommand,
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    #[command(
        about = "Serve local ctx tools over stdio",
        long_about = "Serve local ctx tools over newline-delimited stdio JSON-RPC. Blame may perform bounded local catch-up that updates the canonical Core index, writes the encrypted derived Pro graph, and writes the projection acknowledgement. It never writes provider history or repositories. pro_status remains read-only.\n\nExample:\n  printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"client\",\"version\":\"0\"}}}' | ctx mcp serve"
    )]
    Serve(McpServeArgs),
}

#[derive(Debug, Args)]
struct McpServeArgs {}

pub(crate) fn run(args: McpArgs, data_root: PathBuf) -> Result<()> {
    match args.command {
        McpCommand::Serve(_) => serve_stdio(data_root),
    }
}

fn serve_stdio(data_root: PathBuf) -> Result<()> {
    let daemon_config = config::AppConfig::load(&data_root)?;
    if daemon_config.daemon.enabled
        && crate::semantic::daemon_autostart_suppression_reason().is_none()
    {
        let _ = crate::semantic::autostart_daemon_and_wait(
            &data_root,
            &daemon_config,
            crate::DaemonTriggerCommandArg::Search,
        );
    }
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdin = stdin.lock();
    let mut stdout = stdout.lock();
    let mut telemetry = McpTelemetry::start(data_root.clone());
    let mut control =
        crate::observability_composition::LocalUsageControlAuthority::new(data_root.clone());
    let mut usage_recorder = McpUsageRecorder::start(
        crate::observability_composition::local_usage_storage_authority(&data_root),
        move || control.snapshot(),
    );
    let backend = LocalToolBackend::new(data_root);
    let started = Instant::now();
    let mut initialized = false;

    let result = serve_stdio_loop_with_backend(
        &mut stdin,
        &mut stdout,
        &mut initialized,
        &mut telemetry,
        &mut usage_recorder,
        &backend,
    );
    let (reason, outcome) = match &result {
        Ok(()) => (McpStopReasonV1::Eof, Outcome::Success),
        Err(failure) => (failure.reason, Outcome::Failure),
    };
    telemetry.stop(reason, outcome, started.elapsed());
    result.map_err(|failure| failure.error)
}

struct McpServeFailure {
    reason: McpStopReasonV1,
    error: anyhow::Error,
}

fn serve_stdio_loop_with_backend<B: ToolBackend>(
    stdin: &mut impl BufRead,
    stdout: &mut impl Write,
    initialized: &mut bool,
    telemetry: &mut McpTelemetry,
    usage_recorder: &mut McpUsageRecorder,
    backend: &B,
) -> std::result::Result<(), McpServeFailure> {
    loop {
        let input = read_mcp_input_line(stdin).map_err(|error| McpServeFailure {
            reason: McpStopReasonV1::StdinReadError,
            error,
        })?;
        let Some(input) = input else {
            return Ok(());
        };
        let request_started = Instant::now();
        let (handled, descriptor) = match input {
            McpInputLine::Line(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match serde_json::from_str::<Value>(line) {
                    Ok(message) => {
                        let descriptor = RequestDescriptor::from_message(&message);
                        (
                            handle_protocol_message(
                                message,
                                descriptor,
                                initialized,
                                server_identity(),
                                backend,
                            ),
                            descriptor,
                        )
                    }
                    Err(error) => (
                        McpHandled::plain(Some(error_response(
                            Value::Null,
                            -32700,
                            "Parse error",
                            Some(json!({ "error": error.to_string() })),
                        ))),
                        RequestDescriptor::InvalidJson,
                    ),
                }
            }
            McpInputLine::InvalidUtf8 => (
                McpHandled::plain(Some(error_response(
                    Value::Null,
                    -32700,
                    "Parse error",
                    Some(json!({ "error": "MCP message is not valid UTF-8" })),
                ))),
                RequestDescriptor::InvalidUtf8,
            ),
            McpInputLine::TooLarge => (
                McpHandled::plain(Some(error_response(
                    Value::Null,
                    -32700,
                    "Parse error",
                    Some(json!({
                        "error": format!("MCP message exceeds max line bytes ({MCP_MAX_LINE_BYTES})")
                    })),
                ))),
                RequestDescriptor::LineTooLarge,
            ),
        };
        let McpHandled {
            value: response,
            integration_receipt,
            usage,
        } = handled;
        let usage_invocation = usage.and_then(usage_invocation);
        if let Some(response) = response {
            let encoded = encode_response_line(&response).map_err(|error| {
                telemetry.record_response_failure(
                    descriptor,
                    request_started.elapsed(),
                    McpErrorClassV1::ResponseSerialize,
                );
                McpServeFailure {
                    reason: McpStopReasonV1::ResponseSerializeError,
                    error: error.into(),
                }
            })?;
            stdout.write_all(encoded.as_bytes()).map_err(|error| {
                telemetry.record_response_failure(
                    descriptor,
                    request_started.elapsed(),
                    McpErrorClassV1::ResponseWrite,
                );
                McpServeFailure {
                    reason: McpStopReasonV1::StdoutWriteError,
                    error: error.into(),
                }
            })?;
            stdout.flush().map_err(|error| {
                telemetry.record_response_failure(
                    descriptor,
                    request_started.elapsed(),
                    McpErrorClassV1::ResponseFlush,
                );
                McpServeFailure {
                    reason: McpStopReasonV1::StdoutFlushError,
                    error: error.into(),
                }
            })?;
            let duration = request_started.elapsed();
            if let Some(invocation) = usage_invocation {
                let operation = match descriptor {
                    RequestDescriptor::ToolCall { operation } => {
                        observed_mcp_product_operation(operation)
                            .expect("usage receipts exist only for recognized MCP tools")
                    }
                    _ => unreachable!("usage receipts exist only for MCP tool calls"),
                };
                // Usage-v2 owns bounded, process-local search-to-show correlation inside
                // this delivery boundary; MCP never sends target IDs to storage or logs.
                usage_recorder.record_delivered(invocation, duration, || {
                    crate::observability_product::mcp_completion_facts(
                        operation,
                        &response,
                        encoded.len(),
                    )
                });
            }
            telemetry.record_delivered(descriptor, Some(&response), duration);
            if let Some(receipt) = integration_receipt {
                telemetry.submit_pro_event(integration_receipt_event(receipt));
            }
        } else {
            telemetry.record_delivered(descriptor, None, request_started.elapsed());
        }
    }
}

fn server_identity() -> McpServerIdentity<'static> {
    McpServerIdentity {
        name: "ctx",
        version: env!("CARGO_PKG_VERSION"),
    }
}

fn usage_invocation(usage: McpUsage) -> Option<McpInvocation> {
    let operation = observed_mcp_product_operation(usage.operation)?;
    let mut invocation = McpInvocation::from_operation(operation);
    invocation.bind_tool_usage(crate::observability_product::mcp_tool_usage(usage.facts));
    Some(invocation)
}

fn integration_receipt_event(receipt: ToolIntegrationReceipt) -> PublicEventV1 {
    let operation = match receipt.facts {
        ToolTransportFacts::ProStatus {
            access_state,
            helper_connected,
            error_code,
        } => {
            let mut telemetry = ProStatusTelemetryV1::new(ProSurfaceV1::Mcp);
            telemetry.access_state = access_state
                .as_deref()
                .and_then(ProAccessStateV1::from_safe_name);
            telemetry.helper_connection = if helper_connected {
                ProHelperConnectionOutcomeV1::Connected
            } else {
                pro_helper_connection_outcome(error_code.as_deref())
            };
            if error_code.is_some() {
                telemetry.fail(error_code.as_deref());
            }
            ProHostOperationV1::Status(telemetry)
        }
        ToolTransportFacts::Blame {
            target,
            result_count,
            has_more,
            failure_code,
        } => {
            let target = target.map(|target| match target {
                ToolBlameTargetKind::File => ProBlameTargetV1::File,
                ToolBlameTargetKind::Commit => ProBlameTargetV1::Commit,
                ToolBlameTargetKind::PullRequest => ProBlameTargetV1::PullRequest,
            });
            let mut telemetry = ProBlameTelemetryV1::new(target, ProSurfaceV1::Mcp);
            if receipt.success {
                telemetry.complete(result_count.unwrap_or(0), has_more.unwrap_or(false));
            } else {
                telemetry.fail(failure_code);
            }
            ProHostOperationV1::Blame(telemetry)
        }
    };
    pro_operation_event(
        operation,
        if receipt.success {
            Outcome::Success
        } else {
            Outcome::Failure
        },
        receipt.duration,
    )
}

#[cfg(test)]
fn handle_message(
    message: Value,
    data_root: &Path,
    initialized: &mut bool,
) -> (McpHandled<Option<Value>>, Option<McpInvocation>) {
    let backend = LocalToolBackend::new(data_root.to_path_buf());
    let descriptor = RequestDescriptor::from_message(&message);
    let handled = handle_protocol_message(
        message,
        descriptor,
        initialized,
        server_identity(),
        &backend,
    );
    let invocation = handled.usage.clone().and_then(usage_invocation);
    (handled, invocation)
}

#[cfg(test)]
pub(crate) fn query_events_for_test(arguments: &Value, data_root: &Path) -> Result<Value> {
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": ctx_agent_integrations::mcp::McpToolKind::QueryEvents.tool_name(),
            "arguments": arguments,
        },
    });
    let (handled, _) = handle_message(request, data_root, &mut true);
    let result = handled
        .value
        .and_then(|response| response.get("result").cloned())
        .ok_or_else(|| anyhow::anyhow!("MCP query_events returned no result"))?;
    let structured = result
        .get("structuredContent")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("MCP query_events returned no structured content"))?;
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        return Err(anyhow::anyhow!(serde_json::to_string(&structured)?));
    }
    Ok(structured)
}

#[cfg(test)]
pub(crate) fn render_tool_text_for_test(value: &Value) -> String {
    text::render_tool_text(value)
}
