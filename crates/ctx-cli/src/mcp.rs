use std::{io, path::PathBuf};

use anyhow::Result;
use clap::{Args, Subcommand};
use ctx_agent_application::mcp::{
    serve_stdio as serve_mcp_stdio, McpTelemetry, McpUsagePort, ProductIdentity,
};
use ctx_agent_integrations::{mcp::McpToolKind, tool_backend::ToolUsageFacts};
use ctx_client_observability::local_usage::{McpInvocation, McpUsageRecorder};
use serde_json::Value;

#[cfg(test)]
use {
    ctx_agent_integrations::mcp::{
        handle_protocol_message, McpHandled, McpServerIdentity, McpUsage, RequestDescriptor,
    },
    serde_json::json,
    std::path::Path,
};

pub(crate) mod text;

use super::config;
use crate::{
    analytics::PublicEventV1, operation_descriptor::observed_mcp_product_operation,
    tool_backend::LocalToolBackend,
};

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
    let mut control =
        crate::observability_composition::LocalUsageControlAuthority::new(data_root.clone());
    let recorder = McpUsageRecorder::start(
        crate::observability_composition::local_usage_storage_authority(&data_root),
        move || control.snapshot(),
    );
    let mut usage = LocalUsagePort { recorder };
    let backend = LocalToolBackend::new(data_root.clone());
    let telemetry = product_telemetry(data_root);
    serve_mcp_stdio(
        &mut stdin,
        &mut stdout,
        ProductIdentity {
            name: "ctx",
            version: env!("CARGO_PKG_VERSION"),
        },
        &backend,
        &text::render_tool_text,
        &mut usage,
        telemetry,
    )
    .map_err(|failure| failure.into_error())
}

struct LocalUsagePort {
    recorder: McpUsageRecorder,
}

impl McpUsagePort for LocalUsagePort {
    fn record_delivered(
        &mut self,
        operation: McpToolKind,
        usage: ToolUsageFacts,
        response: &Value,
        encoded_response_bytes: usize,
        duration: std::time::Duration,
    ) {
        let Some(operation) = observed_mcp_product_operation(operation) else {
            return;
        };
        let mut invocation = McpInvocation::from_operation(operation);
        invocation.bind_tool_usage(crate::observability_product::mcp_tool_usage(usage));
        // Usage-v2 owns bounded, process-local search-to-show correlation inside
        // this delivery boundary; MCP never sends target IDs to storage or logs.
        self.recorder.record_delivered(invocation, duration, || {
            crate::observability_product::mcp_completion_facts(
                operation,
                response,
                encoded_response_bytes,
            )
        });
    }
}

fn product_telemetry(data_root: PathBuf) -> McpTelemetry {
    let enabled = config::AppConfig::load(&data_root).is_ok_and(|config| config.analytics.enabled);
    McpTelemetry::start(enabled, move |events: &[PublicEventV1]| {
        let Ok(config) = config::AppConfig::load(&data_root) else {
            return Ok(());
        };
        if !config.analytics.enabled {
            return Ok(());
        }
        crate::analytics::send_batch(&data_root, &config, events);
        Ok(())
    })
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
        McpServerIdentity {
            name: "ctx",
            version: env!("CARGO_PKG_VERSION"),
        },
        &backend,
        text::render_tool_text,
    );
    let invocation = handled.usage.clone().and_then(usage_invocation);
    (handled, invocation)
}

#[cfg(test)]
fn usage_invocation(usage: McpUsage) -> Option<McpInvocation> {
    let operation = observed_mcp_product_operation(usage.operation)?;
    let mut invocation = McpInvocation::from_operation(operation);
    invocation.bind_tool_usage(crate::observability_product::mcp_tool_usage(usage.facts));
    Some(invocation)
}

#[cfg(test)]
pub(crate) fn query_events_for_test(arguments: &Value, data_root: &Path) -> Result<Value> {
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": McpToolKind::QueryEvents.tool_name(),
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
