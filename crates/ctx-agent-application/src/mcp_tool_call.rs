//! Agent-owned tool invocation and content-free delivery receipt construction.

use std::time::Instant;

use ctx_agent_integrations::tool_backend::{
    ToolBackendError, ToolExecutionError, ToolIntegrationReceipt, ToolOperation, ToolOutcome,
    ToolTransportFacts, ToolUsageFacts,
};
use serde_json::json;

use crate::tool_backend::{
    ExtensionBlameOutcome, ExtensionStatusOutcome, ExtensionToolPort, HistoryReadOutcome,
    HistoryReadPort, SearchReadOutcome, SearchReadinessPort, SourceCatalog, SourceCatalogPort,
};

/// Invokes one parsed MCP tool operation through coarse host ports. Each branch
/// performs at most one call to the owning operation port.
pub fn invoke_mcp_tool_call<H, R, S, E>(
    operation: ToolOperation,
    history: &H,
    search: &R,
    sources: &S,
    extensions: &E,
) -> Result<ToolOutcome, ToolExecutionError>
where
    H: HistoryReadPort,
    R: SearchReadinessPort,
    S: SourceCatalogPort,
    E: ExtensionToolPort,
{
    let invocation_usage = operation.invocation_usage();
    execute(operation, history, search, sources, extensions).map_err(|mut failure| {
        failure.usage.merge(invocation_usage);
        failure
    })
}

fn execute<H, R, S, E>(
    operation: ToolOperation,
    history: &H,
    search: &R,
    sources: &S,
    extensions: &E,
) -> Result<ToolOutcome, ToolExecutionError>
where
    H: HistoryReadPort,
    R: SearchReadinessPort,
    S: SourceCatalogPort,
    E: ExtensionToolPort,
{
    match operation {
        ToolOperation::Status => history.status().map(ToolOutcome::plain).map_err(Into::into),
        ToolOperation::Sources => sources
            .source_catalog()
            .map(source_catalog_outcome)
            .map_err(Into::into),
        ToolOperation::Search(request) => search
            .search_ready(request)
            .map(search_outcome)
            .map_err(Into::into),
        ToolOperation::ShowSession(request) => history
            .show_session(request)
            .map(history_outcome)
            .map_err(Into::into),
        ToolOperation::ShowEvent(request) => history
            .show_event(request)
            .map(history_outcome)
            .map_err(Into::into),
        ToolOperation::QueryEvents(request) => history
            .query_events(request)
            .map(ToolOutcome::plain)
            .map_err(Into::into),
        ToolOperation::ProStatus => Ok(pro_status_outcome(extensions)),
        ToolOperation::Blame(request) => blame_outcome(request, extensions),
    }
}

fn source_catalog_outcome(catalog: SourceCatalog) -> ToolOutcome {
    ToolOutcome::plain(json!({
        "schema_version": 1,
        "sources": catalog.sources,
        "issues": catalog.issues,
        "issues_truncated": catalog.issues_truncated,
        "read_only": true,
    }))
}

fn search_outcome(result: SearchReadOutcome) -> ToolOutcome {
    ToolOutcome {
        structured: result.structured,
        compact: Some(result.compact),
        usage: ToolUsageFacts {
            search: Some(result.usage),
            blame_target: None,
        },
        integration_receipt: None,
    }
}

fn history_outcome(result: HistoryReadOutcome) -> ToolOutcome {
    ToolOutcome::with_compact(result.structured, result.compact)
}

fn pro_status_outcome(extensions: &impl ExtensionToolPort) -> ToolOutcome {
    let started = Instant::now();
    let ExtensionStatusOutcome {
        structured,
        access_state,
        helper_connected,
        error_code,
    } = extensions.pro_status();
    let success = error_code.is_none();
    ToolOutcome {
        structured,
        compact: None,
        usage: ToolUsageFacts::default(),
        integration_receipt: Some(ToolIntegrationReceipt {
            facts: ToolTransportFacts::ProStatus {
                access_state,
                helper_connected,
                error_code,
            },
            success,
            duration: started.elapsed(),
        }),
    }
}

fn blame_outcome(
    request: ctx_agent_integrations::tool_backend::BlameRequest,
    extensions: &impl ExtensionToolPort,
) -> Result<ToolOutcome, ToolExecutionError> {
    let started = Instant::now();
    let target = request.target.kind();
    match extensions.blame(request) {
        Ok(ExtensionBlameOutcome {
            structured,
            result_count,
            has_more,
        }) => Ok(ToolOutcome {
            structured,
            compact: None,
            usage: ToolUsageFacts::default(),
            integration_receipt: Some(ToolIntegrationReceipt {
                facts: ToolTransportFacts::Blame {
                    target: Some(target),
                    result_count: Some(result_count),
                    has_more: Some(has_more),
                    failure_code: None,
                },
                success: true,
                duration: started.elapsed(),
            }),
        }),
        Err(error) => {
            let failure_code = match &error {
                ToolBackendError::Pro { code, .. } => Some(*code),
                _ => None,
            };
            Err(ToolExecutionError {
                error,
                usage: ToolUsageFacts::default(),
                integration_receipt: Some(Box::new(ToolIntegrationReceipt {
                    facts: ToolTransportFacts::Blame {
                        target: Some(target),
                        result_count: None,
                        has_more: None,
                        failure_code,
                    },
                    success: false,
                    duration: started.elapsed(),
                })),
            })
        }
    }
}

#[cfg(test)]
mod tests;
