//! Coarse host ports for agent-facing workspace, session, and context tools.

use ctx_agent_integrations::tool_backend::{
    BlameRequest, QueryEventsRequest, ShowEventRequest, ShowSessionRequest, ToolBackendError,
    ToolSearchRequest, ToolSearchUsageFacts,
};
use serde_json::Value;

/// One already-assembled history response and its compact MCP projection.
#[derive(Debug)]
pub struct HistoryReadOutcome {
    pub structured: Value,
    pub compact: Value,
}

/// One already-executed search and its bounded usage accounting.
#[derive(Debug)]
pub struct SearchReadOutcome {
    pub structured: Value,
    pub compact: Value,
    pub usage: ToolSearchUsageFacts,
}

/// Provider and extension source inventory before wire-response assembly.
#[derive(Debug)]
pub struct SourceCatalog {
    pub sources: Vec<Value>,
    pub issues: Vec<Value>,
    pub issues_truncated: bool,
}

/// Content-free facts required to build a Pro status delivery receipt.
#[derive(Debug)]
pub struct ExtensionStatusOutcome {
    pub structured: Value,
    pub access_state: Option<String>,
    pub helper_connected: bool,
    pub error_code: Option<String>,
}

/// Content-free facts required to build a blame delivery receipt.
#[derive(Debug)]
pub struct ExtensionBlameOutcome {
    pub structured: Value,
    pub result_count: usize,
    pub has_more: bool,
}

/// One call per history operation or page. Implementations own concrete index,
/// query, cursor, generation-pinning, and status read-model access.
pub trait HistoryReadPort: Send + Sync {
    fn status(&self) -> Result<Value, ToolBackendError>;

    fn show_session(
        &self,
        request: ShowSessionRequest,
    ) -> Result<HistoryReadOutcome, ToolBackendError>;

    fn show_event(&self, request: ShowEventRequest)
        -> Result<HistoryReadOutcome, ToolBackendError>;

    fn query_events(&self, request: QueryEventsRequest) -> Result<Value, ToolBackendError>;
}

/// One call per search. Readiness and the pinned query intentionally share this
/// port so the host can use one configuration snapshot and at most one daemon
/// recovery attempt without storing opaque host state in the application.
pub trait SearchReadinessPort: Send + Sync {
    fn search_ready(
        &self,
        request: ToolSearchRequest,
    ) -> Result<SearchReadOutcome, ToolBackendError>;
}

/// One call for the complete source catalog, never one call per source.
pub trait SourceCatalogPort: Send + Sync {
    fn source_catalog(&self) -> Result<SourceCatalog, ToolBackendError>;
}

/// One call per optional product extension operation. Concrete Pro protocol,
/// lifecycle, hydration, and error rendering stay in the host implementation.
pub trait ExtensionToolPort: Send + Sync {
    fn pro_status(&self) -> ExtensionStatusOutcome;

    fn blame(&self, request: BlameRequest) -> Result<ExtensionBlameOutcome, ToolBackendError>;
}
