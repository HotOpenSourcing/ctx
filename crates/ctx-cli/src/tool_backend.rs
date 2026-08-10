use std::{fmt, path::PathBuf, time::Duration};

use ctx_history_core::CaptureProvider;
use ctx_history_index::{CoreEventRangeDirection, CoreEventRangeScope, SearchContentScope};
use serde_json::Value;
use uuid::Uuid;

use crate::analytics::ProHostOperationV1;

mod application;

pub(crate) use application::LocalToolBackend;

/// One transport-neutral application operation exposed through the MCP adapter.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ToolOperation {
    Status,
    Sources,
    Search(ToolSearchRequest),
    ShowSession(ShowSessionRequest),
    ShowEvent(ShowEventRequest),
    QueryEvents(QueryEventsRequest),
    ProStatus,
    Blame(BlameRequest),
}

impl ToolOperation {
    pub(crate) fn invocation_usage(&self) -> ToolUsageFacts {
        ToolUsageFacts {
            search: None,
            blame_target: match self {
                Self::Blame(request) => Some(request.target.kind()),
                Self::Status
                | Self::Sources
                | Self::Search(_)
                | Self::ShowSession(_)
                | Self::ShowEvent(_)
                | Self::QueryEvents(_)
                | Self::ProStatus => None,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ToolSearchRequest {
    pub(crate) query: String,
    pub(crate) limit: usize,
    pub(crate) provider: Option<CaptureProvider>,
    pub(crate) history_source: Option<String>,
    pub(crate) provider_key: Option<String>,
    pub(crate) source_id: Option<String>,
    pub(crate) source_format: Option<String>,
    pub(crate) workspace: Option<String>,
    pub(crate) since: Option<String>,
    pub(crate) primary_only: bool,
    pub(crate) include_subagents: bool,
    pub(crate) content_scope: SearchContentScope,
    pub(crate) event_type: Option<String>,
    pub(crate) file: Option<PathBuf>,
    pub(crate) session: Option<String>,
    pub(crate) events: bool,
    pub(crate) include_current_session: bool,
    pub(crate) backend: Option<ToolSearchBackend>,
    pub(crate) semantic_weight: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolSearchBackend {
    Lexical,
    Semantic,
    Hybrid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShowSessionRequest {
    pub(crate) selector: String,
    pub(crate) mode: ToolTranscriptMode,
    pub(crate) limit: usize,
    pub(crate) cursor: Option<String>,
    pub(crate) output_limit_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolTranscriptMode {
    Full,
    Lite,
    Log,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShowEventRequest {
    pub(crate) selector: String,
    pub(crate) before: usize,
    pub(crate) after: usize,
    pub(crate) window: Option<usize>,
    pub(crate) output_limit_bytes: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct QueryEventsRequest {
    pub(crate) since: Option<String>,
    pub(crate) until: Option<String>,
    pub(crate) filters: QueryEventFilters,
    pub(crate) cursor: Option<String>,
    pub(crate) content: ToolEventContent,
    pub(crate) limit: u64,
    pub(crate) output_limit_bytes: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct QueryEventFilters {
    pub(crate) providers: Vec<String>,
    pub(crate) source_identity: Option<Uuid>,
    pub(crate) history_source: Option<String>,
    pub(crate) provider_key: Option<String>,
    pub(crate) source_id: Option<String>,
    pub(crate) source_format: Option<String>,
    pub(crate) provider_session_id: Option<String>,
    pub(crate) session_id: Option<Uuid>,
    pub(crate) parent_session_id: Option<Uuid>,
    pub(crate) root_session_id: Option<Uuid>,
    pub(crate) branch: Option<String>,
    pub(crate) workspace: Option<String>,
    pub(crate) event_type: Option<String>,
    pub(crate) role: Option<String>,
    pub(crate) agent_type: Option<String>,
    pub(crate) scope: CoreEventRangeScope,
    pub(crate) file: Option<String>,
    pub(crate) direction: CoreEventRangeDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolEventContent {
    Full,
    Text,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlameRequest {
    pub(crate) target: ToolBlameTarget,
    pub(crate) limit: usize,
    pub(crate) cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ToolBlameTarget {
    File {
        path: String,
        repository: Option<String>,
        lines: Option<ToolLineRange>,
    },
    Commit {
        oid: String,
        repository: Option<String>,
    },
    PullRequest {
        selector: String,
        repository: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ToolLineRange {
    pub(crate) start: u32,
    pub(crate) end: u32,
}

#[derive(Debug)]
pub(crate) struct ToolOutcome {
    pub(crate) structured: Value,
    /// Optional projection used only by the MCP adapter to render compact text.
    pub(crate) compact: Option<Value>,
    pub(crate) usage: ToolUsageFacts,
    pub(crate) product_observation: Option<ToolProductObservation>,
}

impl ToolOutcome {
    pub(crate) fn plain(structured: Value) -> Self {
        Self {
            structured,
            compact: None,
            usage: ToolUsageFacts::default(),
            product_observation: None,
        }
    }

    pub(crate) fn with_compact(structured: Value, compact: Value) -> Self {
        Self {
            structured,
            compact: Some(compact),
            usage: ToolUsageFacts::default(),
            product_observation: None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ToolProductObservation {
    pub(crate) operation: ProHostOperationV1,
    pub(crate) success: bool,
    pub(crate) duration: Duration,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ToolUsageFacts {
    pub(crate) search: Option<ToolSearchUsageFacts>,
    pub(crate) blame_target: Option<ToolBlameTargetKind>,
}

impl ToolUsageFacts {
    pub(crate) const fn for_blame(target: ToolBlameTargetKind) -> Self {
        Self {
            search: None,
            blame_target: Some(target),
        }
    }

    pub(crate) fn merge(&mut self, additional: Self) {
        if additional.search.is_some() {
            self.search = additional.search;
        }
        if additional.blame_target.is_some() {
            self.blame_target = additional.blame_target;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ToolSearchUsageFacts {
    pub(crate) context_complete: bool,
    pub(crate) delivered_context_bytes: u64,
    pub(crate) matched_normalized_session_bytes: u64,
}

impl ToolSearchUsageFacts {
    pub(crate) const fn complete(
        delivered_context_bytes: u64,
        matched_normalized_session_bytes: u64,
    ) -> Self {
        Self {
            context_complete: true,
            delivered_context_bytes,
            matched_normalized_session_bytes,
        }
    }

    pub(crate) const fn unavailable() -> Self {
        Self {
            context_complete: false,
            delivered_context_bytes: 0,
            matched_normalized_session_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolBlameTargetKind {
    File,
    Commit,
    PullRequest,
}

impl ToolBlameTarget {
    pub(crate) const fn kind(&self) -> ToolBlameTargetKind {
        match self {
            Self::File { .. } => ToolBlameTargetKind::File,
            Self::Commit { .. } => ToolBlameTargetKind::Commit,
            Self::PullRequest { .. } => ToolBlameTargetKind::PullRequest,
        }
    }
}

/// Coarse application boundary. Production callers use static dispatch.
pub(crate) trait ToolBackend: Send + Sync {
    fn execute(&self, operation: ToolOperation) -> Result<ToolOutcome, ToolExecutionError>;
}

#[derive(Debug)]
pub(crate) struct ToolExecutionError {
    pub(crate) error: ToolBackendError,
    pub(crate) usage: ToolUsageFacts,
    pub(crate) product_observation: Option<ToolProductObservation>,
}

impl From<ToolBackendError> for ToolExecutionError {
    fn from(error: ToolBackendError) -> Self {
        Self {
            error,
            usage: ToolUsageFacts::default(),
            product_observation: None,
        }
    }
}

#[derive(Debug)]
pub(crate) enum ToolBackendError {
    InvalidRequest {
        detail: String,
    },
    EventQuery(crate::commands::list::events::EventQueryError),
    GenerationChanged,
    GenerationAuthority(ctx_history_refresh::GenerationQueryAuthorityError),
    Cursor {
        kind: CursorFailureKind,
        detail: String,
    },
    OutputLimit {
        event_id: Uuid,
        actual_bytes: usize,
        maximum_bytes: usize,
    },
    SemanticNotReady {
        code: &'static str,
        detail: String,
        retryable: bool,
    },
    Pro {
        code: &'static str,
        diagnostic: String,
        structured: Value,
    },
    Internal {
        detail: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CursorFailureKind {
    Stale,
    Mismatch,
    Invalid,
}

impl ToolBackendError {
    pub(crate) fn invalid_request(detail: impl Into<String>) -> Self {
        Self::InvalidRequest {
            detail: detail.into(),
        }
    }

    pub(crate) fn internal(detail: impl Into<String>) -> Self {
        Self::Internal {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for ToolBackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest { detail }
            | Self::Cursor { detail, .. }
            | Self::Internal { detail } => formatter.write_str(detail),
            Self::EventQuery(error) => fmt::Display::fmt(error, formatter),
            Self::GenerationAuthority(error) => fmt::Display::fmt(error, formatter),
            Self::GenerationChanged => formatter.write_str(
                "History changed while ctx was opening the searchable generation. Retry the same request.",
            ),
            Self::OutputLimit {
                event_id,
                actual_bytes,
                maximum_bytes,
            } => write!(
                formatter,
                "Core content output for ctx event {event_id} requires {actual_bytes} bytes; the presentation limit is {maximum_bytes} bytes"
            ),
            Self::SemanticNotReady { code, detail, .. } => write!(
                formatter,
                "source-backed semantic search is not ready ({code}): {detail}"
            ),
            Self::Pro { diagnostic, .. } => formatter.write_str(diagnostic),
        }
    }
}

impl std::error::Error for ToolBackendError {}
