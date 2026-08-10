use std::{path::PathBuf, time::Instant};

use ctx_history_core::MAX_CORE_CONTENT_BYTES;
use ctx_history_index::{CoreEventPageBudget, CoreEventRangeFilters};
use ctx_pro_host_protocol::{BlameTarget, LineRange};
use serde_json::{json, Value};

use super::{
    BlameRequest, CursorFailureKind, QueryEventsRequest, ShowEventRequest, ShowSessionRequest,
    ToolBackend, ToolBackendError, ToolBlameTarget, ToolEventContent, ToolExecutionError,
    ToolOperation, ToolOutcome, ToolProductObservation, ToolSearchBackend, ToolSearchRequest,
    ToolSearchUsageFacts, ToolTranscriptMode, ToolUsageFacts,
};
use crate::{
    analytics::{
        pro_failure_bucket, pro_helper_connection_outcome, ProAccessStateV1, ProBlameTargetV1,
        ProBlameTelemetryV1, ProFailureBucketV1, ProHelperConnectionOutcomeV1, ProHostOperationV1,
        ProStatusTelemetryV1, ProSurfaceV1,
    },
    commands::list::events::{
        decode_cursor, event_range_page_value, mcp_event_query_core_record_bytes, selection,
        validated_limit, EventContentProjection, EventQueryError, EventQueryWireRequest,
    },
    config,
    observability_composition::{local_usage_storage_authority, usage_control_snapshot},
};

#[derive(Debug, Clone)]
pub(crate) struct LocalToolBackend {
    data_root: PathBuf,
}

impl LocalToolBackend {
    pub(crate) fn new(data_root: PathBuf) -> Self {
        Self { data_root }
    }

    fn execute_inner(&self, operation: ToolOperation) -> Result<ToolOutcome, ToolExecutionError> {
        match operation {
            ToolOperation::Status => self.status().map_err(Into::into),
            ToolOperation::Sources => self.sources().map_err(Into::into),
            ToolOperation::Search(request) => self.search(request).map_err(Into::into),
            ToolOperation::ShowSession(request) => self.show_session(request).map_err(Into::into),
            ToolOperation::ShowEvent(request) => self.show_event(request).map_err(Into::into),
            ToolOperation::QueryEvents(request) => self.query_events(request).map_err(Into::into),
            ToolOperation::ProStatus => self.pro_status().map_err(Into::into),
            ToolOperation::Blame(request) => self.blame(request),
        }
    }

    fn status(&self) -> Result<ToolOutcome, ToolBackendError> {
        let config =
            config::AppConfig::load(&self.data_root).map_err(classify_application_error)?;
        let storage = local_usage_storage_authority(&self.data_root);
        let control = usage_control_snapshot(config.local_usage.enabled);
        let value = crate::commands::status::status_read_model_authorized(
            &self.data_root,
            &config,
            &storage,
            &control,
        )
        .map_err(classify_application_error)?
        .report;
        Ok(ToolOutcome::plain(value))
    }

    fn sources(&self) -> Result<ToolOutcome, ToolBackendError> {
        let report = crate::provider_sources::discovered_sources_report();
        let mut source_values = crate::sources_json(&report.sources);
        source_values.extend(
            crate::discovered_plugin_sources_json(&self.data_root)
                .map_err(classify_application_error)?,
        );
        let (issues, issues_truncated) =
            crate::provider_sources::discovery_report_issues_json(&report);
        Ok(ToolOutcome::plain(json!({
            "schema_version": 1,
            "sources": source_values,
            "issues": issues,
            "issues_truncated": issues_truncated,
            "read_only": true,
        })))
    }

    fn search(&self, request: ToolSearchRequest) -> Result<ToolOutcome, ToolBackendError> {
        let request = crate::commands::source_index::SourceSearchRequest {
            query: request.query,
            terms: Vec::new(),
            limit: request.limit,
            provider: request.provider,
            history_source: request.history_source,
            provider_key: request.provider_key,
            source_id: request.source_id,
            source_format: request.source_format,
            workspace: request.workspace,
            since: request.since,
            primary_only: request.primary_only,
            include_subagents: request.include_subagents,
            content_scope: request.content_scope,
            event_type: request.event_type,
            file: request.file,
            session: request.session,
            events: request.events,
            include_current_session: request.include_current_session,
            backend: request.backend.map(|backend| match backend {
                ToolSearchBackend::Lexical => crate::SearchBackendArg::Lexical,
                ToolSearchBackend::Semantic => crate::SearchBackendArg::Semantic,
                ToolSearchBackend::Hybrid => crate::SearchBackendArg::Hybrid,
            }),
            semantic_weight: request.semantic_weight,
            semantic_enabled: false,
            semantic_daemon_enabled: false,
            refresh: crate::RefreshArg::Off,
        };
        crate::commands::source_index::validate_explicit_semantic_scope(&request)
            .map_err(classify_mcp_search_error)?;
        self.recover_enabled_daemon_before_search();
        let (structured, observation, compact) =
            crate::commands::source_index::mcp_search_with_compact(request, &self.data_root)
                .map_err(classify_mcp_search_error)?;
        let search = observation
            .complete_byte_totals()
            .map(|(delivered, matched)| ToolSearchUsageFacts::complete(delivered, matched))
            .unwrap_or_else(ToolSearchUsageFacts::unavailable);
        Ok(ToolOutcome {
            structured,
            compact: Some(compact),
            usage: ToolUsageFacts {
                search: Some(search),
                blame_target: None,
            },
            product_observation: None,
        })
    }

    fn recover_enabled_daemon_before_search(&self) {
        let Ok(config) = config::AppConfig::load(&self.data_root) else {
            return;
        };
        if !config.daemon.enabled
            || crate::semantic::daemon_autostart_suppression_reason().is_some()
        {
            return;
        }
        let _ = crate::semantic::autostart_daemon_and_wait(
            &self.data_root,
            &config,
            crate::DaemonTriggerCommandArg::Search,
        );
    }

    fn show_session(&self, request: ShowSessionRequest) -> Result<ToolOutcome, ToolBackendError> {
        let mode = match request.mode {
            ToolTranscriptMode::Full => crate::TranscriptMode::Full,
            ToolTranscriptMode::Lite => crate::TranscriptMode::Lite,
            ToolTranscriptMode::Log => crate::TranscriptMode::Log,
        };
        crate::commands::source_index::mcp_show_session_application(
            &self.data_root,
            &request.selector,
            mode,
            request.limit,
            request.cursor.as_deref(),
            request.output_limit_bytes,
        )
        .map(|(structured, compact)| ToolOutcome::with_compact(structured, compact))
        .map_err(classify_show_error)
    }

    fn show_event(&self, request: ShowEventRequest) -> Result<ToolOutcome, ToolBackendError> {
        crate::commands::source_index::mcp_show_event_application(
            &self.data_root,
            &request.selector,
            request.before,
            request.after,
            request.window,
            request.output_limit_bytes,
        )
        .map(|(structured, compact)| ToolOutcome::with_compact(structured, compact))
        .map_err(classify_show_error)
    }

    fn query_events(&self, request: QueryEventsRequest) -> Result<ToolOutcome, ToolBackendError> {
        let filters = CoreEventRangeFilters {
            providers: request.filters.providers,
            source_identity: request.filters.source_identity,
            history_source: request.filters.history_source,
            provider_key: request.filters.provider_key,
            source_id: request.filters.source_id,
            source_format: request.filters.source_format,
            provider_session_id: request.filters.provider_session_id,
            session_id: request.filters.session_id,
            parent_session_id: request.filters.parent_session_id,
            root_session_id: request.filters.root_session_id,
            branch: request.filters.branch,
            workspace: request.filters.workspace,
            event_type: request.filters.event_type,
            role: request.filters.role,
            agent_type: request.filters.agent_type,
            scope: request.filters.scope,
            file: request.filters.file,
            direction: request.filters.direction,
        };
        let selection = selection(request.since.as_deref(), request.until.as_deref(), filters)
            .map_err(event_query_failure)?;
        let cursor = request
            .cursor
            .as_deref()
            .map(decode_cursor)
            .transpose()
            .map_err(event_query_failure)?;
        let limit = validated_limit(request.limit).map_err(event_query_failure)?;
        let content = match request.content {
            ToolEventContent::Full => EventContentProjection::Full,
            ToolEventContent::Text => EventContentProjection::Text,
            ToolEventContent::None => EventContentProjection::None,
        };
        let wire = EventQueryWireRequest::from_selection(&selection, content, limit);
        let record_bytes = mcp_event_query_core_record_bytes(request.output_limit_bytes);
        let strict_budget =
            CoreEventPageBudget::new(record_bytes, record_bytes.min(MAX_CORE_CONTENT_BYTES));
        event_range_page_value(
            &self.data_root,
            &selection,
            cursor.as_ref(),
            &wire,
            Some(strict_budget),
        )
        .map(ToolOutcome::plain)
        .map_err(event_query_failure)
    }

    fn pro_status(&self) -> Result<ToolOutcome, ToolBackendError> {
        let started = Instant::now();
        let mut value = crate::pro::lifecycle_status_json(&self.data_root);
        if let Some(object) = value.as_object_mut() {
            let access_state = object
                .get("access_state")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let storage = local_usage_storage_authority(&self.data_root);
            let control = config::AppConfig::load(&self.data_root)
                .map(|config| usage_control_snapshot(config.local_usage.enabled))
                .unwrap_or_else(|_| {
                    crate::local_usage::UsageControlSnapshot::unavailable(false, None)
                });
            let usage = crate::local_usage::read_report_authorized(&storage, &control, false);
            object.insert(
                "local_usage".to_owned(),
                serde_json::to_value(usage).unwrap_or_else(|_| {
                    json!({
                        "schema_version": 1,
                        "enabled": false,
                        "state": "error",
                        "error": {
                            "code": "usage_report_serialization",
                            "message": "local usage report could not be serialized",
                        }
                    })
                }),
            );
            object.insert(
                "conversion_action".to_owned(),
                crate::local_usage::pro_conversion_action(access_state.as_deref())
                    .unwrap_or(Value::Null),
            );
        }
        let error_code = value.get("error_code").and_then(Value::as_str);
        let mut telemetry = ProStatusTelemetryV1::new(ProSurfaceV1::Mcp);
        telemetry.access_state = value
            .get("access_state")
            .and_then(Value::as_str)
            .and_then(ProAccessStateV1::from_safe_name);
        telemetry.helper_connection = if value.get("helper_version").is_some_and(Value::is_string) {
            ProHelperConnectionOutcomeV1::Connected
        } else {
            pro_helper_connection_outcome(error_code)
        };
        if error_code.is_some() {
            telemetry.fail(error_code);
        }
        let success = error_code.is_none();
        Ok(ToolOutcome {
            structured: value,
            compact: None,
            usage: ToolUsageFacts::default(),
            product_observation: Some(ToolProductObservation {
                operation: ProHostOperationV1::Status(telemetry),
                success,
                duration: started.elapsed(),
            }),
        })
    }

    fn blame(&self, request: BlameRequest) -> Result<ToolOutcome, ToolExecutionError> {
        self.blame_with(
            request,
            crate::pro::blame,
            crate::commands::blame::hydrate_evidence_context,
        )
    }

    fn blame_with(
        &self,
        request: BlameRequest,
        blame: impl FnOnce(
            &std::path::Path,
            &BlameTarget,
            u32,
            Option<String>,
        ) -> anyhow::Result<crate::pro::HostedBlameResult>,
        hydrate: impl FnOnce(
            &std::path::Path,
            &ctx_pro_host_protocol::BlameResult,
        ) -> crate::pro::evidence_preview::EvidencePreviewModel,
    ) -> Result<ToolOutcome, ToolExecutionError> {
        let started = Instant::now();
        let target_kind = match request.target.kind() {
            super::ToolBlameTargetKind::File => ProBlameTargetV1::File,
            super::ToolBlameTargetKind::Commit => ProBlameTargetV1::Commit,
            super::ToolBlameTargetKind::PullRequest => ProBlameTargetV1::PullRequest,
        };
        let mut telemetry = ProBlameTelemetryV1::new(Some(target_kind), ProSurfaceV1::Mcp);
        let result = (|| {
            let target = protocol_blame_target(request.target);
            target
                .validate()
                .map_err(|_| classify_application_error(crate::pro::invalid_blame_request()))?;
            let result = blame(
                &self.data_root,
                &target,
                u32::try_from(request.limit)
                    .map_err(|_| ToolBackendError::invalid_request("limit is too large"))?,
                request.cursor,
            )
            .map_err(|error| crate::pro::blame_boundary_error(error, &target))
            .map_err(classify_application_error)?;
            telemetry.complete(result.matches.len(), result.next.is_some());
            let previews = matches!(
                &result.target,
                ctx_pro_host_protocol::ResolvedBlameTarget::File { .. }
            )
            .then(|| hydrate(&self.data_root, &result.result));
            Ok(crate::pro::blame_result_json(&result, previews.as_ref()))
        })();
        if let Err(error) = &result {
            let code = match error {
                ToolBackendError::Pro { code, .. } => Some(*code),
                _ => None,
            };
            telemetry.failure = Some(code.map_or(ProFailureBucketV1::InvalidRequest, |code| {
                pro_failure_bucket(Some(code))
            }));
        }
        let product_observation = ToolProductObservation {
            operation: ProHostOperationV1::Blame(telemetry),
            success: result.is_ok(),
            duration: started.elapsed(),
        };
        match result {
            Ok(structured) => Ok(ToolOutcome {
                structured,
                compact: None,
                usage: ToolUsageFacts::default(),
                product_observation: Some(product_observation),
            }),
            Err(error) => Err(ToolExecutionError {
                error,
                usage: ToolUsageFacts::default(),
                product_observation: Some(product_observation),
            }),
        }
    }
}

impl ToolBackend for LocalToolBackend {
    fn execute(&self, operation: ToolOperation) -> Result<ToolOutcome, ToolExecutionError> {
        let usage = operation.invocation_usage();
        self.execute_inner(operation).map_err(|mut failure| {
            failure.usage.merge(usage);
            failure
        })
    }
}

fn protocol_blame_target(target: ToolBlameTarget) -> BlameTarget {
    match target {
        ToolBlameTarget::File {
            path,
            repository,
            lines,
        } => BlameTarget::File {
            path,
            repository,
            lines: lines.map(|range| LineRange {
                start: range.start,
                end: range.end,
            }),
        },
        ToolBlameTarget::Commit { oid, repository } => BlameTarget::Commit { oid, repository },
        ToolBlameTarget::PullRequest {
            selector,
            repository,
        } => BlameTarget::PullRequest {
            selector,
            repository,
        },
    }
}

fn event_query_failure(error: EventQueryError) -> ToolBackendError {
    ToolBackendError::EventQuery(error)
}

fn classify_mcp_search_error(
    error: crate::commands::source_index::McpSearchError,
) -> ToolBackendError {
    match error {
        crate::commands::source_index::McpSearchError::SemanticNotReady {
            code,
            detail,
            retryable,
        } => ToolBackendError::SemanticNotReady {
            code,
            detail,
            retryable,
        },
        crate::commands::source_index::McpSearchError::SemanticFailed { detail } => {
            ToolBackendError::internal(detail)
        }
        crate::commands::source_index::McpSearchError::GenerationChanged => {
            ToolBackendError::GenerationChanged
        }
        crate::commands::source_index::McpSearchError::GenerationAuthority(error) => {
            ToolBackendError::GenerationAuthority(error)
        }
        crate::commands::source_index::McpSearchError::Application { detail } => {
            ToolBackendError::internal(detail)
        }
    }
}

fn classify_show_error(
    error: crate::commands::source_index::ShowApplicationError,
) -> ToolBackendError {
    match error {
        crate::commands::source_index::ShowApplicationError::GenerationChanged => {
            ToolBackendError::GenerationChanged
        }
        crate::commands::source_index::ShowApplicationError::GenerationAuthority(error) => {
            ToolBackendError::GenerationAuthority(error)
        }
        crate::commands::source_index::ShowApplicationError::CursorStale { detail } => {
            ToolBackendError::Cursor {
                kind: CursorFailureKind::Stale,
                detail,
            }
        }
        crate::commands::source_index::ShowApplicationError::CursorMismatch { detail } => {
            ToolBackendError::Cursor {
                kind: CursorFailureKind::Mismatch,
                detail,
            }
        }
        crate::commands::source_index::ShowApplicationError::InvalidCursor { detail } => {
            ToolBackendError::Cursor {
                kind: CursorFailureKind::Invalid,
                detail,
            }
        }
        crate::commands::source_index::ShowApplicationError::OutputLimit {
            event_id,
            actual_bytes,
            maximum_bytes,
        } => ToolBackendError::OutputLimit {
            event_id,
            actual_bytes,
            maximum_bytes,
        },
        crate::commands::source_index::ShowApplicationError::Application { detail } => {
            ToolBackendError::internal(detail)
        }
    }
}

fn classify_application_error(error: anyhow::Error) -> ToolBackendError {
    if let Some(code) = crate::pro::stable_error_code(&error) {
        let mut encoded = Vec::new();
        let structured = crate::pro::write_stable_error_json(&mut encoded, &error)
            .ok()
            .filter(|written| *written)
            .and_then(|_| serde_json::from_slice(&encoded).ok())
            .unwrap_or_else(|| json!({ "error": code, "error_code": code }));
        return ToolBackendError::Pro {
            code,
            diagnostic: error.to_string(),
            structured,
        };
    }
    ToolBackendError::internal(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use ctx_history_core::RepositoryFileInvocationKind;
    use ctx_pro_host_protocol::{
        BlameAttribution, BlameCoverage, BlameCoverageUnit, BlameOutcome, BlameResult,
        CoreMaterializationReceiptIdentity, QuerySnapshotExpectation, ResolvedBlameTarget,
        ResourceKind, ResourceRef,
    };

    use super::*;

    fn private_tempdir() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        ctx_history_core::platform_security::restrict_private_directory(root.path()).unwrap();
        root
    }

    #[test]
    fn pro_status_usage_config_error_is_content_free() {
        let root = private_tempdir();
        let marker = "SECRET_PATH_TOKEN_7f98";
        std::fs::write(
            root.path().join("config.toml"),
            format!("invalid config /tmp/{marker}/bearer-secret\n"),
        )
        .unwrap();

        let response = LocalToolBackend::new(root.path().to_path_buf())
            .pro_status()
            .unwrap()
            .structured;
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(!encoded.contains(marker));
        assert!(!encoded.contains("bearer-secret"));
        assert_eq!(response["local_usage"]["state"], "error");
        assert_eq!(
            response["local_usage"]["error"]["code"],
            "local_usage_config_unavailable"
        );
        assert_eq!(
            response["local_usage"]["error"]["message"],
            "local usage configuration could not be read"
        );
    }

    #[test]
    fn status_surfaces_use_one_config_load_and_no_usage_metadata_probe() {
        let root = private_tempdir();
        let backend = LocalToolBackend::new(root.path().to_path_buf());
        for operation in [
            LocalToolBackend::status
                as fn(&LocalToolBackend) -> Result<ToolOutcome, ToolBackendError>,
            LocalToolBackend::pro_status,
        ] {
            let ((result, metadata_reads), config_loads) =
                crate::config::count_app_config_loads(|| {
                    crate::observability_composition::count_usage_control_metadata_reads(|| {
                        operation(&backend)
                    })
                });
            result.unwrap();
            assert_eq!(config_loads, 1);
            assert_eq!(metadata_reads, 0);
        }
    }

    #[test]
    fn typed_show_error_mapping_preserves_cursor_kind_and_detail() {
        let detail = "cursor belongs to another session".to_owned();
        let error = classify_show_error(
            crate::commands::source_index::ShowApplicationError::CursorMismatch {
                detail: detail.clone(),
            },
        );
        assert!(matches!(
            error,
            ToolBackendError::Cursor {
                kind: CursorFailureKind::Mismatch,
                detail: observed,
            } if observed == detail
        ));
    }

    #[test]
    fn typed_search_generation_authority_maps_without_anyhow_flattening() {
        let error = ctx_history_refresh::GenerationQueryAuthorityError::UncertifiedEmpty {
            generation_id: "11".repeat(32),
        };
        let mapped = classify_mcp_search_error(
            crate::commands::source_index::McpSearchError::GenerationAuthority(error),
        );
        assert!(matches!(
            mapped,
            ToolBackendError::GenerationAuthority(
                ctx_history_refresh::GenerationQueryAuthorityError::UncertifiedEmpty { .. }
            )
        ));
    }

    #[test]
    fn typed_blame_failure_carries_invocation_usage() {
        let root = private_tempdir();
        let error = LocalToolBackend::new(root.path().to_path_buf())
            .execute(ToolOperation::Blame(BlameRequest {
                target: ToolBlameTarget::PullRequest {
                    selector: "42".to_owned(),
                    repository: None,
                },
                limit: 8,
                cursor: None,
            }))
            .unwrap_err();
        assert_eq!(
            error.usage,
            ToolUsageFacts::for_blame(super::super::ToolBlameTargetKind::PullRequest)
        );
    }

    #[test]
    fn blame_target_conversion_is_exhaustive() {
        let target = ToolBlameTarget::File {
            path: "src/lib.rs".to_owned(),
            repository: Some("repo".to_owned()),
            lines: Some(super::super::ToolLineRange { start: 2, end: 4 }),
        };
        assert!(matches!(
            protocol_blame_target(target),
            BlameTarget::File {
                lines: Some(LineRange { start: 2, end: 4 }),
                ..
            }
        ));
    }

    #[test]
    fn file_blame_keeps_the_exact_json_model_and_hydrates_once() {
        let root = private_tempdir();
        let repository = ResourceRef {
            id: "repository:fixture".to_owned(),
            kind: ResourceKind::Repository,
            display: "fixture/repository".to_owned(),
        };
        let result = BlameResult {
            snapshot: QuerySnapshotExpectation::Core {
                receipt: CoreMaterializationReceiptIdentity {
                    core_generation_id: "a".repeat(64),
                    materializer_revision: "materializer-v1".to_owned(),
                },
            },
            target: ResolvedBlameTarget::File {
                path: "src/lib.rs".to_owned(),
                repository,
                requested_lines: None,
            },
            git_snapshot: Some(ctx_pro_host_protocol::GitSnapshot {
                head_oid: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                worktree_status: ctx_pro_host_protocol::WorktreeStatus::Clean,
            }),
            outcome: BlameOutcome {
                attribution: BlameAttribution::None,
                coverage: BlameCoverage {
                    unit: BlameCoverageUnit::CommittedLine,
                    evaluated: 0,
                    proven: 0,
                    possible: 0,
                    conflicting: 0,
                    none: 0,
                },
            },
            matches: Vec::new(),
            evidence: Vec::new(),
            next: None,
            lineage: None,
        };
        let hosted = crate::pro::HostedBlameResult {
            result,
            freshness: crate::pro::BlameResultFreshness::Current,
        };
        let model = crate::pro::evidence_preview::EvidencePreviewModel {
            previews: vec![crate::pro::evidence_preview::EvidencePreview {
                citation_numbers: vec![1],
                operation: RepositoryFileInvocationKind::Modify,
                path: "src/lib.rs".to_owned(),
                prior_path: None,
                tool_name: "test_tool".to_owned(),
                event_occurred_at_ms: Some(1_721_000_000_000),
                excerpt: "modified: src/lib.rs".to_owned(),
            }],
        };
        let expected = crate::pro::blame_result_json(&hosted, Some(&model));
        let hydration_reads = Cell::new(0_usize);

        let outcome = LocalToolBackend::new(root.path().to_path_buf())
            .blame_with(
                BlameRequest {
                    target: ToolBlameTarget::File {
                        path: "src/lib.rs".to_owned(),
                        repository: None,
                        lines: None,
                    },
                    limit: 8,
                    cursor: None,
                },
                |_, _, _, _| Ok(hosted.clone()),
                |_, _| {
                    hydration_reads.set(hydration_reads.get() + 1);
                    model.clone()
                },
            )
            .unwrap();

        assert_eq!(hydration_reads.get(), 1);
        assert_eq!(outcome.structured, expected);
        assert_eq!(
            outcome.structured["evidence_context"]["status"],
            "available"
        );
    }
}
