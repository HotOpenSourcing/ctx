use std::time::Instant;

use ctx_pro_host_protocol::{BlameTarget, LineRange, MAX_BLAME_CURSOR_BYTES};
use serde_json::{json, Map, Value};

use super::{
    invalid_tool_request, object_schema, optional_usize, McpOperationParseError,
    ParsedToolOperation,
};
use crate::tool_backend::{
    BlameRequest, IntegrationProductFacts, ToolBackendError, ToolBlameTarget,
    ToolIntegrationReceipt, ToolLineRange, ToolOperation, ToolUsageFacts,
};

pub(super) const MCP_BLAME_LIMIT: usize = 8;
pub(super) const MCP_BLAME_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

pub(super) fn blame_operation(
    arguments: &Value,
    invalid_blame_error: impl Fn() -> ToolBackendError,
) -> Result<ParsedToolOperation, McpOperationParseError> {
    let started = Instant::now();
    let target = required_blame_target(arguments).map_err(|_| {
        rejected_blame_operation(invalid_blame_error(), ToolUsageFacts::default(), started)
    })?;
    let usage = ToolUsageFacts::for_blame(target.kind());
    let limit = optional_usize(arguments, "limit")
        .map_err(|_| rejected_blame_operation(invalid_blame_error(), usage.clone(), started))?
        .unwrap_or(MCP_BLAME_LIMIT);
    if limit == 0 || limit > MCP_BLAME_LIMIT {
        return Err(rejected_blame_operation(
            invalid_blame_error(),
            usage,
            started,
        ));
    }
    let cursor = optional_cursor(arguments)
        .map_err(|_| rejected_blame_operation(invalid_blame_error(), usage.clone(), started))?;
    Ok(ParsedToolOperation {
        operation: ToolOperation::Blame(BlameRequest {
            target,
            limit,
            cursor,
        }),
        usage,
    })
}

pub(super) fn rejected_blame_operation(
    error: ToolBackendError,
    usage: ToolUsageFacts,
    started: Instant,
) -> McpOperationParseError {
    let target = usage.blame_target;
    McpOperationParseError {
        error,
        usage,
        integration_receipt: Some(ToolIntegrationReceipt {
            receipt: IntegrationProductFacts::Blame {
                target,
                result_count: None,
                has_more: None,
                failure_code: Some("invalid_request"),
            },
            success: false,
            duration: started.elapsed(),
        }),
    }
}

pub(super) fn required_blame_target(
    arguments: &Value,
) -> Result<ToolBlameTarget, ToolBackendError> {
    let target = arguments
        .get("target")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_tool_request("target must be an object"))?;
    let kind = target
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_tool_request("target.kind is required"))?;
    let repository = optional_nonempty_string(target, "repository")?;
    let result = match kind {
        "file" => {
            reject_unknown_target_keys(target, &["kind", "path", "repository", "lines"])?;
            let path = required_nonempty_string(target, "path")?;
            let lines = optional_line_range(target.get("lines"))?;
            ToolBlameTarget::File {
                path,
                repository,
                lines,
            }
        }
        "commit" => {
            reject_unknown_target_keys(target, &["kind", "oid", "repository"])?;
            ToolBlameTarget::Commit {
                oid: required_nonempty_string(target, "oid")?,
                repository,
            }
        }
        "pull_request" => {
            reject_unknown_target_keys(target, &["kind", "selector", "repository"])?;
            ToolBlameTarget::PullRequest {
                selector: required_nonempty_string(target, "selector")?,
                repository,
            }
        }
        _ => {
            return Err(invalid_tool_request(
                "target.kind must be file, commit, or pull_request",
            ));
        }
    };
    validate_tool_target(&result)?;
    Ok(result)
}

fn validate_tool_target(target: &ToolBlameTarget) -> Result<(), ToolBackendError> {
    let target = match target {
        ToolBlameTarget::File {
            path,
            repository,
            lines,
        } => BlameTarget::File {
            path: path.clone(),
            repository: repository.clone(),
            lines: lines.map(|line| LineRange {
                start: line.start,
                end: line.end,
            }),
        },
        ToolBlameTarget::Commit { oid, repository } => BlameTarget::Commit {
            oid: oid.clone(),
            repository: repository.clone(),
        },
        ToolBlameTarget::PullRequest {
            selector,
            repository,
        } => BlameTarget::PullRequest {
            selector: selector.clone(),
            repository: repository.clone(),
        },
    };
    target
        .validate()
        .map_err(|error| invalid_tool_request(error.message))
}

fn optional_cursor(arguments: &Value) -> Result<Option<String>, ToolBackendError> {
    match arguments.get("cursor") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value))
            if !value.is_empty() && value.len() <= MAX_BLAME_CURSOR_BYTES && value.is_ascii() =>
        {
            Ok(Some(value.clone()))
        }
        Some(Value::String(_)) => Err(invalid_tool_request(format!(
            "cursor must contain 1 to {MAX_BLAME_CURSOR_BYTES} ASCII bytes"
        ))),
        Some(_) => Err(invalid_tool_request("cursor must be a string")),
    }
}

fn optional_line_range(value: Option<&Value>) -> Result<Option<ToolLineRange>, ToolBackendError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let object = value
        .as_object()
        .ok_or_else(|| invalid_tool_request("target.lines must be an object"))?;
    reject_unknown_target_keys(object, &["start", "end"])?;
    let start = required_positive_u32(object, "start")?;
    let end = required_positive_u32(object, "end")?;
    let range = LineRange { start, end };
    range
        .validate()
        .map_err(|error| invalid_tool_request(error.message))?;
    Ok(Some(ToolLineRange { start, end }))
}

fn required_positive_u32(
    object: &Map<String, Value>,
    field: &str,
) -> Result<u32, ToolBackendError> {
    let value = object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_tool_request(format!("target.lines.{field} must be positive")))?;
    let value = u32::try_from(value)
        .map_err(|_| invalid_tool_request(format!("target.lines.{field} is too large")))?;
    if value == 0 {
        return Err(invalid_tool_request(format!(
            "target.lines.{field} must be positive"
        )));
    }
    Ok(value)
}

fn required_nonempty_string(
    object: &Map<String, Value>,
    field: &str,
) -> Result<String, ToolBackendError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| invalid_tool_request(format!("target.{field} is required")))
}

fn optional_nonempty_string(
    object: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, ToolBackendError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) => Err(invalid_tool_request(format!(
            "target.{field} cannot be empty"
        ))),
        Some(_) => Err(invalid_tool_request(format!(
            "target.{field} must be a string"
        ))),
    }
}

fn reject_unknown_target_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
) -> Result<(), ToolBackendError> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid_tool_request(format!(
            "unknown target argument {key}"
        )));
    }
    Ok(())
}

pub(super) fn pro_blame_tool() -> Value {
    let target = json!({
        "oneOf": [
            object_schema(
                json!({
                    "kind": { "type": "string", "const": "file" },
                    "path": { "type": "string", "minLength": 1, "description": "Repository-relative committed file path." },
                    "repository": repository_schema(),
                    "lines": object_schema(
                        json!({
                            "start": { "type": "integer", "minimum": 1 },
                            "end": { "type": "integer", "minimum": 1 }
                        }),
                        vec!["start", "end"]
                    )
                }),
                vec!["kind", "path"]
            ),
            object_schema(
                json!({
                    "kind": { "type": "string", "const": "commit" },
                    "oid": { "type": "string", "minLength": 1, "description": "Full or unambiguous abbreviated Git commit ID." },
                    "repository": repository_schema()
                }),
                vec!["kind", "oid"]
            ),
            object_schema(
                json!({
                    "kind": { "type": "string", "const": "pull_request" },
                    "selector": { "type": "string", "minLength": 1, "description": "Positive PR number or canonical GitHub, GitLab, or Codeberg PR/MR URL." },
                    "repository": repository_schema()
                }),
                vec!["kind", "selector"]
            )
        ]
    });
    json!({
        "name": super::McpToolKind::Blame.tool_name(),
        "title": "Agent Blame",
        "description": "Return complete cited provenance for committed file lines, a commit, or a pull request. PR activity and commit production remain separate. Blame may perform bounded local catch-up that updates the canonical Core index, writes the encrypted derived Pro graph, and writes the projection acknowledgement. It never writes provider history or repositories.",
        "inputSchema": object_schema(
            json!({
                "target": target,
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MCP_BLAME_LIMIT,
                    "default": MCP_BLAME_LIMIT,
                    "description": "Maximum complete matches to return."
                },
                "cursor": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_BLAME_CURSOR_BYTES,
                    "description": "Opaque continuation cursor from a previous blame page."
                }
            }),
            vec!["target"]
        ),
        "annotations": {
            "readOnlyHint": false,
            "destructiveHint": false,
            "idempotentHint": true
        },
    })
}

fn repository_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "description": "Logical repository identity; required with a PR number and optional for other selectors."
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn blame_schema_discloses_local_writes_and_is_agent_sized() {
        let schema = pro_blame_tool();
        let disclosure = "Blame may perform bounded local catch-up that updates the canonical Core index, writes the encrypted derived Pro graph, and writes the projection acknowledgement. It never writes provider history or repositories.";
        assert_eq!(schema["annotations"]["readOnlyHint"], false);
        assert_eq!(schema["annotations"]["destructiveHint"], false);
        assert_eq!(schema["annotations"]["idempotentHint"], true);
        assert!(schema["description"]
            .as_str()
            .is_some_and(|description| description.contains(disclosure)));
        assert_eq!(
            schema["inputSchema"]["properties"]["limit"]["maximum"],
            MCP_BLAME_LIMIT
        );
        assert_eq!(
            schema["inputSchema"]["properties"]["target"]["oneOf"]
                .as_array()
                .map(Vec::len),
            Some(3)
        );
    }

    #[test]
    fn blame_mcp_schema_has_no_evidence_switch() {
        let schema = pro_blame_tool();
        let properties = schema["inputSchema"]["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(properties, BTreeSet::from(["cursor", "limit", "target"]));
        assert_eq!(schema["inputSchema"]["additionalProperties"], false);
    }

    #[test]
    fn target_parser_accepts_only_launch_targets() {
        for target in [
            json!({"kind": "file", "path": "src/lib.rs", "lines": {"start": 2, "end": 4}}),
            json!({"kind": "commit", "oid": "abc1234"}),
            json!({"kind": "pull_request", "selector": "42", "repository": "ctxrs/ctx"}),
            json!({"kind": "pull_request", "selector": "https://gitlab.example.com/a/b/-/merge_requests/42"}),
        ] {
            assert!(
                required_blame_target(&json!({"target": target})).is_ok(),
                "{target}"
            );
        }
        for target in [
            json!({"kind": "issue", "selector": "42"}),
            json!({"kind": "commit", "oid": "abc", "line": 2}),
        ] {
            assert!(
                required_blame_target(&json!({"target": target})).is_err(),
                "{target}"
            );
        }
    }

    #[test]
    fn rejected_blame_preserves_only_the_safely_parsed_target_kind() {
        let invalid_target = blame_operation(
            &json!({
                "target": {"kind": "private-invalid-kind"}
            }),
            || invalid_tool_request("invalid blame"),
        )
        .unwrap_err();
        let invalid_target = invalid_target.integration_receipt.unwrap();
        assert!(matches!(
            invalid_target.receipt,
            IntegrationProductFacts::Blame { target: None, .. }
        ));

        let invalid_limit = blame_operation(
            &json!({
                "target": {"kind": "commit", "oid": "abc123"},
                "limit": MCP_BLAME_LIMIT + 1,
            }),
            || invalid_tool_request("invalid blame"),
        )
        .unwrap_err();
        assert_eq!(
            invalid_limit.usage,
            ToolUsageFacts::for_blame(crate::tool_backend::ToolBlameTargetKind::Commit)
        );
        let invalid_limit = invalid_limit.integration_receipt.unwrap();
        assert!(matches!(
            invalid_limit.receipt,
            IntegrationProductFacts::Blame {
                target: Some(crate::tool_backend::ToolBlameTargetKind::Commit),
                ..
            }
        ));
    }
}
