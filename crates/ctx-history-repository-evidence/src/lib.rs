mod association;
mod attributor;
mod engine;
mod exact_json;
mod git;
mod identity;
mod outcome;
mod scoping;
mod shell;

use ctx_history_core::{
    CoreRecordAnnotation, CoreRecordResult, GitObjectId, RepositoryAbstentionReason,
    RepositoryAlias, RepositoryFileInvocationKind, RepositoryFileInvocationTextRange,
    RepositoryFileObservationKind, RepositoryVcsObservationKind,
};
use serde_json::Value;

pub use association::{exact_pull_request_association, UnscopedPullRequestAssociationObservation};
pub use attributor::RepositoryAttributor;
pub use engine::{attribute, MAX_REPOSITORY_CANDIDATES};
use engine::{ScopedFileInput, ScopedRepositoryFileInvocationEvidence, ScopedVcsInput};
pub use exact_json::{default_metadata, exact_json_value, raw_object_keys_are_unique};
use git::CertifiedCandidate;
use identity::push_abstention;
pub use outcome::{
    linked_outcome_evidence, LinkedOutcomeEvidence, LinkedOutcomeInput, UnscopedOutcomeObservation,
};
pub use shell::{
    bounded_outcome_evidence_can_be_positive, bounded_outcome_evidence_relevant,
    bounded_outcome_plan, bounded_pull_request_association_query, lexical_absolute,
    BoundedCommitProducer, BoundedOutcomeOperation, BoundedOutcomePlan,
    BoundedOutcomePlanDisposition, MAX_COMMAND_BYTES,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnscopedFileObservation {
    pub path: String,
    pub prior_path: Option<String>,
    pub kind: RepositoryFileObservationKind,
}

/// Exact request-side file intent supplied by a provider adapter.
///
/// Callers must not synthesize this from generic file observations,
/// recursively discovered paths, structured JSON, or tool results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnscopedRepositoryFileInvocationEvidence {
    pub operation_ordinal: u32,
    pub path: String,
    pub prior_path: Option<String>,
    pub kind: RepositoryFileInvocationKind,
    pub tool_name: Option<String>,
    pub normalized_text_range: Option<RepositoryFileInvocationTextRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnscopedVcsObservation {
    pub path: Option<String>,
    pub kind: RepositoryVcsObservationKind,
    pub object_id: Option<GitObjectId>,
    pub parent_object_ids: Vec<GitObjectId>,
    pub reference: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct AttributionInput {
    pub activity_at_unix_ms: Option<i64>,
    pub provider_native_repository_aliases: Vec<RepositoryAlias>,
    pub session_cwd: Option<String>,
    pub declared_tool_workdir: Option<String>,
    pub command: Option<String>,
    pub command_disposition: CommandEvidenceDisposition,
    pub provider_native_context_ambiguous: bool,
    pub structured_content: Option<Value>,
    pub repository_file_invocation_evidence: Vec<UnscopedRepositoryFileInvocationEvidence>,
    pub file_observations: Vec<UnscopedFileObservation>,
    pub vcs_observations: Vec<UnscopedVcsObservation>,
    pub outcome_operation_repository_path: Option<String>,
    pub outcome_output_repository_path: Option<String>,
    pub outcome_observations: Vec<UnscopedOutcomeObservation>,
    pub pull_request_associations: Vec<UnscopedPullRequestAssociationObservation>,
    pub outcome_abstentions: Vec<(RepositoryAbstentionReason, &'static str)>,
}

impl AttributionInput {
    pub fn apply_linked_outcome(&mut self, linked: LinkedOutcomeEvidence) {
        self.provider_native_repository_aliases = linked.provider_native_repository_aliases;
        self.outcome_operation_repository_path = linked.outcome_operation_repository_path;
        self.outcome_output_repository_path = linked.outcome_output_repository_path;
        self.outcome_observations = linked.outcomes;
        self.pull_request_associations = linked.pull_request_associations;
        self.outcome_abstentions = linked.abstentions;
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum CommandEvidenceDisposition {
    #[default]
    Analyze,
    CommandTooLarge,
}

pub fn apply_annotation(
    record: &mut ctx_history_core::CoreRecord,
    annotation: CoreRecordAnnotation,
) -> CoreRecordResult<()> {
    record.mcp_tool_call = annotation.mcp_tool_call;
    record.content.structured_content = annotation.structured_content;
    record.metadata = annotation.metadata;
    record.repository_candidate_evidence = annotation.repository_candidate_evidence;
    record.repository_bindings = annotation.repository_bindings;
    record.repository_abstentions = annotation.repository_abstentions;
    record.repository_file_invocation_evidence = annotation.repository_file_invocation_evidence;
    record.repository_file_observations = annotation.repository_file_observations;
    record.repository_vcs_observations = annotation.repository_vcs_observations;
    record.bind_repository_commit_operation_identities()
}

/// Merge independently attributed repository activities into one record
/// annotation without treating provider content or MCP identity as mergeable.
pub fn merge_repository_annotation(
    target: &mut CoreRecordAnnotation,
    mut additional: CoreRecordAnnotation,
) {
    for candidate in additional.repository_candidate_evidence.candidates {
        target
            .repository_candidate_evidence
            .insert(candidate.kind, candidate.path);
    }
    for mut binding in additional.repository_bindings.drain(..) {
        if let Some(existing) = target
            .repository_bindings
            .iter_mut()
            .find(|existing| existing.binding_id == binding.binding_id)
        {
            for alias in binding.aliases.drain(..) {
                if !existing.aliases.contains(&alias) {
                    existing.aliases.push(alias);
                }
            }
            for evidence in binding.evidence.drain(..) {
                if !existing.evidence.contains(&evidence) {
                    existing.evidence.push(evidence);
                }
            }
            if existing.local_root_authorization.is_none() {
                existing.local_root_authorization = binding.local_root_authorization;
            }
        } else {
            target.repository_bindings.push(binding);
        }
    }
    for abstention in additional.repository_abstentions {
        if !target.repository_abstentions.contains(&abstention) {
            target.repository_abstentions.push(abstention);
        }
    }
    for observation in additional.repository_file_observations {
        if !target.repository_file_observations.contains(&observation) {
            target.repository_file_observations.push(observation);
        }
    }
    for evidence in additional.repository_file_invocation_evidence {
        if !target
            .repository_file_invocation_evidence
            .contains(&evidence)
        {
            target.repository_file_invocation_evidence.push(evidence);
        }
    }
    target.repository_file_invocation_evidence.sort();
    for observation in additional.repository_vcs_observations {
        if !target.repository_vcs_observations.contains(&observation) {
            target.repository_vcs_observations.push(observation);
        }
    }
}

#[cfg(test)]
mod tests;
