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
    bounded_outcome_evidence_relevant, bounded_outcome_plan,
    bounded_pull_request_association_query, lexical_absolute, BoundedCommitProducer,
    BoundedOutcomeOperation, BoundedOutcomePlan, BoundedOutcomePlanDisposition, MAX_COMMAND_BYTES,
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

#[cfg(test)]
mod tests;
