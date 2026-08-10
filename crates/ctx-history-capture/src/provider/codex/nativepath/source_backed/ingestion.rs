use super::*;

// Keep the existing repository probe accessor type-checked in ordinary builds
// without executing it. Qualification reads it below; this anonymous const
// emits no ledger state, call, allocation, or runtime observation path.
#[cfg(not(any(test, ctx_codex_causal_qualification)))]
const _: fn(&crate::repository_attribution::RepositoryAttributor) -> usize =
    crate::repository_attribution::RepositoryAttributor::full_certification_probe_count;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CodexJsonlFamilyPublicationV0 {
    Append,
    Replace,
}

#[derive(Debug)]
pub(super) struct CodexJsonlFamilyLeafOutcomeV0 {
    pub(super) certificate: CertifiedSource,
    pub(super) append: Option<CertifiedSourceAppend>,
    pub(super) terminal_prefix_bytes: u64,
    pub(super) terminal_prefix_sha256: [u8; 32],
    #[cfg(any(test, ctx_codex_causal_qualification))]
    pub(super) counters: CodexSourceBackedCountersV0,
}

pub(super) struct CodexJsonlFamilyLeafContextV0<'a> {
    pub(super) base_event_lookup: &'a BaseEventIdentityLookup,
    pub(super) repository_attributor: &'a mut crate::repository_attribution::RepositoryAttributor,
}

/// Runs exactly one Codex session leaf through the native scanner while the
/// shared JSONL family owns scheduling and writer publication.
///
/// This is intentionally the same NativePath path used by the former custom
/// route: exact replay validates only the native checkpoint observation,
/// certified growth scans only the suffix, and failed append evidence falls
/// back to one full native replacement scan.
pub(super) fn scan_codex_jsonl_family_leaf_v0(
    source: CodexCatalogSource,
    source_key: SourceKey,
    native_session_id: String,
    base: Option<&CertifiedSource>,
    context: &mut CodexJsonlFamilyLeafContextV0<'_>,
    mut emit: impl FnMut(
        CodexJsonlFamilyPublicationV0,
        u64,
        Vec<CoreRecord>,
    ) -> CodexSourceBackedResultV0<()>,
) -> CodexSourceBackedResultV0<CodexJsonlFamilyLeafOutcomeV0> {
    #[cfg(any(test, ctx_codex_causal_qualification))]
    let probes_before = context
        .repository_attributor
        .full_certification_probe_count();
    if base.is_some_and(|base| !base.observation().source().exact_descriptor_eq(&source_key)) {
        return Err(CodexSourceBackedErrorV0::UnsupportedLifecycle(
            native_session_id,
        ));
    }
    let proof = base
        .filter(|base| base.parser_revision() == CODEX_PARSER_REVISION)
        .and_then(|base| decode_append_proof(&source, &source_key, base).ok());
    if let (Some(base), Some(proof)) = (base, proof.as_ref()) {
        if proof.checkpoint.observation == source.catalog_observation {
            let frontier = base
                .frontier()
                .ok_or(CodexSourceBackedErrorV0::MissingCheckpoint)?;
            let append = CertifiedSourceAppend::certify(
                base,
                base.clone(),
                frontier.certified_prefix_bytes(),
                *frontier.certified_prefix_digest(),
            )?;
            return Ok(CodexJsonlFamilyLeafOutcomeV0 {
                certificate: base.clone(),
                append: Some(append),
                terminal_prefix_bytes: proof.checkpoint.observation.len,
                terminal_prefix_sha256: proof.checkpoint.full_revision_sha256,
                #[cfg(any(test, ctx_codex_causal_qualification))]
                counters: CodexSourceBackedCountersV0 {
                    catalog_sources: 1,
                    catalog_source_bytes: proof.checkpoint.observation.len,
                    replayed_sources: 1,
                    writer_exact_replay_sources: 1,
                    ..CodexSourceBackedCountersV0::default()
                },
            });
        }
    }

    let append_scanner = match (base, proof.as_ref()) {
        (Some(base), Some(proof))
            if source.catalog_observation.len > proof.checkpoint.observation.len =>
        {
            let scanner =
                CodexNativeScanner::new_source_backed_child_local_v0(source.clone(), Some(proof));
            match scanner {
                Ok(scanner) => Some((base, scanner)),
                Err(error) if invalid_append_proof(&error) => None,
                Err(error) => return Err(error.into()),
            }
        }
        _ => None,
    };
    let (append_base, publication, mut scanner) = match append_scanner {
        Some((base, scanner)) => (Some(base), CodexJsonlFamilyPublicationV0::Append, scanner),
        None => (
            None,
            CodexJsonlFamilyPublicationV0::Replace,
            CodexNativeScanner::new_source_backed_child_local_v0(source.clone(), None)?,
        ),
    };
    let session_id = codex_session_identity(&source_key, &native_session_id)?;
    let mut event_identity_state = match append_base {
        Some(_) => CodexEventIdentityStateV0::for_append(context.base_event_lookup.clone()),
        None => CodexEventIdentityStateV0::default(),
    };
    let mut staged_documents = 0_u64;
    while let Some(page) = scanner.next_page()? {
        let CodexNativeOwnedPage::Core(page) = page;
        if !page.core_rows.is_empty() {
            return Err(CodexSourceBackedErrorV0::UnexpectedLegacyRow);
        }
        let completed_bytes = page
            .next_safe_frontier
            .complete_prefix_end
            .checked_sub(page.expected_frontier.complete_prefix_end)
            .ok_or(CodexSourceBackedErrorV0::InvalidCheckpoint)?;
        let mut records = Vec::with_capacity(page.source_backed_rows.len());
        if !page.source_backed_rows.is_empty() {
            let owner = page
                .owner
                .as_ref()
                .ok_or(CodexSourceBackedErrorV0::MissingPageOwner)?;
            validate_owner(owner, &native_session_id)?;
            for row in page.source_backed_rows {
                records.push(codex_core_record(
                    &source_key,
                    session_id,
                    owner,
                    row,
                    &mut event_identity_state,
                    context.repository_attributor,
                )?);
                staged_documents = staged_documents
                    .checked_add(1)
                    .ok_or(CodexSourceBackedErrorV0::CountOverflow)?;
            }
        }
        scanner.release_transient_record_buffer();
        emit(publication, completed_bytes, records)?;
    }
    let scan = scanner.finish()?;
    let scan_counters = scan.counters;
    let certificate = match (append_base, scan.disposition) {
        (None, CodexParseDisposition::FullGeneration) => {
            certify_scan(&source_key, &scan, None, staged_documents, scan_counters)?
        }
        (Some(base), CodexParseDisposition::AppendDelta) => certify_scan(
            &source_key,
            &scan,
            Some(base),
            staged_documents,
            scan_counters,
        )?,
        _ => {
            return Err(CodexSourceBackedErrorV0::UnsupportedLifecycle(
                native_session_id,
            ));
        }
    };
    let append = match append_base {
        Some(base) => {
            let frontier = base
                .frontier()
                .ok_or(CodexSourceBackedErrorV0::MissingCheckpoint)?;
            Some(CertifiedSourceAppend::certify(
                base,
                certificate.clone(),
                frontier.certified_prefix_bytes(),
                *frontier.certified_prefix_digest(),
            )?)
        }
        None => None,
    };
    let terminal_prefix_bytes = scan.before_observation.len;
    let terminal_prefix_sha256 = scan.full_revision_sha256;
    #[cfg(any(test, ctx_codex_causal_qualification))]
    let counters = {
        let mut counters = CodexSourceBackedCountersV0 {
            catalog_sources: 1,
            catalog_source_bytes: source.catalog_observation.len,
            cold_sources: u64::from(base.is_none()),
            appended_sources: u64::from(append.is_some()),
            replaced_sources: u64::from(base.is_some() && append.is_none()),
            writer_mutated_sources: 1,
            scanner_workers: 1,
            scanner_source_opens: 1,
            scanner_sources_started: 1,
            scanner_sources_completed: 1,
            peak_active_scanners: 1,
            repository_full_git_certification_probes: u64::try_from(
                context
                    .repository_attributor
                    .full_certification_probe_count()
                    .saturating_sub(probes_before),
            )
            .unwrap_or(u64::MAX),
            staged_documents,
            ..CodexSourceBackedCountersV0::default()
        };
        counters.add_scan(scan_counters);
        counters
    };
    Ok(CodexJsonlFamilyLeafOutcomeV0 {
        certificate,
        append,
        terminal_prefix_bytes,
        terminal_prefix_sha256,
        #[cfg(any(test, ctx_codex_causal_qualification))]
        counters,
    })
}

fn invalid_append_proof(error: &CaptureError) -> bool {
    matches!(
        error,
        CaptureError::InvalidPayload(detail)
            if detail.starts_with("invalid Codex append proof:")
    )
}
