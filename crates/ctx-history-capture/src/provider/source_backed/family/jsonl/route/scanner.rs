use ctx_history_core::{CertifiedSource, CertifiedSourceAppend, CoreRecord, TypedKey};

use super::super::{JsonlPhysicalRecord, JsonlPhysicalStreamPosition, JsonlReader};
use super::JsonlFamilyTerminalProof;
use crate::Result;

use crate::repository_attribution::RepositoryAttributor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JsonlFamilyAppendMode {
    CertifiedSuffix,
    Replacement,
    ProjectorPreflight(bool),
}

impl JsonlFamilyAppendMode {
    pub(super) fn certified_suffix(self) -> bool {
        matches!(self, Self::CertifiedSuffix | Self::ProjectorPreflight(true))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JsonlFamilyProjectionMode {
    Cold,
    CertifiedAppend,
    Replacement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JsonlFamilySemanticPreflight {
    Ready,
    RetryReplacement,
}

/// Legacy optimized publication mode retained for non-Codex adapters while
/// they migrate independently to the shared executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JsonlFamilyPublication {
    Append,
    Replace,
}

/// Mutable services reused by one shared JSONL scanner worker across every
/// leaf in its stripe. Keeping these caches at worker lifetime preserves
/// bounded parallelism while amortizing provider-neutral projection work.
#[derive(Debug, Default)]
pub(crate) struct JsonlFamilyWorkerContext {
    repository_attributor: RepositoryAttributor,
}

impl JsonlFamilyWorkerContext {
    pub(super) fn begin_leaf(&mut self) {
        self.repository_attributor.begin_source();
    }

    pub(crate) fn repository_attributor(&mut self) -> &mut RepositoryAttributor {
        &mut self.repository_attributor
    }
}

/// Legacy optimized outcome retained for non-Codex adapters. Codex uses the
/// semantic executor, which cannot construct lifecycle evidence.
#[derive(Debug, Clone)]
pub(crate) struct JsonlFamilyOptimizedLeafOutcome {
    pub(super) certificate: CertifiedSource,
    pub(super) append: Option<CertifiedSourceAppend>,
    pub(super) terminal_proof: JsonlFamilyTerminalProof,
}

impl JsonlFamilyOptimizedLeafOutcome {
    pub(crate) fn replacement(
        certificate: CertifiedSource,
        terminal_proof: JsonlFamilyTerminalProof,
    ) -> Self {
        Self {
            certificate,
            append: None,
            terminal_proof,
        }
    }

    pub(crate) fn append(
        append: CertifiedSourceAppend,
        terminal_proof: JsonlFamilyTerminalProof,
    ) -> Self {
        Self {
            certificate: append.current().clone(),
            append: Some(append),
            terminal_proof,
        }
    }
}

#[derive(Debug)]
pub(crate) struct JsonlFamilySemanticPage {
    records: Vec<CoreRecord>,
}

impl JsonlFamilySemanticPage {
    pub(crate) fn new(records: Vec<CoreRecord>) -> Self {
        Self { records }
    }

    pub(super) fn into_records(self) -> Vec<CoreRecord> {
        self.records
    }
}

#[derive(Debug)]
pub(crate) struct JsonlFamilySemanticSummary {
    represented_physical_records: u64,
    rejected_records: u64,
    provider_checkpoint: Option<TypedKey>,
}

impl JsonlFamilySemanticSummary {
    pub(crate) fn new(
        represented_physical_records: u64,
        rejected_records: u64,
        provider_checkpoint: Option<TypedKey>,
    ) -> Self {
        Self {
            represented_physical_records,
            rejected_records,
            provider_checkpoint,
        }
    }

    pub(super) fn represented_physical_records(&self) -> u64 {
        self.represented_physical_records
    }

    pub(super) fn rejected_records(&self) -> u64 {
        self.rejected_records
    }

    pub(super) fn into_provider_checkpoint(self) -> Option<TypedKey> {
        self.provider_checkpoint
    }
}

/// Shared-owned physical input for an adapter's bounded semantic executor.
///
/// The executor may consume and roll back records for provider-native paging,
/// but it cannot construct or return physical checkpoints, certificates,
/// append evidence, terminal proof, or publication mode. Those remain sealed
/// in the family driver.
pub(crate) struct JsonlFamilyExecutionIo {
    reader: JsonlReader,
}

impl JsonlFamilyExecutionIo {
    pub(crate) fn new(reader: JsonlReader) -> Self {
        Self { reader }
    }

    pub(crate) fn next_record(&mut self) -> Result<Option<JsonlFamilyExecutionRecord>> {
        self.reader
            .next_execution_record()
            .map(|record| record.map(JsonlFamilyExecutionRecord::new))
    }

    pub(crate) fn record_bytes(&self, record: JsonlFamilyExecutionRecord) -> Result<&[u8]> {
        self.reader.execution_record_bytes(record.physical)
    }

    pub(crate) fn position(&self) -> Result<JsonlFamilyExecutionPosition> {
        self.reader
            .execution_position()
            .map(|physical| JsonlFamilyExecutionPosition { physical })
    }

    pub(crate) fn settle_preflight(
        &mut self,
        initial: JsonlFamilyExecutionPosition,
    ) -> Result<bool> {
        self.reader
            .settle_semantic_preflight(initial.physical, true, false)
    }

    pub(crate) fn restore(&mut self, position: JsonlFamilyExecutionPosition) -> Result<()> {
        self.reader.restore_execution_position(position.physical)
    }

    pub(crate) fn offset(&self) -> Result<u64> {
        self.reader.execution_offset()
    }

    pub(crate) fn complete_prefix_end(&self) -> Result<u64> {
        self.reader.execution_complete_prefix_end()
    }

    /// Boundary between the previously certified source prefix and bytes
    /// admitted by this append. No physical checkpoint state crosses the
    /// shared executor seam.
    pub(crate) fn certified_prefix_end(&self) -> Option<u64> {
        self.reader.execution_certified_prefix_end()
    }

    pub(crate) fn release_record_buffer(&mut self) -> Result<()> {
        self.reader.release_execution_record_buffer()
    }

    pub(super) fn admitted_eof_sha256(&self) -> Result<Option<[u8; 32]>> {
        self.reader.admitted_eof_sha256()
    }

    pub(super) fn complete_prefix_ends_with_terminal_nul_padding(&self) -> bool {
        self.reader.complete_prefix_ends_with_terminal_nul_padding()
    }

    pub(super) fn into_reader(self) -> JsonlReader {
        self.reader
    }
}

#[derive(Debug, Clone)]
pub(crate) struct JsonlFamilyExecutionPosition {
    physical: JsonlPhysicalStreamPosition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JsonlFamilyExecutionRecord {
    physical: JsonlPhysicalRecord,
}

impl JsonlFamilyExecutionRecord {
    fn new(physical: JsonlPhysicalRecord) -> Self {
        Self { physical }
    }

    pub(crate) fn physical_ordinal(self) -> u64 {
        self.physical.physical_ordinal
    }

    pub(crate) fn byte_start(self) -> u64 {
        self.physical.byte_start
    }

    pub(crate) fn byte_end_exclusive(self) -> u64 {
        self.physical.byte_end_exclusive
    }

    pub(crate) fn byte_len(self) -> u64 {
        self.physical.byte_len()
    }

    pub(crate) fn complete(self) -> bool {
        self.physical.complete
    }

    pub(crate) fn terminal_nul_padding(self) -> bool {
        self.physical.terminal_nul_padding
    }

    pub(crate) fn oversized(self) -> bool {
        self.physical.oversized
    }

    pub(crate) fn stored_len(self) -> usize {
        self.physical.stored_len
    }

    pub(crate) fn sha256(self) -> [u8; 32] {
        self.physical.sha256
    }
}

#[cfg(test)]
pub(crate) use activity::with_family_scanner_workers;
#[cfg(test)]
pub(super) use activity::{
    jsonl_family_scanner_activity, jsonl_family_scanner_probe,
    record_jsonl_family_scanner_activity, JsonlFamilyScannerActivity, JsonlFamilyScannerProbe,
    FAMILY_SCANNER_WORKERS_OVERRIDE,
};

#[cfg(test)]
mod activity {
    use std::{
        cell::Cell,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Barrier,
        },
    };

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub(crate) struct JsonlFamilyScannerActivity {
        pub(crate) worker_count: usize,
        pub(crate) sources_started: usize,
        pub(crate) sources_completed: usize,
        pub(crate) peak_active_scanners: usize,
    }

    thread_local! {
        pub(in super::super) static FAMILY_SCANNER_WORKERS_OVERRIDE: Cell<Option<usize>> =
            const { Cell::new(None) };
        static FAMILY_SCANNER_ACTIVITY: Cell<JsonlFamilyScannerActivity> =
            const { Cell::new(JsonlFamilyScannerActivity {
                worker_count: 0,
                sources_started: 0,
                sources_completed: 0,
                peak_active_scanners: 0,
            }) };
    }

    pub(crate) fn jsonl_family_scanner_activity() -> JsonlFamilyScannerActivity {
        FAMILY_SCANNER_ACTIVITY.get()
    }

    pub(in super::super) struct JsonlFamilyScannerProbe {
        sources_started: AtomicUsize,
        sources_completed: AtomicUsize,
        active_scanners: AtomicUsize,
        peak_active_scanners: AtomicUsize,
        rendezvous_arrivals: AtomicUsize,
        rendezvous_target: usize,
        rendezvous: Barrier,
    }

    impl JsonlFamilyScannerProbe {
        pub(in super::super) fn enter(&self) -> JsonlFamilyActiveScanner<'_> {
            self.sources_started.fetch_add(1, Ordering::SeqCst);
            let active = self
                .active_scanners
                .fetch_add(1, Ordering::SeqCst)
                .saturating_add(1);
            self.peak_active_scanners
                .fetch_max(active, Ordering::SeqCst);
            if self.rendezvous_arrivals.fetch_add(1, Ordering::SeqCst) < self.rendezvous_target {
                self.rendezvous.wait();
            }
            JsonlFamilyActiveScanner { probe: self }
        }

        fn snapshot(&self, worker_count: usize) -> JsonlFamilyScannerActivity {
            debug_assert_eq!(self.active_scanners.load(Ordering::SeqCst), 0);
            JsonlFamilyScannerActivity {
                worker_count,
                sources_started: self.sources_started.load(Ordering::SeqCst),
                sources_completed: self.sources_completed.load(Ordering::SeqCst),
                peak_active_scanners: self.peak_active_scanners.load(Ordering::SeqCst),
            }
        }
    }

    pub(in super::super) struct JsonlFamilyActiveScanner<'probe> {
        probe: &'probe JsonlFamilyScannerProbe,
    }

    impl Drop for JsonlFamilyActiveScanner<'_> {
        fn drop(&mut self) {
            self.probe.sources_completed.fetch_add(1, Ordering::SeqCst);
            self.probe.active_scanners.fetch_sub(1, Ordering::SeqCst);
        }
    }

    pub(in super::super) fn jsonl_family_scanner_probe(
        worker_count: usize,
    ) -> Option<Arc<JsonlFamilyScannerProbe>> {
        FAMILY_SCANNER_WORKERS_OVERRIDE.with(|workers| {
            workers.get().map(|_| {
                let rendezvous_target = worker_count.clamp(1, 4);
                Arc::new(JsonlFamilyScannerProbe {
                    sources_started: AtomicUsize::new(0),
                    sources_completed: AtomicUsize::new(0),
                    active_scanners: AtomicUsize::new(0),
                    peak_active_scanners: AtomicUsize::new(0),
                    rendezvous_arrivals: AtomicUsize::new(0),
                    rendezvous_target,
                    rendezvous: Barrier::new(rendezvous_target),
                })
            })
        })
    }

    pub(in super::super) fn record_jsonl_family_scanner_activity(
        worker_count: usize,
        probe: Option<&JsonlFamilyScannerProbe>,
    ) {
        FAMILY_SCANNER_ACTIVITY.set(
            probe.map_or_else(JsonlFamilyScannerActivity::default, |probe| {
                probe.snapshot(worker_count)
            }),
        );
    }

    pub(crate) fn with_family_scanner_workers<T>(workers: usize, run: impl FnOnce() -> T) -> T {
        struct Restore(Option<usize>);

        impl Drop for Restore {
            fn drop(&mut self) {
                FAMILY_SCANNER_WORKERS_OVERRIDE.set(self.0);
            }
        }

        let previous = FAMILY_SCANNER_WORKERS_OVERRIDE.replace(Some(workers));
        let _restore = Restore(previous);
        FAMILY_SCANNER_ACTIVITY.set(JsonlFamilyScannerActivity::default());
        run()
    }
}
