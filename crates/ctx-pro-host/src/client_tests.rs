use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(unix)]
use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
    thread,
    time::Duration,
};

use super::*;
use crate::{AuthorizationMode, AuthorizationReceipt, CoreGenerationPin};
use ctx_pro_host_protocol::{
    BlameAttribution, BlameCoverage, BlameCoverageUnit, BlameOutcome, BlameResult,
    CoreMaterializationFinalizationPhase, CoreMaterializationFinalizationProgress,
    CoreMaterializationReceipt, CoreProjectionCurrentness, ErrorClass, HelloResult,
    MaterializedCoverage, ProAccessState, ProAccessStatus, ProOperation, ProStorageEvidence,
    ProtocolError, QuerySnapshotExpectation, RepositoryCoverage, ResolvedBlameTarget, ResourceKind,
    ResourceRef,
};

struct MissingPin;

impl CoreGenerationPin for MissingPin {
    fn generation_id(&self) -> &str {
        unreachable!("the missing-pin test host never returns a pin")
    }
}

struct MissingPinHost;

impl InstalledProHost for MissingPinHost {
    fn host_version(&self) -> &str {
        "1.0.0"
    }

    fn existing_installation_id(&self, _data_root: &Path) -> Result<Option<String>> {
        Ok(Some("00000000-0000-4000-8000-000000000000".to_owned()))
    }

    fn validated_installed_helper(&self, _data_root: &Path) -> Result<VerifiedHelperExecutable> {
        bail!("pro_not_installed: helper fixture is absent")
    }

    fn release_trust(&self) -> Result<crate::lifecycle_manifest::ReleaseTrust> {
        crate::lifecycle_manifest::release_trust(crate::lifecycle_manifest::ReleaseChannel::Stable)
    }

    fn authorization_for_challenge(
        &self,
        _data_root: &Path,
        _challenge: &[u8; ctx_pro_host_protocol::AUTHORIZATION_CHALLENGE_BYTES],
        _mode: AuthorizationMode,
    ) -> Result<AuthorizationReceipt> {
        bail!("authentication_denied: test host does not authorize")
    }

    fn unix_time(&self) -> Result<i64> {
        Ok(0)
    }
}

impl CoreGenerationHost for MissingPinHost {
    type Pin = MissingPin;

    fn pin_active_core_generation(&self, _data_root: &Path) -> Result<Self::Pin> {
        bail!("source_unavailable: active verified Core generation is missing")
    }
}

#[cfg(unix)]
struct DropTrackedPin {
    generation_id: String,
    dropped: Arc<AtomicBool>,
}

#[cfg(unix)]
impl CoreGenerationPin for DropTrackedPin {
    fn generation_id(&self) -> &str {
        &self.generation_id
    }
}

#[cfg(unix)]
impl Drop for DropTrackedPin {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[cfg(unix)]
struct PinLifetimeHost {
    helper_path: PathBuf,
    pin_dropped: Arc<AtomicBool>,
}

#[cfg(unix)]
impl InstalledProHost for PinLifetimeHost {
    fn host_version(&self) -> &str {
        "1.0.0"
    }

    fn existing_installation_id(&self, _data_root: &Path) -> Result<Option<String>> {
        Ok(Some("00000000-0000-4000-8000-000000000000".to_owned()))
    }

    fn helper_override(&self) -> Result<Option<PathBuf>> {
        Ok(Some(self.helper_path.clone()))
    }

    fn validated_installed_helper(&self, _data_root: &Path) -> Result<VerifiedHelperExecutable> {
        unreachable!("the test host always selects its developer helper")
    }

    fn release_trust(&self) -> Result<crate::lifecycle_manifest::ReleaseTrust> {
        crate::lifecycle_manifest::release_trust(crate::lifecycle_manifest::ReleaseChannel::Stable)
    }

    fn authorization_for_challenge(
        &self,
        _data_root: &Path,
        _challenge: &[u8; ctx_pro_host_protocol::AUTHORIZATION_CHALLENGE_BYTES],
        _mode: AuthorizationMode,
    ) -> Result<AuthorizationReceipt> {
        unreachable!("the status-only helper does not select authorization")
    }

    fn unix_time(&self) -> Result<i64> {
        Ok(0)
    }
}

#[cfg(unix)]
impl CoreGenerationHost for PinLifetimeHost {
    type Pin = DropTrackedPin;

    fn pin_active_core_generation(&self, _data_root: &Path) -> Result<Self::Pin> {
        Ok(DropTrackedPin {
            generation_id: "a".repeat(64),
            dropped: Arc::clone(&self.pin_dropped),
        })
    }
}

#[cfg(unix)]
fn python3_interpreter() -> PathBuf {
    [
        "/usr/bin/python3",
        "/usr/local/bin/python3",
        "/usr/local/bin/python3.14",
        "/usr/local/bin/python3.13",
        "/opt/homebrew/bin/python3",
    ]
    .into_iter()
    .filter_map(|candidate| fs::canonicalize(candidate).ok())
    .find(|candidate| {
        fs::metadata(candidate)
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
    })
    .expect("status pin lifetime test requires an executable Python 3")
}

#[cfg(unix)]
fn write_blocking_status_helper(
    helper_path: &Path,
    request_path: &Path,
    release_path: &Path,
) {
    const HELPER: &str = r#"
import json, pathlib, struct, sys, time

REQUEST = pathlib.Path(__REQUEST_PATH__)
RELEASE = pathlib.Path(__RELEASE_PATH__)
RESPONSE = json.loads(__RESPONSE__)
FINGERPRINT = __PROTOCOL_FINGERPRINT__

def receive():
    header = sys.stdin.buffer.read(12)
    if len(header) != 12 or header[:6] != b'CTXPRO' or struct.unpack('>H', header[6:8])[0] != 3:
        sys.exit(20)
    size = struct.unpack('>I', header[8:12])[0]
    payload = sys.stdin.buffer.read(size)
    if len(payload) != size:
        sys.exit(21)
    return json.loads(payload)

def send(request, kind, body):
    envelope = {
        'sequence': request['sequence'],
        'request_id': request['request_id'],
        'message': {'kind': kind, 'body': body},
    }
    payload = json.dumps(envelope, separators=(',', ':')).encode()
    sys.stdout.buffer.write(b'CTXPRO' + struct.pack('>H', 3) + struct.pack('>I', len(payload)) + payload)
    sys.stdout.buffer.flush()

hello = receive()
if hello['message']['kind'] != 'hello':
    sys.exit(22)
send(hello, 'hello', {
    'protocol_version': 3,
    'protocol_fingerprint': FINGERPRINT,
    'helper_version': 'status-pin-lifetime-fixture-v1',
    'capabilities': ['status'],
    'authorization_challenge_base64url': '',
})

request = receive()
if request['message']['kind'] != 'status':
    sys.exit(23)
requested_generation = request['message']['body'].get('requested_core_generation_id')
REQUEST.write_text(requested_generation)
while not RELEASE.exists():
    time.sleep(0.001)
send(request, 'status', RESPONSE)
"#;
    let helper = HELPER
        .replace(
            "__REQUEST_PATH__",
            &serde_json::to_string(&request_path.to_string_lossy()).unwrap(),
        )
        .replace(
            "__RELEASE_PATH__",
            &serde_json::to_string(&release_path.to_string_lossy()).unwrap(),
        )
        .replace(
            "__RESPONSE__",
            &serde_json::to_string(
                &serde_json::to_string(&status(MaterializedCoverage::Abstained)).unwrap(),
            )
            .unwrap(),
        )
        .replace(
            "__PROTOCOL_FINGERPRINT__",
            &serde_json::to_string(PROTOCOL_FINGERPRINT).unwrap(),
        );
    let interpreter = python3_interpreter();
    fs::write(
        helper_path,
        format!("#!{}\n{helper}", interpreter.display()),
    )
    .unwrap();
    fs::set_permissions(helper_path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn receipt(generation: char) -> CoreMaterializationReceipt {
    CoreMaterializationReceipt {
        core_generation_id: generation.to_string().repeat(64),
        core_record_contract_fingerprint: "b".repeat(64),
        source_snapshot_sha256: "c".repeat(64),
        materializer_revision: "materializer-v1".to_owned(),
        source_count: 1,
        event_count: 1,
    }
}

fn status(coverage: MaterializedCoverage) -> StatusResult {
    let supported_operations = BTreeSet::from([
        ProOperation::FileBlame,
        ProOperation::CommitBlame,
        ProOperation::PullRequestBlame,
    ]);
    let mut core_receipt = receipt('a');
    if coverage == MaterializedCoverage::Empty {
        core_receipt.event_count = 0;
    }
    StatusResult {
        currentness: CoreProjectionCurrentness::Current,
        requested_core_generation_id: Some("a".repeat(64)),
        core_receipt: Some(core_receipt),
        coverage,
        repository_coverage: if coverage == MaterializedCoverage::Complete {
            RepositoryCoverage {
                repository_candidate_events: 1,
                logical_binding_events: 1,
                certified_live_root_access_events: 1,
                file_evidence_events: 1,
                exact_commit_evidence_events: 1,
                exact_pull_request_evidence_events: 1,
            }
        } else {
            RepositoryCoverage::default()
        },
        core_preparation_peak_workers: 4,
        finalization_progress: None,
        storage_evidence: Some(ProStorageEvidence {
            graph_manifest_schema: 3,
            flat_format_version: 2,
            materializer_checkpoint_version: 5,
            journal_pack_format_version: 3,
            legacy_journals_written: 0,
            journal_pages_written: 2,
            journal_packs_written: 1,
            journal_finish_activity: ctx_pro_host_protocol::JournalFinishActivity {
                worker_limit: 1,
                peak_workers: 1,
                started_after_preparation: true,
            },
        }),
        access: ProAccessStatus {
            entitlement: ProAccessState::Available,
            graph_key: ProAccessState::Available,
            local_repository: ProAccessState::Available,
        },
        available_operations: if coverage == MaterializedCoverage::Complete {
            supported_operations.clone()
        } else {
            BTreeSet::new()
        },
        supported_operations,
    }
}

fn empty_commit_result(snapshot: QuerySnapshotExpectation) -> BlameResult {
    BlameResult {
        snapshot,
        target: ResolvedBlameTarget::Commit {
            commit: ResourceRef {
                id: "commit:0123456789abcdef".to_owned(),
                kind: ResourceKind::Commit,
                display: "0123456789abcdef".to_owned(),
            },
            repository: ResourceRef {
                id: "repository:fixture".to_owned(),
                kind: ResourceKind::Repository,
                display: "fixture/repository".to_owned(),
            },
        },
        git_snapshot: None,
        outcome: BlameOutcome {
            attribution: BlameAttribution::None,
            coverage: BlameCoverage {
                unit: BlameCoverageUnit::CommitFact,
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
    }
}

#[test]
fn blame_capabilities_require_git_only_for_file_targets() {
    assert_eq!(
        required_blame_capabilities(&BlameTarget::File {
            path: "src/lib.rs".to_owned(),
            repository: None,
            lines: None,
        }),
        BTreeSet::from([Capability::Status, Capability::Query, Capability::GitRead])
    );
    assert_eq!(
        required_blame_capabilities(&BlameTarget::Commit {
            oid: "0123456789abcdef".to_owned(),
            repository: None,
        }),
        BTreeSet::from([Capability::Status, Capability::Query])
    );
}

#[test]
fn every_helper_session_requires_the_current_protocol_fingerprint() {
    let core = BTreeSet::from([Capability::Status, Capability::CoreMaterialization]);
    for fingerprint in [
        "0a5db03b653a8effa18ff3ef6a275b085f3e68eedf7d3f982ac18d4a6c38b642",
        "dd902ae952032e66fcdaabcdc84522bde4350dace2bca28b9b16e67ffe6ef2fd",
    ] {
        let error = super::transport::validate_protocol_session(&core, fingerprint).unwrap_err();
        assert!(error
            .to_string()
            .contains("requires the current Protocol V3 fingerprint"));
    }
    super::transport::validate_protocol_session(&core, PROTOCOL_FINGERPRINT).unwrap();

    let query = BTreeSet::from([Capability::Status, Capability::Query]);
    assert!(super::transport::validate_protocol_session(
        &query,
        "0a5db03b653a8effa18ff3ef6a275b085f3e68eedf7d3f982ac18d4a6c38b642",
    )
    .is_err());
}

#[test]
fn protocol_v2_hello_is_rejected_by_the_exact_v3_handshake() {
    let hello = HelloResult {
        protocol_version: 2,
        protocol_fingerprint: PROTOCOL_FINGERPRINT.to_owned(),
        helper_version: "legacy-helper".to_owned(),
        capabilities: BTreeSet::from([Capability::Status]),
        authorization_challenge_base64url: String::new(),
    };
    let error =
        super::transport::validate_hello_identity(&hello, PROTOCOL_FINGERPRINT).unwrap_err();
    assert!(error.to_string().contains("exact Protocol V3 inventory"));
}

#[test]
fn blame_request_is_bound_to_the_exact_core_receipt() {
    let status = status(MaterializedCoverage::Complete);
    let request = support::current_blame_request(
        BlameTarget::Commit {
            oid: "0123456789abcdef".to_owned(),
            repository: None,
        },
        10,
        None,
        &status,
        &"a".repeat(64),
    )
    .unwrap();
    let ctx_pro_host_protocol::QuerySnapshotExpectation::Core { receipt } =
        request.expected_snapshot;
    assert_eq!(receipt.core_generation_id, "a".repeat(64));
}

#[test]
fn unscoped_status_keeps_the_prior_active_snapshot_queryable() {
    let mut finalizing = status(MaterializedCoverage::Complete);
    finalizing.currentness = CoreProjectionCurrentness::Finalizing;
    finalizing.requested_core_generation_id = Some("b".repeat(64));
    finalizing.finalization_progress = Some(CoreMaterializationFinalizationProgress {
        materialization_id: "c".repeat(64),
        core_generation_id: "b".repeat(64),
        finish_request_digest: "d".repeat(64),
        materializer_revision: "materializer-v1".to_owned(),
        phase: CoreMaterializationFinalizationPhase::EmitReplay,
        cursor_sha256: "e".repeat(64),
    });
    finalizing.validate().unwrap();

    let status = helper_status_with(None, &mut |message, _| {
        let HostMessage::Status(request) = message else {
            panic!("unscoped helper status must send Status")
        };
        assert!(request.requested_core_generation_id.is_none());
        Ok(HelperMessage::Status(finalizing.clone()))
    })
    .unwrap();
    let generation = blame_core_generation(&status, None).unwrap();

    let request = support::current_blame_request(
        BlameTarget::Commit {
            oid: "0123456789abcdef".to_owned(),
            repository: None,
        },
        10,
        None,
        &status,
        &generation,
    )
    .unwrap();
    let QuerySnapshotExpectation::Core { receipt } = request.expected_snapshot;
    assert_eq!(receipt.core_generation_id, "a".repeat(64));

    let wait_error = support::current_blame_request(
        BlameTarget::Commit {
            oid: "0123456789abcdef".to_owned(),
            repository: None,
        },
        10,
        None,
        &status,
        &"b".repeat(64),
    )
    .unwrap_err();
    assert_eq!(stable_error_code(&wait_error), Some("stale_source"));
}

#[test]
fn client_rejects_an_empty_result_from_another_materializer_revision_before_rendering() {
    let status = status(MaterializedCoverage::Complete);
    let request = support::current_blame_request(
        BlameTarget::Commit {
            oid: "0123456789abcdef".to_owned(),
            repository: None,
        },
        10,
        None,
        &status,
        &"a".repeat(64),
    )
    .unwrap();
    let matching = empty_commit_result(request.expected_snapshot.clone());
    validate_blame_response(&request, &matching).unwrap();

    let mut mismatched = matching;
    let QuerySnapshotExpectation::Core { receipt } = &mut mismatched.snapshot;
    receipt.materializer_revision = "materializer-v2".to_owned();
    let error = validate_blame_response(&request, &mismatched).unwrap_err();
    assert_eq!(stable_error_code(&error), Some("invalid_response"));
    assert!(error
        .to_string()
        .contains("blame result snapshot does not match the requested Core snapshot"));
}

#[test]
fn terminal_quiet_status_is_current_materialized_and_not_blame_ready() {
    for coverage in [MaterializedCoverage::Empty, MaterializedCoverage::Abstained] {
        let status = status(coverage);
        status.validate().unwrap();
        assert_eq!(
            super::client_status::status_outcome(&status, None, &"a".repeat(64)),
            (false, true, None),
            "{coverage:?}"
        );
        let error = support::current_blame_request(
            BlameTarget::Commit {
                oid: "0123456789abcdef".to_owned(),
                repository: None,
            },
            10,
            None,
            &status,
            &"a".repeat(64),
        )
        .unwrap_err();
        assert_eq!(
            stable_error_code(&error),
            Some("not_materialized"),
            "{coverage:?}"
        );
    }
}

#[test]
fn current_helper_receipt_is_ready_for_the_active_core_generation() {
    let current = status(MaterializedCoverage::Complete);

    assert_eq!(
        super::client_status::status_outcome(&current, None, &"a".repeat(64)),
        (true, true, None)
    );
}

#[test]
fn invalid_status_contradiction_fails_closed() {
    let mut contradictory = status(MaterializedCoverage::Complete);
    contradictory.core_receipt = None;
    assert!(contradictory.validate().is_err());

    assert_eq!(
        super::client_status::status_outcome(&contradictory, None, &"a".repeat(64)),
        (false, false, Some("protocol_mismatch"))
    );
}

#[test]
fn malformed_current_receipt_fails_closed_as_a_protocol_mismatch() {
    let mut malformed = status(MaterializedCoverage::Complete);
    malformed.requested_core_generation_id = Some("d".repeat(64));
    malformed.core_receipt.as_mut().unwrap().core_generation_id = "malformed".to_owned();

    assert_eq!(
        super::client_status::status_outcome(&malformed, None, &"d".repeat(64)),
        (false, false, Some("protocol_mismatch"))
    );
}

#[test]
fn status_rejects_a_current_receipt_for_a_stale_core_generation() {
    let mut stale = status(MaterializedCoverage::Complete);
    stale.requested_core_generation_id = Some("d".repeat(64));

    assert_eq!(
        super::client_status::status_outcome(&stale, None, &"d".repeat(64)),
        (false, false, Some("stale_source"))
    );
}

#[test]
fn status_preserves_explicit_stale_currentness_for_the_pinned_generation() {
    let mut stale = status(MaterializedCoverage::Complete);
    stale.currentness = CoreProjectionCurrentness::Stale;
    stale.requested_core_generation_id = Some("d".repeat(64));
    stale.coverage = MaterializedCoverage::Partial;
    stale.repository_coverage = RepositoryCoverage::default();
    stale.available_operations.clear();

    assert_eq!(
        super::client_status::status_outcome(&stale, None, &"d".repeat(64)),
        (false, false, Some("stale_source"))
    );
}

#[test]
fn missing_helper_status_does_not_require_an_active_core_generation() {
    let temp = tempfile::tempdir().unwrap();
    let status =
        super::client_status::status_with_helper_resolver(&MissingPinHost, temp.path(), |_| {
            bail!("pro_not_installed: helper fixture is absent")
        });

    assert!(!status.installed);
    assert!(!status.ready);
    assert!(!status.materialized);
    assert_eq!(status.error_code.as_deref(), Some("pro_not_installed"));
}

#[test]
fn installed_status_fails_closed_when_active_core_cannot_be_pinned() {
    let temp = tempfile::tempdir().unwrap();
    let status =
        super::client_status::status_with_helper_resolver(&MissingPinHost, temp.path(), |_| {
            Ok(temp.path().join("ctx-pro"))
        });

    assert!(status.installed);
    assert!(!status.ready);
    assert!(!status.materialized);
    assert_eq!(status.error_code.as_deref(), Some("source_unavailable"));
    assert!(status.projection_currentness.is_none());
    assert!(status.materialized_coverage.is_none());
    assert!(status.supported_operations.is_none());
    assert!(status.available_operations.is_none());
}

#[cfg(unix)]
#[test]
fn active_core_pin_lifetime_covers_the_complete_status_exchange() {
    let temp = tempfile::tempdir().unwrap();
    let data_root = temp.path().join("data");
    fs::create_dir(&data_root).unwrap();
    let helper_path = temp.path().join("status-helper.py");
    let request_path = temp.path().join("status-requested");
    let release_path = temp.path().join("release-status");
    write_blocking_status_helper(&helper_path, &request_path, &release_path);

    let pin_dropped = Arc::new(AtomicBool::new(false));
    let host = Arc::new(PinLifetimeHost {
        helper_path: helper_path.clone(),
        pin_dropped: Arc::clone(&pin_dropped),
    });
    let status_thread = {
        let host = Arc::clone(&host);
        let data_root = data_root.clone();
        thread::spawn(move || {
            super::client_status::status_with_helper_resolver(
                host.as_ref(),
                &data_root,
                |_| Ok(helper_path),
            )
        })
    };

    for _ in 0..300 {
        if request_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let request_received = request_path.exists();
    if request_received {
        assert_eq!(fs::read_to_string(&request_path).unwrap(), "a".repeat(64));
    }
    let pin_live_during_request = !pin_dropped.load(Ordering::SeqCst);
    fs::write(&release_path, b"release").unwrap();
    let result = status_thread.join().unwrap();
    assert!(
        request_received,
        "helper never received the status request: {result:?}"
    );
    assert!(
        pin_live_during_request,
        "active Core generation pin dropped while the helper held the status request"
    );
    assert!(result.materialized);
    assert_eq!(
        result.projection_currentness,
        Some(CoreProjectionCurrentness::Current)
    );
    assert!(
        pin_dropped.load(Ordering::SeqCst),
        "active Core generation pin was not released after status completed"
    );
}

#[test]
fn stale_core_receipt_fails_closed() {
    let status = status(MaterializedCoverage::Complete);
    let error = support::current_blame_request(
        BlameTarget::Commit {
            oid: "0123456789abcdef".to_owned(),
            repository: None,
        },
        10,
        None,
        &status,
        &"d".repeat(64),
    )
    .unwrap_err();
    assert_eq!(stable_error_code(&error), Some("stale_source"));
}

#[test]
fn default_blame_policy_reads_latest_committed_without_waiting() {
    let wake_calls = AtomicUsize::new(0);
    let expected_active_generation = prepare_blame_freshness_with(
        BlameFreshnessPolicy::LatestCommitted,
        || {
            wake_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        || panic!("ordinary blame must not synchronously wait"),
    )
    .unwrap();
    assert_eq!(expected_active_generation, None);
    assert_eq!(wake_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn latest_committed_blame_ignores_a_failed_background_wake() {
    let expected_active_generation = prepare_blame_freshness_with(
        BlameFreshnessPolicy::LatestCommitted,
        || bail!("source_unavailable: daemon is unavailable"),
        || panic!("ordinary blame must not synchronously wait"),
    )
    .unwrap();
    assert_eq!(expected_active_generation, None);
}

#[test]
fn latest_committed_blame_uses_the_helpers_trailing_receipt() {
    let status = status(MaterializedCoverage::Complete);
    let generation = blame_core_generation(&status, None).unwrap();
    assert_eq!(generation, "a".repeat(64));
    support::current_blame_request(
        BlameTarget::Commit {
            oid: "0123456789abcdef".to_owned(),
            repository: None,
        },
        10,
        None,
        &status,
        &generation,
    )
    .unwrap();
}

#[test]
fn explicit_wait_policy_uses_the_wait_path() {
    let generation = prepare_blame_freshness_with(
        BlameFreshnessPolicy::WaitForCurrent,
        || panic!("wait policy must not read latest-only state"),
        || Ok("b".repeat(64)),
    )
    .unwrap();
    assert_eq!(generation, Some("b".repeat(64)));
}

#[test]
fn core_advance_during_blame_returns_typed_stale_source() {
    let error =
        ensure_active_core_generation_is_unchanged(&"a".repeat(64), &"b".repeat(64)).unwrap_err();
    assert_eq!(stable_error_code(&error), Some("stale_source"));
}

#[test]
fn blame_freshness_accepts_only_current_or_fully_positive_stale_coverage() {
    let outcome = |attribution, proven, possible, conflicting, none| BlameOutcome {
        attribution,
        coverage: BlameCoverage {
            unit: BlameCoverageUnit::CommitFact,
            evaluated: proven + possible + conflicting + none,
            proven,
            possible,
            conflicting,
            none,
        },
    };
    let current_none = outcome(BlameAttribution::None, 0, 0, 0, 0);
    assert_eq!(
        classify_blame_snapshot_freshness("a", &current_none, "a", "a").unwrap(),
        BlameResultFreshness::Current
    );

    for positive in [
        outcome(BlameAttribution::Proven, 1, 0, 0, 0),
        outcome(BlameAttribution::Possible, 1, 1, 0, 0),
        outcome(BlameAttribution::Conflicting, 1, 0, 1, 0),
    ] {
        assert_eq!(
            classify_blame_snapshot_freshness("a", &positive, "b", "b").unwrap(),
            BlameResultFreshness::StaleCommitted
        );
    }

    for stale_miss in [
        outcome(BlameAttribution::None, 0, 0, 0, 1),
        outcome(BlameAttribution::Possible, 1, 0, 0, 1),
    ] {
        let error = classify_blame_snapshot_freshness("a", &stale_miss, "b", "b").unwrap_err();
        assert_eq!(stable_error_code(&error), Some("stale_source"));
    }
}

#[test]
fn stale_generation_bound_failure_becomes_one_typed_stale_diagnostic() {
    let error = protocol_blame_error(
        ProtocolError::new(ErrorClass::ResourceNotFound, "ignored helper detail")
            .with_blame_details(ctx_pro_host_protocol::BlameDiagnosticDetails {
                reason: ctx_pro_host_protocol::BlameDiagnosticReason::TargetNotIndexed,
                candidates: Vec::new(),
                candidates_truncated: false,
            }),
        &BlameTarget::Commit {
            oid: "a".repeat(40),
            repository: None,
        },
    );
    assert!(is_generation_bound_negative(&error));

    let stale = stale_negative_diagnostic();
    let diagnostic = blame_diagnostic(&stale).unwrap();
    assert_eq!(diagnostic.error_code, "stale_source");
    assert!(diagnostic.retryable);
    assert!(diagnostic.candidates.is_empty());
    assert_ne!(
        diagnostic.next_action.as_ref().map(|action| action.kind),
        Some(crate::diagnostic::BlameNextActionKind::SearchCore)
    );

    let entitlement = protocol_blame_error(
        ProtocolError::new(ErrorClass::EntitlementExpired, "ignored helper detail"),
        &BlameTarget::Commit {
            oid: "a".repeat(40),
            repository: None,
        },
    );
    assert!(!is_generation_bound_negative(&entitlement));
}

#[test]
fn pro_receipt_advance_during_blame_returns_typed_stale_source() {
    let mut advanced = status(MaterializedCoverage::Complete);
    advanced.requested_core_generation_id = None;
    advanced.core_receipt = Some(receipt('b'));
    let error = ensure_committed_pro_receipt_is_unchanged(&receipt('a'), &advanced).unwrap_err();
    assert_eq!(stable_error_code(&error), Some("stale_source"));
}

#[test]
fn unchanged_pro_receipt_after_blame_is_accepted() {
    let status = status(MaterializedCoverage::Complete);
    ensure_committed_pro_receipt_is_unchanged(&receipt('a'), &status).unwrap();
}

#[test]
fn missing_pro_receipt_after_blame_fails_closed() {
    let mut missing = status(MaterializedCoverage::Complete);
    missing.currentness = CoreProjectionCurrentness::NotMaterialized;
    missing.requested_core_generation_id = None;
    missing.core_receipt = None;
    missing.coverage = MaterializedCoverage::NotMaterialized;
    missing.repository_coverage = RepositoryCoverage::default();
    missing.available_operations.clear();
    missing.storage_evidence = None;
    let error = ensure_committed_pro_receipt_is_unchanged(&receipt('a'), &missing).unwrap_err();
    assert_eq!(stable_error_code(&error), Some("stale_source"));
}

#[test]
fn incoherent_pro_receipt_after_blame_fails_closed() {
    let mut incoherent = status(MaterializedCoverage::Complete);
    incoherent.core_receipt = None;
    let error = ensure_committed_pro_receipt_is_unchanged(&receipt('a'), &incoherent).unwrap_err();
    assert_eq!(stable_error_code(&error), Some("invalid_response"));
}
