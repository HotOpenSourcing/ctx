use std::{
    cmp::Ordering,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use ctx_history_core::platform_security::{
    restrict_private_directory, restrict_private_executable, restrict_private_file,
    verify_private_directory,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::artifact_delivery::VerifiedArtifactBundle;
use crate::installed_artifact::{
    inspect_pair_at, installation_artifacts_present, load_pair_at, open_validated_pair_identity,
    read_candidate, read_validated_artifact, setup_repair_required, validate_pair_bytes,
    PairIdentity, PairInspection, ValidatedArtifactIdentity, ValidatedPair,
};
use crate::operation::LifecycleOperation;
use crate::release_manifest::{
    parse_release_version, validate_manifest_release_trust, verified_manifest_for_trust,
    ProInstallMarker, ProManifest, ReleaseTrust, MAX_ARTIFACT_BYTES, MAX_INSTALL_MARKER_BYTES,
};
#[cfg(test)]
use crate::release_manifest::{
    platform_target, verified_manifest, verify_signature_with_key, MAX_MANIFEST_BYTES,
    MAX_SIGNATURE_BYTES, PRO_RELEASE_STAGING_PUBLIC_KEY_PEM,
};

const MAX_TRANSACTION_JOURNAL_BYTES: u64 = 16 * 1024;

use crate::operation::{
    install_marker_path, layout_for_target, previous_helper_path, previous_marker_path,
    publish_helper_path, publish_marker_path, rollback_helper_stage_path,
    rollback_marker_stage_path, transaction_helper_path, transaction_journal_next_path,
    transaction_journal_path, transaction_marker_path, validate_private_directory,
};

#[path = "installation/persistence.rs"]
mod persistence;
use persistence::{
    cleanup_transaction_files, durable_write, prepare_install_directory,
    protect_existing_installation, publish_current, publish_previous, remove_current_pair,
    sync_install_directory, write_journal,
};
pub use persistence::{replace_file, sync_parent_directory};

/// A fully downloaded release bundle. Artifact delivery owns construction of
/// this value; lifecycle only feeds it to the transactional installer.
#[derive(Debug, Clone)]
#[cfg(test)]
pub struct ProInstallArgs {
    artifact: PathBuf,
    manifest: PathBuf,
    signature: PathBuf,
}

#[cfg(test)]
impl ProInstallArgs {
    pub fn new(artifact: PathBuf, manifest: PathBuf, signature: PathBuf) -> Self {
        Self {
            artifact,
            manifest,
            signature,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InstallTransaction {
    schema_version: u32,
    transaction_id: Uuid,
    state: TransactionState,
    old: Option<PairIdentity>,
    new: PairIdentity,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TransactionState {
    Preparing,
    Committed,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SetupInstallation {
    Current(ValidatedPair),
    Missing,
    RepairRequired,
}

impl SetupInstallation {
    pub fn installed_version(&self) -> Option<&str> {
        match self {
            Self::Current(pair) => Some(pair.manifest.version.as_str()),
            Self::Missing | Self::RepairRequired => None,
        }
    }

    pub fn is_repair_required(&self) -> bool {
        matches!(self, Self::RepairRequired)
    }

    fn into_current(self) -> Option<ValidatedPair> {
        match self {
            Self::Current(pair) => Some(pair),
            Self::Missing | Self::RepairRequired => None,
        }
    }
}

#[derive(Default)]
struct Persistence {
    #[cfg(test)]
    crash_after: Option<usize>,
    #[cfg(test)]
    boundaries: Vec<&'static str>,
    #[cfg(test)]
    hard_exit: bool,
}

impl Persistence {
    fn boundary(&mut self, name: &'static str) -> Result<()> {
        #[cfg(test)]
        {
            self.boundaries.push(name);
            if self.crash_after == Some(self.boundaries.len()) {
                if self.hard_exit {
                    std::process::exit(86);
                }
                bail!("simulated_termination: {name}");
            }
        }
        #[cfg(not(test))]
        let _ = name;
        Ok(())
    }
}

pub fn acquire_commercial_lifecycle_lock(
    data_root: &Path,
    create_pro_root: bool,
) -> Result<Option<LifecycleOperation>> {
    LifecycleOperation::begin(data_root, create_pro_root)
}

pub fn discover_installed_artifact(
    data_root: &Path,
    trust: ReleaseTrust,
) -> Result<ValidatedArtifactIdentity> {
    if !installation_artifacts_present(data_root) {
        bail!("pro_not_installed: signed Pro helper is not installed");
    }
    let operation = LifecycleOperation::begin(data_root, false)?
        .ok_or_else(|| anyhow!("pro_not_installed: signed Pro helper is not installed"))?;
    discover_installed_artifact_in(&operation, trust)
}

pub fn discover_installed_artifact_in(
    operation: &LifecycleOperation,
    trust: ReleaseTrust,
) -> Result<ValidatedArtifactIdentity> {
    let data_root = operation.data_root();
    let target = default_helper_path(data_root);
    if !installation_artifacts_present(data_root) {
        bail!("pro_not_installed: signed Pro helper is not installed");
    }
    let pair =
        reconcile_installation_locked(&target, trust.public_key_pem, &mut Persistence::default())?
            .ok_or_else(|| anyhow!("pro_not_installed: signed Pro helper is not installed"))?;
    validate_manifest_release_trust(&pair.manifest, trust)?;
    let marker_path = install_marker_path(&target)?;
    open_validated_pair_identity(operation, &target, &marker_path, &pair, trust)
}

#[cfg(test)]
fn validated_installed_helper_path_with_key(
    data_root: &Path,
    public_key_pem: &str,
) -> Result<PathBuf> {
    let target = default_helper_path(data_root);
    reconcile_installation(&target, public_key_pem, &mut Persistence::default())?
        .ok_or_else(|| anyhow!("pro_not_installed: signed Pro helper is not installed"))?;
    Ok(target)
}

pub trait InstallRecheckPort {
    fn publish_recheck_intent(&self, data_root: &Path, artifact_sha256: &str) -> Result<()>;
    fn recheck_targets(&self, data_root: &Path, artifact_sha256: &str) -> Result<bool>;
    fn wake_recheck(&self, data_root: &Path);
}

#[cfg(test)]
struct NoopInstallRecheck;

#[cfg(test)]
impl InstallRecheckPort for NoopInstallRecheck {
    fn publish_recheck_intent(&self, _data_root: &Path, _artifact_sha256: &str) -> Result<()> {
        Ok(())
    }

    fn recheck_targets(&self, _data_root: &Path, _artifact_sha256: &str) -> Result<bool> {
        Ok(false)
    }

    fn wake_recheck(&self, _data_root: &Path) {}
}

pub fn install_verified_bundle(
    bundle: &VerifiedArtifactBundle,
    operation: &LifecycleOperation,
    trust: ReleaseTrust,
    recheck: &dyn InstallRecheckPort,
) -> Result<serde_json::Value> {
    let data_root = operation.data_root();
    let target = default_helper_path(data_root);
    let installation = reconcile_setup_installation_locked(
        &target,
        trust.public_key_pem,
        &mut Persistence::default(),
    )?;
    if let SetupInstallation::Current(current) = &installation {
        validate_manifest_release_trust(&current.manifest, trust)?;
    }
    let manifest =
        verified_manifest_for_trust(bundle.manifest_bytes(), bundle.signature_bytes(), trust)?;
    let artifact = read_validated_artifact(bundle.identity())?;
    install_for_setup_bytes_locked(
        data_root,
        installation,
        artifact,
        bundle.manifest_bytes(),
        bundle.signature_bytes(),
        manifest,
        trust.public_key_pem,
        recheck,
        &mut Persistence::default(),
    )
}

#[cfg(test)]
fn install_with_key(
    args: &ProInstallArgs,
    data_root: &Path,
    require_existing: bool,
    public_key_pem: &str,
    recheck: &dyn InstallRecheckPort,
    persistence: &mut Persistence,
) -> Result<serde_json::Value> {
    let _operation = LifecycleOperation::begin(data_root, true)?
        .ok_or_else(|| anyhow!("invalid_request: failed to create Pro lifecycle lock"))?;
    install_with_key_locked(
        args,
        data_root,
        require_existing,
        public_key_pem,
        recheck,
        persistence,
    )
}

#[cfg(test)]
fn install_with_key_locked(
    args: &ProInstallArgs,
    data_root: &Path,
    require_existing: bool,
    public_key_pem: &str,
    recheck: &dyn InstallRecheckPort,
    persistence: &mut Persistence,
) -> Result<serde_json::Value> {
    let target = default_helper_path(data_root);
    let current = reconcile_installation_locked(&target, public_key_pem, persistence)?;
    if require_existing && current.is_none() {
        bail!("pro_not_installed: install Pro before updating it");
    }
    if !require_existing && current.is_some() {
        bail!("invalid_request: Pro is already installed; use ctx pro update");
    }
    install_candidate_with_key_locked(
        args,
        data_root,
        current.as_ref(),
        require_existing,
        public_key_pem,
        recheck,
        persistence,
    )
}

#[cfg(test)]
fn install_for_setup_with_key_locked(
    args: &ProInstallArgs,
    data_root: &Path,
    installation: SetupInstallation,
    public_key_pem: &str,
    persistence: &mut Persistence,
) -> Result<serde_json::Value> {
    let replacing_existing =
        installation.is_repair_required() || matches!(&installation, SetupInstallation::Current(_));
    let current = installation.into_current();
    install_candidate_with_key_locked(
        args,
        data_root,
        current.as_ref(),
        replacing_existing,
        public_key_pem,
        &NoopInstallRecheck,
        persistence,
    )
}

#[cfg(test)]
fn install_candidate_with_key_locked(
    args: &ProInstallArgs,
    data_root: &Path,
    current: Option<&ValidatedPair>,
    replacing_existing: bool,
    public_key_pem: &str,
    recheck: &dyn InstallRecheckPort,
    persistence: &mut Persistence,
) -> Result<serde_json::Value> {
    let manifest_bytes = read_bounded(&args.manifest, MAX_MANIFEST_BYTES, "manifest")?;
    let signature = read_bounded(&args.signature, MAX_SIGNATURE_BYTES, "signature")?;
    let manifest = verified_manifest(&manifest_bytes, &signature, public_key_pem)?;
    let artifact = read_bounded(&args.artifact, MAX_ARTIFACT_BYTES, "artifact")?;
    install_candidate_bytes_locked(
        data_root,
        current,
        replacing_existing,
        artifact,
        &manifest_bytes,
        &signature,
        manifest,
        public_key_pem,
        recheck,
        persistence,
    )
}

#[allow(clippy::too_many_arguments)]
fn install_for_setup_bytes_locked(
    data_root: &Path,
    installation: SetupInstallation,
    artifact: Vec<u8>,
    manifest_bytes: &[u8],
    signature: &[u8],
    manifest: ProManifest,
    public_key_pem: &str,
    recheck: &dyn InstallRecheckPort,
    persistence: &mut Persistence,
) -> Result<serde_json::Value> {
    let replacing_existing =
        installation.is_repair_required() || matches!(&installation, SetupInstallation::Current(_));
    let current = installation.into_current();
    install_candidate_bytes_locked(
        data_root,
        current.as_ref(),
        replacing_existing,
        artifact,
        manifest_bytes,
        signature,
        manifest,
        public_key_pem,
        recheck,
        persistence,
    )
}

#[allow(clippy::too_many_arguments)]
fn install_candidate_bytes_locked(
    data_root: &Path,
    current: Option<&ValidatedPair>,
    replacing_existing: bool,
    artifact: Vec<u8>,
    manifest_bytes: &[u8],
    signature: &[u8],
    manifest: ProManifest,
    public_key_pem: &str,
    recheck: &dyn InstallRecheckPort,
    persistence: &mut Persistence,
) -> Result<serde_json::Value> {
    let target = default_helper_path(data_root);
    if let Some(current) = current {
        validate_update(current, &manifest)?;
    }
    if artifact.len() as u64 != manifest.artifact_size {
        bail!("invalid_response: Pro artifact size does not match signed manifest");
    }
    let actual = format!("{:x}", Sha256::digest(&artifact));
    if !actual.eq_ignore_ascii_case(&manifest.artifact_sha256) {
        bail!("invalid_response: Pro artifact digest does not match signed manifest");
    }
    let marker = ProInstallMarker::new(&manifest_bytes, &signature)?;
    let marker_bytes = serde_json::to_vec(&marker)
        .context("invalid_response: encode signed Pro install marker")?;
    let new_identity = PairIdentity::new(&artifact, &marker_bytes, &manifest);
    let helper_changed = current
        .map(|current| current.identity != new_identity)
        .unwrap_or(true);
    if helper_changed {
        persistence.boundary("before_publish_pro_recheck_intent")?;
        recheck.publish_recheck_intent(data_root, &new_identity.artifact_sha256)?;
        persistence.boundary("after_publish_pro_recheck_intent")?;
    }
    let recheck_wake_required =
        helper_changed || recheck.recheck_targets(data_root, &new_identity.artifact_sha256)?;
    install_transaction_locked(
        &target,
        current,
        &artifact,
        &marker_bytes,
        new_identity,
        public_key_pem,
        persistence,
    )?;
    if recheck_wake_required {
        persistence.boundary("after_install_before_pro_recheck_wake")?;
        recheck.wake_recheck(data_root);
        persistence.boundary("after_pro_recheck_wake")?;
    }
    Ok(json!({
        "schema_version": 1,
        "installed": true,
        "updated": replacing_existing,
        "version": manifest.version,
        "source_commit": manifest.source_commit,
        "helper_path": target,
    }))
}

fn read_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("invalid_request: inspect {label}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("invalid_request: {label} must be a regular non-symlink file");
    }
    if metadata.len() > maximum {
        bail!("invalid_request: {label} exceeds maximum size {maximum}");
    }
    fs::read(path).with_context(|| format!("invalid_request: read {label}"))
}

fn validate_update(current: &ValidatedPair, next: &ProManifest) -> Result<()> {
    let current_version = parse_release_version(&current.manifest.version)?;
    let next_version = parse_release_version(&next.version)?;
    match next_version.cmp(&current_version) {
        Ordering::Less => {
            bail!("invalid_request: Pro update would roll back the installed version")
        }
        Ordering::Equal
            if !next
                .artifact_sha256
                .eq_ignore_ascii_case(&current.identity.artifact_sha256) =>
        {
            bail!("invalid_request: Pro update reuses a version with different contents")
        }
        _ => Ok(()),
    }
}

fn install_transaction_locked(
    target: &Path,
    current: Option<&ValidatedPair>,
    artifact: &[u8],
    marker: &[u8],
    new_identity: PairIdentity,
    public_key_pem: &str,
    persistence: &mut Persistence,
) -> Result<()> {
    prepare_install_directory(target, persistence)?;
    let mut transaction = InstallTransaction {
        schema_version: 1,
        transaction_id: Uuid::new_v4(),
        state: TransactionState::Preparing,
        old: current.map(|pair| pair.identity.clone()),
        new: new_identity,
    };
    write_journal(target, &transaction, persistence)?;
    durable_write(
        &transaction_helper_path(target)?,
        artifact,
        0o700,
        persistence,
        "write_transaction_helper",
        "chmod_transaction_helper",
        "fsync_transaction_helper",
    )?;
    durable_write(
        &transaction_marker_path(target)?,
        marker,
        0o600,
        persistence,
        "write_transaction_marker",
        "chmod_transaction_marker",
        "fsync_transaction_marker",
    )?;
    sync_install_directory(target, persistence, "fsync_staged_transaction_directory")?;
    transaction.state = TransactionState::Committed;
    write_journal(target, &transaction, persistence)?;
    let installed = reconcile_installation_locked(target, public_key_pem, persistence)?
        .ok_or_else(|| {
            anyhow!("invalid_response: committed Pro transaction produced no installed helper")
        })?;
    if installed.identity != transaction.new {
        bail!("invalid_response: committed Pro transaction published the wrong signed pair");
    }
    let final_pair = load_pair_at(target, &install_marker_path(target)?, public_key_pem)?
        .ok_or_else(|| anyhow!("invalid_response: final signed Pro helper pair is missing"))?;
    if final_pair.identity != transaction.new {
        bail!("invalid_response: final signed Pro helper pair verification failed");
    }
    Ok(())
}

#[cfg(test)]
fn reconcile_installation(
    target: &Path,
    public_key_pem: &str,
    persistence: &mut Persistence,
) -> Result<Option<ValidatedPair>> {
    let Some(_operation) = LifecycleOperation::acquire(target, false)? else {
        return Ok(None);
    };
    reconcile_installation_locked(target, public_key_pem, persistence)
}

fn reconcile_setup_installation_locked(
    target: &Path,
    public_key_pem: &str,
    persistence: &mut Persistence,
) -> Result<SetupInstallation> {
    reconcile_installation_locked_with_setup_repair(target, public_key_pem, persistence, true)
}

pub fn reconcile_setup_installation(
    operation: &LifecycleOperation,
    trust: ReleaseTrust,
) -> Result<SetupInstallation> {
    let target = default_helper_path(operation.data_root());
    let installation = reconcile_setup_installation_locked(
        &target,
        trust.public_key_pem,
        &mut Persistence::default(),
    )?;
    if let SetupInstallation::Current(current) = &installation {
        validate_manifest_release_trust(&current.manifest, trust)?;
    }
    Ok(installation)
}

/// Removes the complete helper/marker/transaction namespace while the caller
/// retains the lifecycle operation. Every candidate is verified absent before
/// the operation may complete.
pub fn remove_installation_artifacts(operation: &LifecycleOperation) -> Result<bool> {
    let data_root = operation.data_root();
    let target = default_helper_path(data_root);
    let candidates = [
        target.clone(),
        install_marker_path(&target)?,
        previous_helper_path(&target)?,
        previous_marker_path(&target)?,
        transaction_journal_path(&target)?,
        transaction_journal_next_path(&target)?,
        transaction_helper_path(&target)?,
        transaction_marker_path(&target)?,
        publish_helper_path(&target)?,
        publish_marker_path(&target)?,
        rollback_helper_stage_path(&target)?,
        rollback_marker_stage_path(&target)?,
    ];
    let mut removed = false;
    for candidate in &candidates {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                fs::remove_file(candidate).context("remove local Pro file")?;
                removed = true;
            }
            Ok(_) => bail!("invalid_request: a local Pro file path is not a file"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect local Pro file"),
        }
    }
    for candidate in &candidates {
        match candidate.symlink_metadata() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => bail!("invalid_request: failed to verify local Pro helper removal"),
            Err(error) => return Err(error).context("verify local Pro helper removal"),
        }
    }
    if let Some(bin) = target.parent() {
        let _ = fs::remove_dir(bin);
        if let Some(pro) = bin.parent() {
            let _ = fs::remove_dir(pro);
        }
    }
    Ok(removed)
}

fn reconcile_installation_locked(
    target: &Path,
    public_key_pem: &str,
    persistence: &mut Persistence,
) -> Result<Option<ValidatedPair>> {
    match reconcile_installation_locked_with_setup_repair(
        target,
        public_key_pem,
        persistence,
        false,
    )? {
        SetupInstallation::Current(pair) => Ok(Some(pair)),
        SetupInstallation::Missing => Ok(None),
        SetupInstallation::RepairRequired => Err(setup_repair_required(
            "invalid_response: installed Pro helper and marker do not form a trusted pair",
        )),
    }
}

fn reconcile_installation_locked_with_setup_repair(
    target: &Path,
    public_key_pem: &str,
    persistence: &mut Persistence,
    allow_setup_repair: bool,
) -> Result<SetupInstallation> {
    let Some(parent) = target.parent() else {
        bail!("invalid_request: Pro install path has no parent");
    };
    if !parent.exists() {
        return Ok(SetupInstallation::Missing);
    }
    protect_existing_installation(target)?;
    let journal_path = transaction_journal_path(target)?;
    if !journal_path.exists() {
        let current = inspect_pair_at(target, &install_marker_path(target)?, public_key_pem)?;
        let current_untrusted = current.is_untrusted();
        if let PairInspection::Valid(pair) = current {
            cleanup_transaction_files(target, persistence)?;
            return Ok(SetupInstallation::Current(pair));
        }
        let previous = inspect_pair_at(
            &previous_helper_path(target)?,
            &previous_marker_path(target)?,
            public_key_pem,
        )?;
        let previous_untrusted = previous.is_untrusted();
        if let PairInspection::Valid(previous) = previous {
            publish_current(target, &previous, public_key_pem, persistence)?;
            cleanup_transaction_files(target, persistence)?;
            return Ok(SetupInstallation::Current(previous));
        }
        if current_untrusted || previous_untrusted {
            if allow_setup_repair {
                return Ok(SetupInstallation::RepairRequired);
            }
            return Err(setup_repair_required(
                "invalid_response: installed Pro helper and marker do not form a trusted pair",
            ));
        }
        cleanup_transaction_files(target, persistence)?;
        return Ok(SetupInstallation::Missing);
    }

    let journal_bytes = read_bounded(
        &journal_path,
        MAX_TRANSACTION_JOURNAL_BYTES,
        "transaction journal",
    )?;
    let transaction: InstallTransaction = serde_json::from_slice(&journal_bytes)
        .context("invalid_response: parse Pro transaction journal")?;
    validate_transaction(&transaction)?;
    let old = transaction
        .old
        .as_ref()
        .map(|identity| find_pair(target, identity, public_key_pem))
        .transpose()?
        .flatten();
    let new = find_pair(target, &transaction.new, public_key_pem)?;

    let chosen = if transaction.state == TransactionState::Committed {
        new.as_ref().or(old.as_ref())
    } else {
        old.as_ref()
    };
    let Some(chosen) = chosen else {
        if transaction.state == TransactionState::Committed {
            if allow_setup_repair {
                let current =
                    inspect_pair_at(target, &install_marker_path(target)?, public_key_pem)?;
                if let PairInspection::Valid(current) = current {
                    cleanup_transaction_files(target, persistence)?;
                    return Ok(SetupInstallation::Current(current));
                }
                let previous = inspect_pair_at(
                    &previous_helper_path(target)?,
                    &previous_marker_path(target)?,
                    public_key_pem,
                )?;
                if let PairInspection::Valid(previous) = previous {
                    publish_current(target, &previous, public_key_pem, persistence)?;
                    cleanup_transaction_files(target, persistence)?;
                    return Ok(SetupInstallation::Current(previous));
                }
                return Ok(SetupInstallation::RepairRequired);
            }
            return Err(setup_repair_required(
                "invalid_response: Pro transaction contains no recoverable signed helper pair",
            ));
        }
        if transaction.old.is_none() && transaction.state == TransactionState::Preparing {
            remove_current_pair(target, persistence)?;
            cleanup_transaction_files(target, persistence)?;
            return Ok(SetupInstallation::Missing);
        }
        bail!("invalid_response: Pro transaction contains no recoverable signed helper pair");
    };

    if transaction.state == TransactionState::Committed && chosen.identity == transaction.new {
        if let Some(old) = old.as_ref() {
            publish_previous(target, old, public_key_pem, persistence)?;
        }
    }
    publish_current(target, chosen, public_key_pem, persistence)?;
    let installed = load_pair_at(target, &install_marker_path(target)?, public_key_pem)?
        .ok_or_else(|| anyhow!("invalid_response: recovered Pro helper pair is missing"))?;
    cleanup_transaction_files(target, persistence)?;
    Ok(SetupInstallation::Current(installed))
}

fn validate_transaction(transaction: &InstallTransaction) -> Result<()> {
    if transaction.schema_version != 1 || transaction.transaction_id.is_nil() {
        bail!("invalid_response: invalid Pro transaction journal identity");
    }
    validate_pair_identity(&transaction.new)?;
    if let Some(old) = &transaction.old {
        validate_pair_identity(old)?;
    }
    Ok(())
}

fn validate_pair_identity(identity: &PairIdentity) -> Result<()> {
    if identity.artifact_size == 0
        || identity.artifact_size > MAX_ARTIFACT_BYTES
        || !is_lower_hex_digest(&identity.artifact_sha256)
        || !is_lower_hex_digest(&identity.marker_sha256)
        || parse_release_version(&identity.version).is_err()
    {
        bail!("invalid_response: invalid Pro transaction pair identity");
    }
    Ok(())
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn find_pair(
    target: &Path,
    identity: &PairIdentity,
    public_key_pem: &str,
) -> Result<Option<ValidatedPair>> {
    let helper_paths = [
        target.to_path_buf(),
        previous_helper_path(target)?,
        transaction_helper_path(target)?,
        publish_helper_path(target)?,
        rollback_helper_stage_path(target)?,
    ];
    let marker_paths = [
        install_marker_path(target)?,
        previous_marker_path(target)?,
        transaction_marker_path(target)?,
        publish_marker_path(target)?,
        rollback_marker_stage_path(target)?,
    ];
    let mut artifacts = Vec::new();
    for path in &helper_paths {
        if let Some(bytes) = read_candidate(path, MAX_ARTIFACT_BYTES)? {
            artifacts.push(bytes);
        }
    }
    let mut markers = Vec::new();
    for path in &marker_paths {
        if let Some(bytes) = read_candidate(path, MAX_INSTALL_MARKER_BYTES)? {
            markers.push(bytes);
        }
    }
    let artifact = artifacts
        .into_iter()
        .find(|bytes| identity.matches_artifact(bytes));
    let marker = markers
        .into_iter()
        .find(|bytes| identity.matches_marker(bytes));
    let (Some(artifact), Some(marker)) = (artifact, marker) else {
        return Ok(None);
    };
    let Ok(pair) = validate_pair_bytes(artifact, marker, public_key_pem) else {
        return Ok(None);
    };
    if pair.identity != *identity {
        return Ok(None);
    }
    Ok(Some(pair))
}

#[cfg(test)]
#[path = "installation/tests.rs"]
mod tests;

fn default_helper_path(data_root: &Path) -> PathBuf {
    ctx_pro_host_protocol::ProFilesystemLayout::new(data_root).helper_path()
}
