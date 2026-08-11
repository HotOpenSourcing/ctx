use std::{
    fs,
    io::{Read as _, Seek as _, SeekFrom},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use ctx_pro_host_protocol::ProFilesystemLayout;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::operation::LifecycleOperation;
use crate::release_manifest::{
    validate_manifest_release_trust, ProInstallMarker, ProManifest, ReleaseTrust,
    MAX_ARTIFACT_BYTES, MAX_INSTALL_MARKER_BYTES,
};

/// Lifecycle-validated bytes and release identity retained for one host
/// execution. The host may inspect the open file's OS identity, but it must not
/// reopen or hash artifact bytes to establish release trust again.
#[derive(Clone)]
pub struct ValidatedArtifactIdentity {
    path: PathBuf,
    artifact_size: u64,
    artifact_sha256: String,
    manifest: ProManifest,
    artifact: Arc<fs::File>,
    operation: LifecycleOperation,
}

impl std::fmt::Debug for ValidatedArtifactIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedArtifactIdentity")
            .field("path", &self.path)
            .field("artifact_size", &self.artifact_size)
            .field("artifact_sha256", &self.artifact_sha256)
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}

impl ValidatedArtifactIdentity {
    pub(crate) fn new(
        path: PathBuf,
        artifact_size: u64,
        artifact_sha256: String,
        manifest: ProManifest,
        artifact: fs::File,
        operation: LifecycleOperation,
    ) -> Self {
        Self {
            path,
            artifact_size,
            artifact_sha256,
            manifest,
            artifact: Arc::new(artifact),
            operation,
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn artifact_sha256(&self) -> &str {
        &self.artifact_sha256
    }

    #[must_use]
    pub fn artifact_size(&self) -> u64 {
        self.artifact_size
    }

    #[must_use]
    pub fn manifest(&self) -> &ProManifest {
        &self.manifest
    }

    #[must_use]
    pub fn artifact_file(&self) -> &fs::File {
        &self.artifact
    }

    #[must_use]
    pub fn operation(&self) -> &LifecycleOperation {
        &self.operation
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn open_test_artifact_identity(
    operation: &LifecycleOperation,
    path: &Path,
) -> Result<ValidatedArtifactIdentity> {
    let artifact_file = open_candidate(path, MAX_ARTIFACT_BYTES, "test Pro helper")?;
    let (artifact_size, artifact_sha256) =
        digest_bounded_handle(&artifact_file, MAX_ARTIFACT_BYTES, "test Pro helper")?;
    let manifest = ProManifest {
        schema_version: 1,
        product: "ctx-pro".to_owned(),
        channel: "staging".to_owned(),
        version: "1.0.0".to_owned(),
        source_commit: "1".repeat(40),
        public_source_commit: "2".repeat(40),
        private_source_commit: "1".repeat(40),
        build_identity: "3".repeat(64),
        protocol_min: ctx_pro_host_protocol::PROTOCOL_VERSION,
        protocol_max: ctx_pro_host_protocol::PROTOCOL_VERSION,
        protocol_fingerprint: ctx_pro_host_protocol::PROTOCOL_FINGERPRINT.to_owned(),
        target: crate::release_manifest::platform_target(),
        architecture: std::env::consts::ARCH.to_owned(),
        artifact_object: "test/ctx-pro".to_owned(),
        artifact_size,
        artifact_sha256: artifact_sha256.clone(),
        public_artifact_sha256: "4".repeat(64),
        public_package_sha256: "5".repeat(64),
        private_package_sha256: "6".repeat(64),
        runtime_evidence_sha256: "7".repeat(64),
        runtime_run_id: "12345678-1234-4234-8234-123456789abc".to_owned(),
        release_key_id: "ctx-pro-release-staging-test".to_owned(),
    };
    Ok(ValidatedArtifactIdentity::new(
        path.to_path_buf(),
        artifact_size,
        artifact_sha256,
        manifest,
        artifact_file,
        operation.clone(),
    ))
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairIdentity {
    pub artifact_size: u64,
    pub artifact_sha256: String,
    pub marker_sha256: String,
    pub version: String,
}

impl PairIdentity {
    #[must_use]
    pub fn new(artifact: &[u8], marker: &[u8], manifest: &ProManifest) -> Self {
        Self {
            artifact_size: artifact.len() as u64,
            artifact_sha256: format!("{:x}", Sha256::digest(artifact)),
            marker_sha256: format!("{:x}", Sha256::digest(marker)),
            version: manifest.version.clone(),
        }
    }

    #[must_use]
    pub fn matches_artifact(&self, artifact: &[u8]) -> bool {
        artifact.len() as u64 == self.artifact_size
            && format!("{:x}", Sha256::digest(artifact)) == self.artifact_sha256
    }

    #[must_use]
    pub fn matches_marker(&self, marker: &[u8]) -> bool {
        format!("{:x}", Sha256::digest(marker)) == self.marker_sha256
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedPair {
    pub identity: PairIdentity,
    pub artifact: Vec<u8>,
    pub marker: Vec<u8>,
    pub manifest: ProManifest,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum PairInspection {
    Absent,
    Untrusted,
    Valid(ValidatedPair),
}

impl PairInspection {
    #[must_use]
    pub fn is_untrusted(&self) -> bool {
        matches!(self, Self::Untrusted)
    }
}

#[derive(Debug)]
struct SetupRepairRequiredError {
    message: &'static str,
}

impl std::fmt::Display for SetupRepairRequiredError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for SetupRepairRequiredError {}

#[must_use]
pub fn setup_repair_required(message: &'static str) -> anyhow::Error {
    anyhow::Error::new(SetupRepairRequiredError { message })
}

#[must_use]
pub fn is_setup_repair_required_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<SetupRepairRequiredError>().is_some()
}

/// Conservatively reports whether any installed-helper lifecycle artifact or
/// unsafe layout component is present beneath `data_root`.
#[must_use]
pub fn installation_artifacts_present(data_root: &Path) -> bool {
    if !data_root.is_absolute()
        || data_root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return true;
    }

    let layout = ProFilesystemLayout::new(data_root);
    for directory in [data_root.to_path_buf(), layout.pro_root(), layout.bin_dir()] {
        match fs::symlink_metadata(directory) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return true,
        }
    }

    [
        layout.helper_path(),
        layout.helper_marker_path(),
        layout.previous_helper_path(),
        layout.previous_marker_path(),
        layout.transaction_journal_path(),
        layout.transaction_journal_next_path(),
        layout.transaction_helper_path(),
        layout.transaction_marker_path(),
        layout.publish_helper_path(),
        layout.publish_marker_path(),
        layout.rollback_helper_path(),
        layout.rollback_marker_path(),
    ]
    .into_iter()
    .any(|path| match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    })
}

pub fn load_pair_at(
    helper_path: &Path,
    marker_path: &Path,
    public_key_pem: &str,
) -> Result<Option<ValidatedPair>> {
    match inspect_pair_at(helper_path, marker_path, public_key_pem)? {
        PairInspection::Absent => Ok(None),
        PairInspection::Valid(pair) => Ok(Some(pair)),
        PairInspection::Untrusted => {
            bail!("invalid_response: Pro helper and marker do not form a trusted pair")
        }
    }
}

pub fn inspect_pair_at(
    helper_path: &Path,
    marker_path: &Path,
    public_key_pem: &str,
) -> Result<PairInspection> {
    let helper = read_candidate(helper_path, MAX_ARTIFACT_BYTES)?;
    let marker = read_candidate(marker_path, MAX_INSTALL_MARKER_BYTES)?;
    match (helper, marker) {
        (None, None) => Ok(PairInspection::Absent),
        (Some(helper), Some(marker)) => match validate_pair_bytes(helper, marker, public_key_pem) {
            Ok(pair) => Ok(PairInspection::Valid(pair)),
            Err(_) => Ok(PairInspection::Untrusted),
        },
        _ => Ok(PairInspection::Untrusted),
    }
}

pub fn validate_pair_bytes(
    artifact: Vec<u8>,
    marker_bytes: Vec<u8>,
    public_key_pem: &str,
) -> Result<ValidatedPair> {
    let marker: ProInstallMarker = serde_json::from_slice(&marker_bytes)
        .context("invalid_response: parse installed Pro marker")?;
    let manifest = marker.signed_manifest(public_key_pem)?;
    let identity = PairIdentity::new(&artifact, &marker_bytes, &manifest);
    if artifact.len() as u64 != manifest.artifact_size
        || !identity
            .artifact_sha256
            .eq_ignore_ascii_case(&manifest.artifact_sha256)
    {
        bail!("invalid_response: installed Pro helper does not match its signed marker");
    }
    Ok(ValidatedPair {
        identity,
        artifact,
        marker: marker_bytes,
        manifest,
    })
}

pub(crate) fn open_validated_pair_identity(
    operation: &LifecycleOperation,
    helper_path: &Path,
    marker_path: &Path,
    expected: &ValidatedPair,
    trust: ReleaseTrust,
) -> Result<ValidatedArtifactIdentity> {
    operation.require_data_root(operation.data_root())?;
    let layout = ProFilesystemLayout::new(operation.data_root());
    if helper_path != layout.helper_path() || marker_path != layout.helper_marker_path() {
        bail!("invalid_response: installed Pro pair escaped its lifecycle root");
    }

    let artifact_file = open_candidate(helper_path, MAX_ARTIFACT_BYTES, "installed Pro helper")?;
    let marker_file = open_candidate(
        marker_path,
        MAX_INSTALL_MARKER_BYTES,
        "installed Pro marker",
    )?;
    let marker_bytes = read_bounded_handle(
        &marker_file,
        MAX_INSTALL_MARKER_BYTES,
        "installed Pro marker",
    )?;
    let marker: ProInstallMarker = serde_json::from_slice(&marker_bytes)
        .context("invalid_response: parse installed Pro marker")?;
    let manifest = marker.signed_manifest(trust.public_key_pem)?;
    validate_manifest_release_trust(&manifest, trust)?;
    let (artifact_size, artifact_sha256) =
        digest_bounded_handle(&artifact_file, MAX_ARTIFACT_BYTES, "installed Pro helper")?;
    if artifact_size != manifest.artifact_size
        || !artifact_sha256.eq_ignore_ascii_case(&manifest.artifact_sha256)
    {
        bail!("invalid_response: installed Pro helper does not match its signed marker");
    }
    let locked_identity = PairIdentity {
        artifact_size,
        artifact_sha256,
        marker_sha256: format!("{:x}", Sha256::digest(&marker_bytes)),
        version: manifest.version.clone(),
    };
    if locked_identity != expected.identity {
        bail!("invalid_response: installed Pro helper changed during validation");
    }
    Ok(ValidatedArtifactIdentity::new(
        helper_path.to_path_buf(),
        locked_identity.artifact_size,
        locked_identity.artifact_sha256,
        manifest,
        artifact_file,
        operation.clone(),
    ))
}

pub(crate) fn open_validated_staged_identity(
    operation: &LifecycleOperation,
    path: PathBuf,
    manifest: ProManifest,
) -> Result<ValidatedArtifactIdentity> {
    let artifact_file = open_candidate(&path, MAX_ARTIFACT_BYTES, "staged Pro helper")?;
    let (artifact_size, artifact_sha256) =
        digest_bounded_handle(&artifact_file, MAX_ARTIFACT_BYTES, "staged Pro helper")?;
    if artifact_size != manifest.artifact_size
        || !artifact_sha256.eq_ignore_ascii_case(&manifest.artifact_sha256)
    {
        bail!("invalid_response: staged Pro helper changed after verification");
    }
    Ok(ValidatedArtifactIdentity::new(
        path,
        artifact_size,
        artifact_sha256,
        manifest,
        artifact_file,
        operation.clone(),
    ))
}

pub(crate) fn read_validated_artifact(identity: &ValidatedArtifactIdentity) -> Result<Vec<u8>> {
    read_bounded_handle(
        identity.artifact_file(),
        MAX_ARTIFACT_BYTES,
        "validated Pro helper",
    )
}

fn open_candidate(path: &Path, maximum: u64, label: &str) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;

        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .with_context(|| format!("invalid_request: open {label}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("invalid_request: inspect {label}"))?;
    if !metadata.is_file() || metadata.len() > maximum {
        bail!("invalid_response: {label} is invalid");
    }
    Ok(file)
}

fn read_bounded_handle(file: &fs::File, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let metadata = file
        .metadata()
        .with_context(|| format!("invalid_request: inspect {label}"))?;
    if !metadata.is_file() || metadata.len() > maximum {
        bail!("invalid_response: {label} is invalid");
    }
    let mut reader = file
        .try_clone()
        .with_context(|| format!("invalid_request: clone {label} handle"))?;
    reader
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("invalid_request: seek {label} handle"))?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    reader
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("invalid_request: read {label} handle"))?;
    if bytes.len() as u64 > maximum {
        bail!("invalid_response: {label} exceeds maximum size");
    }
    Ok(bytes)
}

fn digest_bounded_handle(file: &fs::File, maximum: u64, label: &str) -> Result<(u64, String)> {
    let metadata = file
        .metadata()
        .with_context(|| format!("invalid_request: inspect {label}"))?;
    if !metadata.is_file() || metadata.len() > maximum {
        bail!("invalid_response: {label} is invalid");
    }
    let mut reader = file
        .try_clone()
        .with_context(|| format!("invalid_request: clone {label} handle"))?;
    reader
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("invalid_request: seek {label} handle"))?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("invalid_request: read {label} handle"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("invalid_response: {label} exceeds maximum size"))?;
        if total > maximum {
            bail!("invalid_response: {label} exceeds maximum size");
        }
        digest.update(&buffer[..read]);
    }
    if total != metadata.len() {
        bail!("invalid_response: {label} changed while reading");
    }
    Ok((total, format!("{:x}", digest.finalize())))
}

pub fn read_candidate(path: &Path, maximum: u64) -> Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => bail!("invalid_request: inspect Pro transaction file"),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        bail!("invalid_response: Pro transaction file is invalid");
    }
    fs::read(path)
        .map(Some)
        .context("invalid_request: read Pro transaction file")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_required_errors_retain_their_typed_classification() {
        let error = setup_repair_required("repair required");
        assert!(is_setup_repair_required_error(&error));
        assert!(!is_setup_repair_required_error(&anyhow::anyhow!(
            "repair required"
        )));
    }

    #[test]
    fn installed_artifact_presence_covers_every_transaction_path() {
        let temp = tempfile::tempdir().unwrap();
        assert!(!installation_artifacts_present(temp.path()));

        let layout = ProFilesystemLayout::new(temp.path());
        for path in [
            layout.helper_path(),
            layout.helper_marker_path(),
            layout.previous_helper_path(),
            layout.previous_marker_path(),
            layout.transaction_journal_path(),
            layout.transaction_journal_next_path(),
            layout.transaction_helper_path(),
            layout.transaction_marker_path(),
            layout.publish_helper_path(),
            layout.publish_marker_path(),
            layout.rollback_helper_path(),
            layout.rollback_marker_path(),
        ] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"fixture").unwrap();
            assert!(installation_artifacts_present(temp.path()), "{path:?}");
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn unsafe_or_non_directory_layout_is_conservatively_present() {
        assert!(installation_artifacts_present(Path::new("relative-root")));

        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("pro"), b"not a directory").unwrap();
        assert!(installation_artifacts_present(temp.path()));
    }
}
