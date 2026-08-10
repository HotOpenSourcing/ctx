use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use ctx_pro_host_protocol::ProFilesystemLayout;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::release_manifest::{
    ProInstallMarker, ProManifest, MAX_ARTIFACT_BYTES, MAX_INSTALL_MARKER_BYTES,
};

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
