use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use ctx_pro_host_protocol::{
    BlameRequest, BlameTarget, CoreMaterializationReceiptIdentity, CoreProjectionCurrentness,
    MaterializedCoverage, ProFilesystemLayout, ProOperation, QuerySnapshotExpectation,
    StatusResult,
};

use crate::{InstalledProHost, VerifiedHelperExecutable};

const MAX_GIT_EXECUTABLE_PATH_BYTES: usize = 4 * 1024;

pub(crate) fn error_code(error: &anyhow::Error) -> String {
    error
        .to_string()
        .split(':')
        .next()
        .unwrap_or("helper_crashed")
        .to_owned()
}

pub(crate) fn current_blame_request(
    target: BlameTarget,
    limit: u32,
    cursor: Option<String>,
    status: &StatusResult,
    expected_core_generation_id: &str,
) -> Result<BlameRequest> {
    status
        .validate()
        .map_err(|error| anyhow!("invalid_response: {}", error.message))?;
    if !matches!(
        status.currentness,
        CoreProjectionCurrentness::Current | CoreProjectionCurrentness::Finalizing
    ) || status.coverage != MaterializedCoverage::Complete
    {
        bail!("not_materialized: Pro Core projection has no complete queryable coverage");
    }
    let operation = match &target {
        BlameTarget::File { .. } => ProOperation::FileBlame,
        BlameTarget::Commit { .. } => ProOperation::CommitBlame,
        BlameTarget::PullRequest { .. } => ProOperation::PullRequestBlame,
    };
    if !status.available_operations.contains(&operation) {
        bail!("repository_unavailable: requested Pro blame operation is not currently available");
    }
    let receipt = status.core_receipt.as_ref().ok_or_else(|| {
        anyhow!("not_materialized: current Pro Core projection has no completed receipt")
    })?;
    if receipt.core_generation_id != expected_core_generation_id {
        bail!(
            "stale_source: Pro helper generation {} does not match active verified Core generation {}",
            receipt.core_generation_id,
            expected_core_generation_id
        );
    }
    Ok(BlameRequest {
        target,
        limit,
        cursor,
        expected_snapshot: QuerySnapshotExpectation::Core {
            receipt: CoreMaterializationReceiptIdentity::from_receipt(receipt)
                .map_err(|error| anyhow!("invalid_response: {}", error.message))?,
        },
    })
}

pub fn default_helper_path(data_root: &Path) -> PathBuf {
    ProFilesystemLayout::new(data_root).helper_path()
}

pub(crate) fn helper_path(
    host: &(impl InstalledProHost + ?Sized),
    data_root: &Path,
) -> Result<PathBuf> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(path) = host.helper_override()? {
        return regular_helper_path(path);
    }

    helper_executable(host, data_root).map(|helper| helper.path().to_path_buf())
}

pub(crate) fn helper_executable(
    host: &(impl InstalledProHost + ?Sized),
    data_root: &Path,
) -> Result<VerifiedHelperExecutable> {
    helper_executable_in(host, data_root, None)
}

pub(crate) fn helper_executable_in(
    host: &(impl InstalledProHost + ?Sized),
    data_root: &Path,
    operation: Option<&ctx_pro_lifecycle::operation::LifecycleOperation>,
) -> Result<VerifiedHelperExecutable> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(path) = host.helper_override()? {
        if !path.is_absolute() {
            bail!("pro_not_installed: developer Pro helper must be an absolute path");
        }
        return VerifiedHelperExecutable::open_developer(&path);
    }

    let identity = host.validated_installed_helper(data_root, operation)?;
    VerifiedHelperExecutable::from_validated(identity)
}

pub fn git_executable() -> Result<PathBuf> {
    let search_path = env::var_os("PATH")
        .ok_or_else(|| anyhow!("repository_unavailable: Git is not available on PATH"))?;
    let current_directory = env::current_dir().context("repository_unavailable: resolve cwd")?;
    for directory in env::split_paths(&search_path) {
        let directory = if directory.is_absolute() {
            directory
        } else {
            current_directory.join(directory)
        };
        for executable_name in git_executable_names() {
            let candidate = directory.join(executable_name);
            let Ok(canonical) = candidate.canonicalize() else {
                continue;
            };
            if canonical.as_os_str().as_encoded_bytes().len() > MAX_GIT_EXECUTABLE_PATH_BYTES {
                continue;
            }
            let Ok(metadata) = fs::symlink_metadata(&canonical) else {
                continue;
            };
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                if metadata.permissions().mode() & 0o111 == 0 {
                    continue;
                }
            }
            return Ok(canonical);
        }
    }
    bail!("repository_unavailable: Git is not available on PATH")
}

#[cfg(windows)]
fn git_executable_names() -> &'static [&'static str] {
    &["git.exe"]
}

#[cfg(not(windows))]
fn git_executable_names() -> &'static [&'static str] {
    &["git"]
}

#[cfg(any(test, feature = "test-support"))]
fn regular_helper_path(path: PathBuf) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("pro_not_installed: developer Pro helper must be an absolute path");
    }
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("pro_not_installed: no Pro helper at {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("pro_not_installed: Pro helper must be a regular non-symlink file");
    }
    Ok(path)
}
