use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context as _, Result};
use ctx_history_core::platform_security::{
    restrict_private_file, verify_private_directory, verify_private_file,
};
use ctx_pro_host_protocol::ProFilesystemLayout;
use uuid::Uuid;

use crate::{
    installation::{replace_file, sync_parent_directory},
    operation::LifecycleOperation,
};

const INITIALIZATION_MARKER_FILE_NAME: &str = ".ctx-pro.initialized";
const INITIALIZATION_MARKER_CONTENT: &[u8] = b"ctx-local-pro-initialized-v1\n";
const MATERIALIZATION_MARKER_FILE_NAME: &str = ".ctx-pro.materialization-pending";
const MATERIALIZATION_MARKER_CONTENT: &[u8] = b"ctx-pro-materialization-pending-v1\n";
const MAX_MATERIALIZATION_MARKER_BYTES: u64 = 128;
const PRESERVED_DATA_MARKER_CONTENT: &[u8] = b"ctx-local-pro-data-preserved-v1\n";

pub fn initialization_marker_exists(data_root: &Path) -> Result<bool> {
    let path = initialization_marker_path(data_root);
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            verify_private_file(&path).context("verify local Pro initialization marker")?;
            if fs::read(&path).context("read local Pro initialization marker")?
                != INITIALIZATION_MARKER_CONTENT
            {
                bail!("invalid_request: local Pro initialization marker has invalid content");
            }
            Ok(true)
        }
        Ok(_) => bail!("invalid_request: local Pro initialization marker is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspect local Pro initialization marker"),
    }
}

pub fn mark_initialized(operation: &LifecycleOperation) -> Result<()> {
    let data_root = operation.data_root();
    let pro_root = ProFilesystemLayout::new(data_root).pro_root();
    verify_private_directory(&pro_root)
        .context("invalid_request: verify private Pro lifecycle directory")?;
    if initialization_marker_exists(data_root)? {
        return Ok(());
    }
    publish_private_file(
        &initialization_marker_path(data_root),
        &initialization_marker_staged_path(data_root),
        INITIALIZATION_MARKER_CONTENT,
        "local Pro initialization marker",
    )
}

pub fn clear_initialization_marker(operation: &LifecycleOperation) -> Result<()> {
    let data_root = operation.data_root();
    let path = initialization_marker_path(data_root);
    let removed = delete_private_file(&path, "local Pro initialization marker")?;
    let staged = initialization_marker_staged_path(data_root);
    let removed_staged = delete_private_file(&staged, "local Pro initialization marker")?;
    if removed || removed_staged {
        sync_parent_directory(&path)?;
    }
    Ok(())
}

pub fn materialization_pending(data_root: &Path) -> Result<bool> {
    let marker = materialization_marker_path(data_root);
    match marker.symlink_metadata() {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
        Ok(_) => bail!("invalid_request: Pro materialization marker is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("inspect Pro materialization marker"),
    }
    verify_private_file(&marker).context("verify Pro materialization marker")?;
    let mut bytes = Vec::new();
    fs::File::open(&marker)
        .context("open Pro materialization marker")?
        .take(MAX_MATERIALIZATION_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read Pro materialization marker")?;
    if bytes != MATERIALIZATION_MARKER_CONTENT {
        bail!("invalid_request: Pro materialization marker is invalid");
    }
    Ok(true)
}

pub fn request_materialization(operation: &LifecycleOperation) -> Result<()> {
    let data_root = operation.data_root();
    let marker = materialization_marker_path(data_root);
    let parent = marker
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid_request: Pro marker has no parent"))?;
    verify_private_directory(parent)
        .context("invalid_request: verify private Pro lifecycle directory")?;
    if materialization_pending(data_root)? {
        return Ok(());
    }
    let staged = parent.join(format!(".materialization-pending-{}.next", Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)
            .context("write Pro materialization marker")?;
        restrict_private_file(&staged).context("protect Pro materialization marker")?;
        file.write_all(MATERIALIZATION_MARKER_CONTENT)
            .context("write Pro materialization marker")?;
        file.sync_all().context("sync Pro materialization marker")?;
        fs::rename(&staged, &marker).context("publish Pro materialization marker")?;
        sync_parent_directory(&marker)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

pub fn clear_materialization(operation: &LifecycleOperation) -> Result<()> {
    let data_root = operation.data_root();
    if !materialization_pending(data_root)? {
        return Ok(());
    }
    let marker = materialization_marker_path(data_root);
    fs::remove_file(&marker).context("remove Pro materialization marker")?;
    sync_parent_directory(&marker)
}

pub fn clear_materialization_at(data_root: &Path) -> Result<()> {
    let Some(operation) = LifecycleOperation::begin(data_root, false)? else {
        return Ok(());
    };
    clear_materialization(&operation)
}

#[must_use]
pub fn preserved_data_marker_is_set(data_root: &Path) -> bool {
    let path = ProFilesystemLayout::new(data_root).preserved_data_marker_path();
    path.symlink_metadata()
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        && fs::read(path).is_ok_and(|content| content == PRESERVED_DATA_MARKER_CONTENT)
        && crate::deletion::local_pro_graph_data_exists(data_root).unwrap_or(false)
}

pub fn preserved_data_marker_present(data_root: &Path) -> Result<bool> {
    let path = ProFilesystemLayout::new(data_root).preserved_data_marker_path();
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => bail!("invalid_request: local Pro data marker is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspect local Pro data marker"),
    }
}

pub fn mark_data_preserved(operation: &LifecycleOperation) -> Result<()> {
    let data_root = operation.data_root();
    if !crate::deletion::local_pro_graph_data_exists(data_root)? {
        bail!("invalid_request: cannot mark absent local Pro data as preserved");
    }
    let path = ProFilesystemLayout::new(data_root).preserved_data_marker_path();
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            verify_private_file(&path).context("verify local Pro data marker")?;
            if fs::read(&path).context("read local Pro data marker")?
                != PRESERVED_DATA_MARKER_CONTENT
            {
                bail!("invalid_request: local Pro data marker has invalid content");
            }
            return Ok(());
        }
        Ok(_) => bail!("invalid_request: local Pro data marker is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect local Pro data marker"),
    }
    publish_private_file(
        &path,
        &path.with_extension("data-preserved.next"),
        PRESERVED_DATA_MARKER_CONTENT,
        "local Pro data marker",
    )
}

pub fn clear_data_preserved(operation: &LifecycleOperation) -> Result<()> {
    let path = ProFilesystemLayout::new(operation.data_root()).preserved_data_marker_path();
    let removed = delete_private_file(&path, "local Pro data marker")?;
    let staged = path.with_extension("data-preserved.next");
    let removed_staged = delete_private_file(&staged, "local Pro data marker")?;
    if removed || removed_staged {
        sync_parent_directory(&path)?;
    }
    Ok(())
}

fn initialization_marker_path(data_root: &Path) -> PathBuf {
    ProFilesystemLayout::new(data_root)
        .pro_root()
        .join(INITIALIZATION_MARKER_FILE_NAME)
}

fn initialization_marker_staged_path(data_root: &Path) -> PathBuf {
    initialization_marker_path(data_root).with_extension("initialized.next")
}

fn materialization_marker_path(data_root: &Path) -> PathBuf {
    ProFilesystemLayout::new(data_root)
        .pro_root()
        .join(MATERIALIZATION_MARKER_FILE_NAME)
}

fn publish_private_file(path: &Path, staged: &Path, contents: &[u8], label: &str) -> Result<()> {
    delete_private_file(staged, label)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(staged)
        .with_context(|| format!("create {label}"))?;
    restrict_private_file(staged).with_context(|| format!("protect {label}"))?;
    file.write_all(contents)
        .with_context(|| format!("write {label}"))?;
    file.sync_all().with_context(|| format!("sync {label}"))?;
    verify_private_file(staged).with_context(|| format!("verify {label}"))?;
    replace_file(staged, path).with_context(|| format!("publish {label}"))?;
    sync_parent_directory(path)
}

fn delete_private_file(path: &Path, label: &str) -> Result<bool> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path).with_context(|| format!("remove {label}"))?;
            Ok(true)
        }
        Ok(_) => bail!("invalid_request: {label} is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {label}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn materialization_marker_is_private_idempotent_and_strict() {
        let root = tempfile::tempdir().unwrap();
        let operation = LifecycleOperation::begin(root.path(), true)
            .unwrap()
            .unwrap();
        assert!(!materialization_pending(root.path()).unwrap());
        request_materialization(&operation).unwrap();
        request_materialization(&operation).unwrap();
        assert!(materialization_pending(root.path()).unwrap());
        fs::write(materialization_marker_path(root.path()), b"wrong").unwrap();
        assert!(materialization_pending(root.path()).is_err());
        fs::write(
            materialization_marker_path(root.path()),
            MATERIALIZATION_MARKER_CONTENT,
        )
        .unwrap();
        clear_materialization(&operation).unwrap();
        assert!(!materialization_pending(root.path()).unwrap());
    }
}
