use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{anyhow, bail, Context as _, Result};
use ctx_history_core::platform_security::{
    restrict_private_directory, restrict_private_file, verify_private_directory,
    verify_private_file,
};
use ctx_pro_host_protocol::ProFilesystemLayout;
use fs2::FileExt as _;

/// A single exclusive lifecycle epoch for one ctx data root.
///
/// Clones retain the same OS lock. Starting a separate operation still opens
/// and exclusively locks the durable lifecycle lock file, so setup and
/// uninstall cannot overlap even within one process.
#[derive(Clone)]
pub struct LifecycleOperation {
    inner: Arc<OperationInner>,
}

struct OperationInner {
    data_root: PathBuf,
    file: fs::File,
}

impl LifecycleOperation {
    pub fn begin(data_root: &Path, create_pro_root: bool) -> Result<Option<Self>> {
        let layout = ProFilesystemLayout::new(data_root);
        Self::acquire(&layout.helper_path(), create_pro_root)
    }

    #[doc(hidden)]
    pub fn acquire(target: &Path, create_pro_root: bool) -> Result<Option<Self>> {
        let layout = layout_for_target(target)?;
        let pro_root = layout.pro_root();
        let mut created_pro_root = false;
        match fs::symlink_metadata(&pro_root) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => bail!("invalid_request: Pro lifecycle root is not a safe directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create_pro_root => {
                return Ok(None);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                validate_private_directory(layout.data_root(), "ctx data root")?;
                match fs::create_dir(&pro_root) {
                    Ok(()) => created_pro_root = true,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(error).context("invalid_request: create Pro lifecycle root")
                    }
                }
            }
            Err(error) => return Err(error).context("invalid_request: inspect Pro lifecycle root"),
        }
        for (directory, label) in [
            (layout.data_root(), "ctx data root"),
            (pro_root.as_path(), "Pro lifecycle root"),
        ] {
            validate_private_directory(directory, label)?;
            restrict_private_directory(directory)
                .with_context(|| format!("invalid_request: protect {label}"))?;
            verify_private_directory(directory)
                .with_context(|| format!("invalid_request: verify {label}"))?;
        }
        if created_pro_root {
            sync_parent_directory(&pro_root)
                .context("invalid_request: persist Pro lifecycle root")?;
        }

        let path = layout.lifecycle_lock_path();
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;

            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options
            .open(&path)
            .context("invalid_request: open Pro lifecycle lock")?;
        file.lock_exclusive()
            .context("invalid_request: lock Pro lifecycle")?;
        restrict_private_file(&path).context("invalid_request: protect Pro lifecycle lock")?;
        verify_private_file(&path).context("invalid_request: verify Pro lifecycle lock")?;
        verify_open_lock(&path, &file)?;
        Ok(Some(Self {
            inner: Arc::new(OperationInner {
                data_root: layout.data_root().to_path_buf(),
                file,
            }),
        }))
    }

    #[must_use]
    pub fn data_root(&self) -> &Path {
        &self.inner.data_root
    }

    pub fn require_data_root(&self, data_root: &Path) -> Result<()> {
        if data_root != self.data_root() {
            bail!("invalid_request: Pro lifecycle operation belongs to another data root");
        }
        Ok(())
    }
}

impl Drop for OperationInner {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

pub fn layout_for_target(target: &Path) -> Result<ProFilesystemLayout<'_>> {
    let bin = target
        .parent()
        .ok_or_else(|| anyhow!("invalid_request: Pro install path has no parent"))?;
    let pro = bin
        .parent()
        .ok_or_else(|| anyhow!("invalid_request: Pro install path has no Pro root"))?;
    let data_root = pro
        .parent()
        .ok_or_else(|| anyhow!("invalid_request: Pro install path has no data root"))?;
    if !data_root.is_absolute()
        || data_root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        bail!("invalid_request: ctx data root must be a safe absolute path");
    }
    let layout = ProFilesystemLayout::new(data_root);
    if target != layout.helper_path() {
        bail!("invalid_request: Pro install path is outside the controlled layout");
    }
    Ok(layout)
}

macro_rules! layout_path {
    ($name:ident, $method:ident) => {
        pub fn $name(target: &Path) -> Result<std::path::PathBuf> {
            Ok(layout_for_target(target)?.$method())
        }
    };
}

layout_path!(install_marker_path, helper_marker_path);
layout_path!(previous_helper_path, previous_helper_path);
layout_path!(previous_marker_path, previous_marker_path);
layout_path!(transaction_journal_path, transaction_journal_path);
layout_path!(transaction_journal_next_path, transaction_journal_next_path);
layout_path!(transaction_helper_path, transaction_helper_path);
layout_path!(transaction_marker_path, transaction_marker_path);
layout_path!(publish_helper_path, publish_helper_path);
layout_path!(publish_marker_path, publish_marker_path);
layout_path!(rollback_helper_stage_path, rollback_helper_path);
layout_path!(rollback_marker_stage_path, rollback_marker_path);

pub fn validate_private_directory(path: &Path, label: &str) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("invalid_request: inspect {label}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("invalid_request: {label} is not a safe directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if metadata.uid() != unsafe { libc::geteuid() } {
            bail!("invalid_request: {label} ownership is unsafe");
        }
    }
    Ok(())
}

#[cfg(unix)]
fn verify_open_lock(path: &Path, file: &fs::File) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let opened = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if opened.dev() != named.dev()
        || opened.ino() != named.ino()
        || opened.nlink() != 1
        || opened.uid() != unsafe { libc::geteuid() }
    {
        bail!("invalid_request: Pro lifecycle lock changed while opened");
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_open_lock(_path: &Path, _file: &fs::File) -> Result<()> {
    Ok(())
}

fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("invalid_request: lifecycle path has no parent"))?;
    #[cfg(not(windows))]
    let directory = fs::File::open(parent)?;
    #[cfg(windows)]
    let directory = {
        use std::os::windows::fs::OpenOptionsExt as _;

        fs::OpenOptions::new()
            .write(true)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
            .open(parent)?
    };
    directory.sync_all()?;
    Ok(())
}
