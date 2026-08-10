use std::{
    fs,
    io::{Read as _, Seek as _},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::io::Write as _;
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd as _;
#[cfg(unix)]
use std::os::{
    fd::{AsRawFd as _, RawFd},
    unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
};

use anyhow::{bail, Context, Result};
#[cfg(not(windows))]
use ctx_history_core::platform_security::{
    verify_private_directory, verify_private_executable, verify_private_file,
};
#[cfg(windows)]
use ctx_history_core::platform_security::{
    verify_private_directory_handle, verify_private_file_handle,
};
use ctx_pro_host_protocol::ProFilesystemLayout;
use sha2::{Digest as _, Sha256};

pub(crate) struct PreparedHelperExecution {
    program: PathBuf,
    #[cfg(unix)]
    descriptor: RawFd,
}

impl PreparedHelperExecution {
    pub(crate) fn program(&self) -> &Path {
        &self.program
    }

    pub(crate) fn configure_command(&self, command: &mut std::process::Command) {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;

            let descriptor = self.descriptor;
            // The descriptor route is resolved by exec on native binaries and
            // reopened by the interpreter for script fixtures. Clear CLOEXEC
            // only in the forked child at the final pre-exec boundary.
            unsafe {
                command.pre_exec(move || {
                    let flags = libc::fcntl(descriptor, libc::F_GETFD);
                    if flags == -1
                        || libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        #[cfg(windows)]
        let _ = command;
    }
}

/// The narrow lifecycle-to-host identity established after signed-pair and
/// release-trust validation. The host treats these fields as opaque process
/// binding inputs and does not parse lifecycle manifests.
pub struct LifecycleValidatedHelper {
    artifact_sha256: String,
    protocol_fingerprint: String,
}

impl LifecycleValidatedHelper {
    #[must_use]
    pub fn new(artifact_sha256: String, protocol_fingerprint: String) -> Self {
        Self {
            artifact_sha256,
            protocol_fingerprint,
        }
    }
}

/// Retains the exact lifecycle-validated execution object and lifecycle guard
/// for the complete helper process lifetime.
pub struct VerifiedHelperExecutable {
    path: PathBuf,
    artifact_sha256: String,
    protocol_fingerprint: String,
    _installation_guard: Option<Box<dyn std::any::Any>>,
    #[cfg(unix)]
    execution: UnixExecutionSnapshot,
    #[cfg(windows)]
    _directories: Vec<fs::File>,
    #[cfg(windows)]
    helper: fs::File,
}

impl VerifiedHelperExecutable {
    #[cfg(any(test, feature = "test-support"))]
    pub fn open_developer(path: &Path) -> Result<Self> {
        #[cfg(windows)]
        {
            let helper = open_locked_file(path)?;
            let artifact = read_bounded_handle(&helper, u64::MAX, "developer Pro helper")?;
            Ok(Self {
                path: path.to_path_buf(),
                artifact_sha256: format!("{:x}", Sha256::digest(&artifact)),
                protocol_fingerprint: ctx_pro_host_protocol::PROTOCOL_FINGERPRINT.to_owned(),
                _installation_guard: None,
                _directories: Vec::new(),
                helper,
            })
        }
        #[cfg(unix)]
        {
            let source = open_unix_regular_file(path, "developer Pro helper")?;
            let artifact = read_bounded_handle(&source, u64::MAX, "developer Pro helper")?;
            let artifact_sha256 = format!("{:x}", Sha256::digest(&artifact));
            let execution = UnixExecutionSnapshot::from_validated_bytes(
                path.parent().ok_or_else(|| {
                    anyhow::anyhow!("pro_not_installed: developer Pro helper has no parent")
                })?,
                &artifact,
                &artifact_sha256,
            )?;
            Ok(Self {
                path: path.to_path_buf(),
                artifact_sha256,
                protocol_fingerprint: ctx_pro_host_protocol::PROTOCOL_FINGERPRINT.to_owned(),
                _installation_guard: None,
                execution,
            })
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open(
        data_root: &Path,
        path: &Path,
        marker: &Path,
        artifact: &[u8],
        identity: LifecycleValidatedHelper,
        installation_guard: impl std::any::Any,
    ) -> Result<Self> {
        let layout = ProFilesystemLayout::new(data_root);
        let expected_parent = layout.bin_dir();
        if path.parent() != Some(expected_parent.as_path())
            || marker.parent() != Some(expected_parent.as_path())
        {
            bail!("invalid_response: installed Pro helper path escaped its private root");
        }

        #[cfg(windows)]
        {
            let directories = [data_root.to_path_buf(), layout.pro_root(), expected_parent];
            let mut locked = Vec::with_capacity(directories.len());
            for directory in directories {
                let handle = open_locked_directory(&directory)?;
                verify_private_directory_handle(&handle)
                    .context("invalid_response: Pro install directory ACL is unsafe")?;
                locked.push(handle);
            }
            let helper = open_locked_file(path)?;
            let marker_file = open_locked_file(marker)?;
            verify_private_file_handle(&helper)
                .context("invalid_response: installed Pro helper ACL is unsafe")?;
            verify_private_file_handle(&marker_file)
                .context("invalid_response: installed Pro marker ACL is unsafe")?;
            if read_bounded_handle(
                &helper,
                artifact.len() as u64,
                "installed Pro helper execution handle",
            )? != artifact
            {
                bail!(
                    "invalid_response: installed Pro helper changed before its execution handle was retained"
                );
            }
            Ok(Self {
                path: path.to_path_buf(),
                artifact_sha256: identity.artifact_sha256,
                protocol_fingerprint: identity.protocol_fingerprint,
                _installation_guard: Some(Box::new(installation_guard)),
                _directories: locked,
                helper,
            })
        }
        #[cfg(unix)]
        {
            verify_private_directory(data_root)
                .context("invalid_response: ctx data directory permissions are unsafe")?;
            verify_private_directory(&layout.pro_root())
                .context("invalid_response: Pro directory permissions are unsafe")?;
            verify_private_directory(&expected_parent)
                .context("invalid_response: Pro install directory permissions are unsafe")?;
            verify_private_executable(path)
                .context("invalid_response: installed Pro helper permissions are unsafe")?;
            verify_private_file(marker)
                .context("invalid_response: installed Pro marker permissions are unsafe")?;
            let execution = UnixExecutionSnapshot::from_validated_bytes(
                &expected_parent,
                artifact,
                &identity.artifact_sha256,
            )?;
            Ok(Self {
                path: path.to_path_buf(),
                artifact_sha256: identity.artifact_sha256,
                protocol_fingerprint: identity.protocol_fingerprint,
                _installation_guard: Some(Box::new(installation_guard)),
                execution,
            })
        }
    }

    pub fn artifact_sha256(&self) -> &str {
        &self.artifact_sha256
    }

    pub(crate) fn protocol_fingerprint(&self) -> &str {
        &self.protocol_fingerprint
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn prepare_execution(&self) -> Result<PreparedHelperExecution> {
        self.verify_execution_identity()?;
        #[cfg(unix)]
        {
            return Ok(PreparedHelperExecution {
                program: self.execution.descriptor_path(),
                descriptor: self.execution.file.as_raw_fd(),
            });
        }
        #[cfg(windows)]
        Ok(PreparedHelperExecution {
            program: self.path.clone(),
        })
    }

    /// Confirms the final spawn route still resolves to the exact retained
    /// execution object and, where sealing is unavailable, revalidates bytes.
    pub fn verify_execution_identity(&self) -> Result<()> {
        #[cfg(unix)]
        self.execution.verify(&self.artifact_sha256)?;
        #[cfg(windows)]
        {
            let named = open_file_handle(&self.path)?;
            verify_open_identity(&self.helper, &named, false)?;
        }
        Ok(())
    }
}

fn read_bounded_handle(file: &fs::File, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let metadata = file
        .metadata()
        .with_context(|| format!("invalid_request: inspect {label} handle"))?;
    if !metadata.is_file() || metadata.len() > maximum {
        bail!("invalid_response: {label} exceeds maximum size");
    }
    let mut reader = file
        .try_clone()
        .with_context(|| format!("invalid_request: clone {label} handle"))?;
    reader
        .seek(std::io::SeekFrom::Start(0))
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

#[cfg(unix)]
fn open_unix_regular_file(path: &Path, label: &str) -> Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("pro_not_installed: open {label}"))?;
    if !file
        .metadata()
        .with_context(|| format!("pro_not_installed: inspect {label}"))?
        .is_file()
    {
        bail!("pro_not_installed: {label} is not a regular file");
    }
    Ok(file)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnixFileIdentity {
    device: u64,
    inode: u64,
    size: u64,
}

#[cfg(unix)]
impl UnixFileIdentity {
    fn from_file(file: &fs::File) -> Result<Self> {
        let metadata = file
            .metadata()
            .context("invalid_response: inspect retained Pro execution object")?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
        })
    }
}

#[cfg(unix)]
struct UnixExecutionSnapshot {
    file: fs::File,
    identity: UnixFileIdentity,
    #[cfg(target_os = "linux")]
    sealed: bool,
}

#[cfg(unix)]
impl UnixExecutionSnapshot {
    fn from_validated_bytes(parent: &Path, artifact: &[u8], artifact_sha256: &str) -> Result<Self> {
        #[cfg(target_os = "linux")]
        if let Some(file) = create_sealed_linux_snapshot(artifact)? {
            return Ok(Self {
                identity: UnixFileIdentity::from_file(&file)?,
                file,
                sealed: true,
            });
        }

        let file = create_unlinked_unix_snapshot(parent, artifact)?;
        let snapshot = Self {
            identity: UnixFileIdentity::from_file(&file)?,
            file,
            #[cfg(target_os = "linux")]
            sealed: false,
        };
        snapshot.verify(artifact_sha256)?;
        Ok(snapshot)
    }

    fn descriptor_path(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        let root = "/proc/self/fd";
        #[cfg(not(target_os = "linux"))]
        let root = "/dev/fd";
        Path::new(root).join(self.file.as_raw_fd().to_string())
    }

    fn verify(&self, artifact_sha256: &str) -> Result<()> {
        let descriptor_path = self.descriptor_path();
        let retained = UnixFileIdentity::from_file(&self.file)?;
        // `stat(/dev/fd/N)` reports the synthetic fdesc vnode on macOS rather
        // than the retained file itself. Opening the kernel-owned route first
        // gives the duplicated execution object on every supported Unix.
        let routed_file = fs::OpenOptions::new()
            .read(true)
            .open(&descriptor_path)
            .context("invalid_response: resolve Pro execution descriptor route")?;
        let routed = UnixFileIdentity::from_file(&routed_file)?;
        if retained != self.identity || routed != self.identity {
            bail!("invalid_response: retained Pro execution object identity changed");
        }

        #[cfg(target_os = "linux")]
        if self.sealed {
            let seals = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GET_SEALS) };
            let required =
                libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
            if seals == -1 || seals & required != required {
                bail!("invalid_response: retained Pro execution object lost its write seals");
            }
            return Ok(());
        }

        // Platforms without a sealed anonymous executable revalidate the exact
        // retained bytes at the smallest boundary before descriptor-bound exec.
        let bytes = read_bounded_handle(
            &self.file,
            self.identity.size,
            "retained Pro execution object",
        )?;
        if format!("{:x}", Sha256::digest(bytes)) != artifact_sha256 {
            bail!("invalid_response: retained Pro execution object bytes changed before spawn");
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn create_sealed_linux_snapshot(artifact: &[u8]) -> Result<Option<fs::File>> {
    let name = std::ffi::CString::new("ctx-pro-verified-execution")
        .expect("static memfd name contains no NUL");
    let base_flags = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    let mut descriptor = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            base_flags | libc::MFD_EXEC,
        )
    };
    if descriptor == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        // MFD_EXEC is required by hardened current kernels but unknown to
        // older kernels, where executable memfds were the default.
        descriptor = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), base_flags) };
    }
    if descriptor == -1 {
        let error = std::io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS | libc::EPERM | libc::EINVAL)
        ) {
            return Ok(None);
        }
        return Err(error).context("invalid_response: create sealed Pro execution object");
    }
    let descriptor = i32::try_from(descriptor)
        .context("invalid_response: Pro execution descriptor exceeded i32")?;
    let mut file = unsafe { fs::File::from_raw_fd(descriptor) };
    file.write_all(artifact)
        .context("invalid_response: populate sealed Pro execution object")?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } == -1 {
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::EPERM | libc::EINVAL)) {
            return Ok(None);
        }
        return Err(error).context("invalid_response: seal Pro execution object");
    }
    Ok(Some(file))
}

#[cfg(unix)]
fn create_unlinked_unix_snapshot(parent: &Path, artifact: &[u8]) -> Result<fs::File> {
    for _ in 0..16 {
        let path = parent.join(format!(".ctx-pro-exec-{}", uuid::Uuid::new_v4()));
        let mut writer = match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).context("invalid_response: create Pro execution snapshot")
            }
        };
        writer
            .write_all(artifact)
            .context("invalid_response: populate Pro execution snapshot")?;
        writer
            .sync_all()
            .context("invalid_response: persist Pro execution snapshot")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o500))
            .context("invalid_response: restrict Pro execution snapshot")?;
        let reader = open_unix_regular_file(&path, "Pro execution snapshot")?;
        if UnixFileIdentity::from_file(&writer)? != UnixFileIdentity::from_file(&reader)? {
            let _ = fs::remove_file(&path);
            bail!("invalid_response: Pro execution snapshot identity changed while opening");
        }
        fs::remove_file(&path).context("invalid_response: unlink Pro execution snapshot")?;
        drop(writer);
        return Ok(reader);
    }
    bail!("invalid_response: allocate unique Pro execution snapshot")
}

#[cfg(windows)]
fn open_locked_directory(path: &Path) -> Result<fs::File> {
    let file = open_directory_handle(path)?;
    let named = open_directory_handle(path)?;
    verify_open_identity(&file, &named, true)?;
    Ok(file)
}

#[cfg(windows)]
fn open_directory_handle(path: &Path) -> Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    };

    fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .context("invalid_response: lock Pro install directory")
}

#[cfg(windows)]
fn open_locked_file(path: &Path) -> Result<fs::File> {
    let file = open_file_handle(path)?;
    let named = open_file_handle(path)?;
    verify_open_identity(&file, &named, false)?;
    Ok(file)
}

#[cfg(windows)]
fn open_file_handle(path: &Path) -> Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .context("invalid_response: lock installed Pro file")
}

#[cfg(windows)]
fn verify_open_identity(file: &fs::File, named_handle: &fs::File, directory: bool) -> Result<()> {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let opened = file
        .metadata()
        .context("invalid_response: inspect locked Pro path")?;
    let named = named_handle
        .metadata()
        .context("invalid_response: inspect second locked Pro handle")?;
    let expected_type = if directory {
        opened.is_dir() && named.is_dir()
    } else {
        opened.is_file() && named.is_file()
    };
    if !expected_type
        || opened.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || named.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || windows_file_identity(file)? != windows_file_identity(named_handle)?
    {
        bail!("invalid_response: locked Pro path identity changed");
    }
    Ok(())
}

#[cfg(windows)]
fn windows_file_identity(file: &fs::File) -> Result<(u32, u64)> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    // SAFETY: the file owns a live Windows handle and the out pointer is valid.
    if unsafe {
        GetFileInformationByHandle(file.as_raw_handle() as HANDLE, information.as_mut_ptr())
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("invalid_response: read locked Pro path identity");
    }
    // SAFETY: the successful API call initialized the complete structure.
    let information = unsafe { information.assume_init() };
    let index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((information.dwVolumeSerialNumber, index))
}

#[cfg(all(test, windows))]
mod windows_tests {
    use ctx_history_core::platform_security::{
        restrict_private_directory, restrict_private_executable, restrict_private_file,
    };

    use super::*;

    #[test]
    fn locked_verified_helper_cannot_be_replaced_before_spawn(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parent = tempfile::tempdir()?;
        let data_root = parent.path().join("ctx-data");
        let layout = ProFilesystemLayout::new(&data_root);
        let pro = layout.pro_root();
        let bin = layout.bin_dir();
        fs::create_dir_all(&bin)?;
        for directory in [&data_root, &pro, &bin] {
            restrict_private_directory(directory)?;
        }
        let helper = bin.join("ctx-pro.exe");
        let marker = bin.join("ctx-pro.exe.install.json");
        fs::write(&helper, b"signed helper bytes")?;
        fs::write(&marker, b"signed marker bytes")?;
        restrict_private_executable(&helper)?;
        restrict_private_file(&marker)?;

        let locked = VerifiedHelperExecutable::open(
            &data_root,
            &helper,
            &marker,
            b"signed helper bytes",
            LifecycleValidatedHelper::new(
                format!("{:x}", Sha256::digest(b"signed helper bytes")),
                ctx_pro_host_protocol::PROTOCOL_FINGERPRINT.to_owned(),
            ),
            (),
        )?;
        assert!(fs::remove_file(&helper).is_err());
        assert!(fs::rename(&helper, bin.join("replaced.exe")).is_err());
        assert!(fs::write(&helper, b"attacker replacement").is_err());
        assert_eq!(
            locked.artifact_sha256(),
            format!("{:x}", Sha256::digest(b"signed helper bytes"))
        );
        locked.verify_execution_identity()?;
        drop(locked);
        assert!(fs::write(&helper, b"owner update after spawn").is_ok());
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use std::{os::unix::fs::PermissionsExt as _, process::Command};

    use ctx_history_core::platform_security::{
        restrict_private_directory, restrict_private_executable, restrict_private_file,
    };

    use super::*;

    const TRUSTED_HELPER: &[u8] = b"#!/bin/sh\nprintf trusted-snapshot\n";
    const ATTACKER_HELPER: &[u8] = b"#!/bin/sh\nprintf attacker-replacement\n";

    fn write_executable(path: &Path, bytes: &[u8]) -> Result<()> {
        fs::write(path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn execute(executable: &VerifiedHelperExecutable) -> Result<Vec<u8>> {
        let prepared = executable.prepare_execution()?;
        let mut command = Command::new(prepared.program());
        prepared.configure_command(&mut command);
        let output = command
            .output()
            .context("execute retained Pro helper test snapshot")?;
        if !output.status.success() {
            bail!(
                "retained Pro helper test snapshot failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(output.stdout)
    }

    #[test]
    fn developer_helper_rename_replacement_cannot_change_retained_execution() -> Result<()> {
        let root = tempfile::tempdir()?;
        let helper = root.path().join("ctx-pro-helper");
        let displaced = root.path().join("ctx-pro-helper.displaced");
        write_executable(&helper, TRUSTED_HELPER)?;

        let executable = VerifiedHelperExecutable::open_developer(&helper)?;
        fs::rename(&helper, &displaced)?;
        write_executable(&helper, ATTACKER_HELPER)?;

        executable.verify_execution_identity()?;
        assert_eq!(execute(&executable)?, b"trusted-snapshot");
        Ok(())
    }

    #[test]
    fn developer_helper_in_place_rewrite_cannot_change_retained_execution() -> Result<()> {
        let root = tempfile::tempdir()?;
        let helper = root.path().join("ctx-pro-helper");
        write_executable(&helper, TRUSTED_HELPER)?;

        let executable = VerifiedHelperExecutable::open_developer(&helper)?;
        write_executable(&helper, ATTACKER_HELPER)?;

        executable.verify_execution_identity()?;
        assert_eq!(execute(&executable)?, b"trusted-snapshot");
        Ok(())
    }

    #[test]
    fn installed_path_replacement_cannot_override_lifecycle_validated_bytes() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let data_root = parent.path().join("ctx-data");
        let layout = ProFilesystemLayout::new(&data_root);
        let pro = layout.pro_root();
        let bin = layout.bin_dir();
        fs::create_dir_all(&bin)?;
        for directory in [&data_root, &pro, &bin] {
            restrict_private_directory(directory)?;
        }
        let helper = layout.helper_path();
        let marker = layout.helper_marker_path();
        write_executable(&helper, ATTACKER_HELPER)?;
        fs::write(&marker, b"lifecycle-validated marker")?;
        restrict_private_executable(&helper)?;
        restrict_private_file(&marker)?;

        let executable = VerifiedHelperExecutable::open(
            &data_root,
            &helper,
            &marker,
            TRUSTED_HELPER,
            LifecycleValidatedHelper::new(
                format!("{:x}", Sha256::digest(TRUSTED_HELPER)),
                ctx_pro_host_protocol::PROTOCOL_FINGERPRINT.to_owned(),
            ),
            (),
        )?;

        assert_eq!(execute(&executable)?, b"trusted-snapshot");
        Ok(())
    }

    #[test]
    fn unsealed_snapshot_revalidates_exact_bytes_before_spawn() -> Result<()> {
        let root = tempfile::tempdir()?;
        let snapshot_path = root.path().join("retained-snapshot");
        write_executable(&snapshot_path, TRUSTED_HELPER)?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&snapshot_path)?;
        fs::remove_file(&snapshot_path)?;
        let identity = UnixFileIdentity::from_file(&file)?;
        let snapshot = UnixExecutionSnapshot {
            file: file.try_clone()?,
            identity,
            #[cfg(target_os = "linux")]
            sealed: false,
        };
        let artifact_sha256 = format!("{:x}", Sha256::digest(TRUSTED_HELPER));
        snapshot.verify(&artifact_sha256)?;

        file.seek(std::io::SeekFrom::Start(0))?;
        file.write_all(b"?")?;
        file.sync_all()?;

        let error = snapshot.verify(&artifact_sha256).unwrap_err();
        assert!(error
            .to_string()
            .contains("retained Pro execution object bytes changed before spawn"));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_execution_snapshot_is_write_sealed() -> Result<()> {
        let root = tempfile::tempdir()?;
        let helper = root.path().join("ctx-pro-helper");
        write_executable(&helper, TRUSTED_HELPER)?;
        let executable = VerifiedHelperExecutable::open_developer(&helper)?;

        assert!(executable.execution.sealed);
        let mut attacker = fs::OpenOptions::new()
            .write(true)
            .open(executable.execution.descriptor_path())?;
        assert!(attacker.write_all(ATTACKER_HELPER).is_err());
        drop(attacker);
        assert_eq!(execute(&executable)?, b"trusted-snapshot");
        Ok(())
    }
}
