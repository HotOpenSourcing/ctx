use std::{
    fs,
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd as _;
#[cfg(unix)]
use std::os::{
    fd::{AsRawFd as _, RawFd},
    unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
};

use anyhow::{bail, Context, Result};
#[cfg(not(windows))]
use ctx_history_core::platform_security::{verify_private_directory, verify_private_executable};
#[cfg(windows)]
use ctx_history_core::platform_security::{
    verify_private_directory_handle, verify_private_file_handle,
};
#[cfg(test)]
use ctx_pro_host_protocol::ProFilesystemLayout;
use ctx_pro_lifecycle::installed_artifact::ValidatedArtifactIdentity;
use sha2::{Digest as _, Sha256};

const STREAM_BUFFER_BYTES: usize = 64 * 1024;

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

/// Retains the exact lifecycle-validated identity and operation guard for the
/// complete helper process lifetime. Release interpretation remains entirely
/// in `ctx-pro-lifecycle`; this type owns only executable/process identity.
pub struct VerifiedHelperExecutable {
    path: PathBuf,
    artifact_sha256: String,
    protocol_fingerprint: String,
    _validated_identity: Option<ValidatedArtifactIdentity>,
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
            let (artifact_size, artifact_sha256) =
                stream_digest(&helper, u64::MAX, "developer Pro helper")?;
            if artifact_size == 0 {
                bail!("pro_not_installed: developer Pro helper is empty");
            }
            Ok(Self {
                path: path.to_path_buf(),
                artifact_sha256,
                protocol_fingerprint: ctx_pro_host_protocol::PROTOCOL_FINGERPRINT.to_owned(),
                _validated_identity: None,
                _directories: Vec::new(),
                helper,
            })
        }
        #[cfg(unix)]
        {
            let source = open_unix_regular_file(path, "developer Pro helper")?;
            let source_size = source
                .metadata()
                .context("pro_not_installed: inspect developer Pro helper")?
                .len();
            if source_size == 0 {
                bail!("pro_not_installed: developer Pro helper is empty");
            }
            let (execution, artifact_sha256) = UnixExecutionSnapshot::from_source(
                path.parent().ok_or_else(|| {
                    anyhow::anyhow!("pro_not_installed: developer Pro helper has no parent")
                })?,
                &source,
                source_size,
                None,
            )?;
            Ok(Self {
                path: path.to_path_buf(),
                artifact_sha256,
                protocol_fingerprint: ctx_pro_host_protocol::PROTOCOL_FINGERPRINT.to_owned(),
                _validated_identity: None,
                execution,
            })
        }
    }

    /// Consumes one lifecycle-validated artifact identity without reopening
    /// the release marker or interpreting release bytes. The retained handle
    /// is streamed into the OS execution object with fixed memory.
    pub fn from_validated(identity: ValidatedArtifactIdentity) -> Result<Self> {
        let path = identity.path().to_path_buf();
        let data_root = identity.operation().data_root();
        verify_controlled_executable_layout(data_root, &path)?;
        let artifact_sha256 = identity.artifact_sha256().to_owned();
        let protocol_fingerprint = identity.manifest().protocol_fingerprint.clone();

        #[cfg(windows)]
        {
            let directories = lock_controlled_directory_chain(data_root, &path)?;
            let helper = open_locked_file(&path)?;
            verify_open_identity(identity.artifact_file(), &helper, false)?;
            verify_private_file_handle(&helper)
                .context("invalid_response: validated Pro helper ACL is unsafe")?;
            verify_stream_digest(
                &helper,
                identity.artifact_size(),
                &artifact_sha256,
                "validated Pro helper execution handle",
            )?;
            Ok(Self {
                path,
                artifact_sha256,
                protocol_fingerprint,
                _validated_identity: Some(identity),
                _directories: directories,
                helper,
            })
        }
        #[cfg(unix)]
        {
            verify_private_executable(&path)
                .context("invalid_response: validated Pro helper permissions are unsafe")?;
            verify_unix_open_identity(identity.artifact_file(), &path, identity.artifact_size())?;
            let parent = path.parent().ok_or_else(|| {
                anyhow::anyhow!("invalid_response: validated Pro helper has no parent")
            })?;
            let (execution, copied_sha256) = UnixExecutionSnapshot::from_source(
                parent,
                identity.artifact_file(),
                identity.artifact_size(),
                Some(&artifact_sha256),
            )?;
            debug_assert_eq!(copied_sha256, artifact_sha256);
            Ok(Self {
                path,
                artifact_sha256,
                protocol_fingerprint,
                _validated_identity: Some(identity),
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
            Ok(PreparedHelperExecution {
                program: self.execution.descriptor_path(),
                descriptor: self.execution.file.as_raw_fd(),
            })
        }
        #[cfg(windows)]
        Ok(PreparedHelperExecution {
            program: self.path.clone(),
        })
    }

    /// Confirms the final spawn route still resolves to the exact retained
    /// execution object and, where sealing is unavailable, streams a bounded
    /// digest over the retained handle immediately before descriptor-bound exec.
    pub fn verify_execution_identity(&self) -> Result<()> {
        #[cfg(unix)]
        self.execution.verify(&self.artifact_sha256)?;
        #[cfg(windows)]
        {
            if let Some(identity) = &self._validated_identity {
                verify_open_identity(identity.artifact_file(), &self.helper, false)?;
            } else {
                let named = open_file_handle(&self.path)?;
                verify_open_identity(&self.helper, &named, false)?;
            }
            let expected_size = self
                ._validated_identity
                .as_ref()
                .map(ValidatedArtifactIdentity::artifact_size)
                .unwrap_or(self.helper.metadata()?.len());
            verify_stream_digest(
                &self.helper,
                expected_size,
                &self.artifact_sha256,
                "retained Pro execution object",
            )?;
        }
        Ok(())
    }
}

fn stream_digest(file: &fs::File, maximum: u64, label: &str) -> Result<(u64, String)> {
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
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("invalid_request: seek {label} handle"))?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; STREAM_BUFFER_BYTES];
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

fn verify_stream_digest(
    file: &fs::File,
    expected_size: u64,
    expected_sha256: &str,
    label: &str,
) -> Result<()> {
    let (size, digest) = stream_digest(file, expected_size, label)?;
    if size != expected_size || !digest.eq_ignore_ascii_case(expected_sha256) {
        bail!("invalid_response: {label} bytes changed before spawn");
    }
    Ok(())
}

fn stream_copy_and_digest(
    source: &fs::File,
    destination: &mut fs::File,
    expected_size: u64,
    label: &str,
) -> Result<String> {
    let metadata = source
        .metadata()
        .with_context(|| format!("invalid_request: inspect {label} handle"))?;
    if !metadata.is_file() || metadata.len() != expected_size {
        bail!("invalid_response: {label} size changed before execution retention");
    }
    let mut reader = source
        .try_clone()
        .with_context(|| format!("invalid_request: clone {label} handle"))?;
    reader
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("invalid_request: seek {label} handle"))?;
    destination
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("invalid_response: seek retained {label}"))?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; STREAM_BUFFER_BYTES];
    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("invalid_request: read {label} handle"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("invalid_response: {label} exceeds expected size"))?;
        if total > expected_size {
            bail!("invalid_response: {label} exceeds expected size");
        }
        destination
            .write_all(&buffer[..read])
            .with_context(|| format!("invalid_response: populate retained {label}"))?;
        digest.update(&buffer[..read]);
    }
    if total != expected_size || source.metadata()?.len() != expected_size {
        bail!("invalid_response: {label} changed while retaining execution bytes");
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn verify_controlled_executable_layout(data_root: &Path, path: &Path) -> Result<()> {
    if !path.is_absolute() || !path.starts_with(data_root) {
        bail!("invalid_response: validated Pro helper escaped its lifecycle root");
    }
    let mut directory = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid_response: validated Pro helper has no parent"))?;
    loop {
        #[cfg(not(windows))]
        verify_private_directory(directory)
            .context("invalid_response: validated Pro helper directory permissions are unsafe")?;
        if directory == data_root {
            break;
        }
        directory = directory.parent().ok_or_else(|| {
            anyhow::anyhow!("invalid_response: validated Pro helper directory escaped its root")
        })?;
    }
    Ok(())
}

#[cfg(windows)]
fn lock_controlled_directory_chain(data_root: &Path, path: &Path) -> Result<Vec<fs::File>> {
    let mut current = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid_response: validated Pro helper has no parent"))?;
    let mut directories = Vec::new();
    loop {
        directories.push(current.to_path_buf());
        if current == data_root {
            break;
        }
        current = current.parent().ok_or_else(|| {
            anyhow::anyhow!("invalid_response: validated Pro helper directory escaped its root")
        })?;
    }
    directories.reverse();
    directories
        .into_iter()
        .map(|directory| {
            let handle = open_locked_directory(&directory)?;
            verify_private_directory_handle(&handle)
                .context("invalid_response: validated Pro helper directory ACL is unsafe")?;
            Ok(handle)
        })
        .collect()
}

#[cfg(unix)]
fn verify_unix_open_identity(file: &fs::File, path: &Path, artifact_size: u64) -> Result<()> {
    let opened = file
        .metadata()
        .context("invalid_response: inspect validated Pro helper handle")?;
    let named = fs::symlink_metadata(path)
        .context("invalid_response: inspect validated Pro helper path")?;
    if !opened.is_file()
        || !named.is_file()
        || named.file_type().is_symlink()
        || opened.len() != artifact_size
        || opened.dev() != named.dev()
        || opened.ino() != named.ino()
    {
        bail!("invalid_response: validated Pro helper path identity changed");
    }
    Ok(())
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
    fn from_source(
        parent: &Path,
        source: &fs::File,
        expected_size: u64,
        expected_sha256: Option<&str>,
    ) -> Result<(Self, String)> {
        #[cfg(target_os = "linux")]
        if let Some((file, artifact_sha256)) = create_sealed_linux_snapshot(source, expected_size)?
        {
            if expected_sha256
                .is_some_and(|expected| !artifact_sha256.eq_ignore_ascii_case(expected))
            {
                bail!("invalid_response: validated Pro helper changed before execution retention");
            }
            let snapshot = Self {
                identity: UnixFileIdentity::from_file(&file)?,
                file,
                sealed: true,
            };
            snapshot.verify(&artifact_sha256)?;
            return Ok((snapshot, artifact_sha256));
        }

        let (file, artifact_sha256) = create_unlinked_unix_snapshot(parent, source, expected_size)?;
        if expected_sha256.is_some_and(|expected| !artifact_sha256.eq_ignore_ascii_case(expected)) {
            bail!("invalid_response: validated Pro helper changed before execution retention");
        }
        let snapshot = Self {
            identity: UnixFileIdentity::from_file(&file)?,
            file,
            #[cfg(target_os = "linux")]
            sealed: false,
        };
        snapshot.verify(&artifact_sha256)?;
        Ok((snapshot, artifact_sha256))
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
        // `stat(/dev/fd/N)` reports a synthetic fdesc vnode on macOS. Opening
        // the kernel-owned route first yields the duplicated execution object
        // and makes this identity comparison portable across supported Unix.
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

        verify_stream_digest(
            &self.file,
            self.identity.size,
            artifact_sha256,
            "retained Pro execution object",
        )
    }
}

#[cfg(target_os = "linux")]
fn create_sealed_linux_snapshot(
    source: &fs::File,
    expected_size: u64,
) -> Result<Option<(fs::File, String)>> {
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
    let artifact_sha256 =
        stream_copy_and_digest(source, &mut file, expected_size, "validated Pro helper")?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } == -1 {
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::EPERM | libc::EINVAL)) {
            return Ok(None);
        }
        return Err(error).context("invalid_response: seal Pro execution object");
    }
    Ok(Some((file, artifact_sha256)))
}

#[cfg(unix)]
fn create_unlinked_unix_snapshot(
    parent: &Path,
    source: &fs::File,
    expected_size: u64,
) -> Result<(fs::File, String)> {
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
        let artifact_sha256 =
            stream_copy_and_digest(source, &mut writer, expected_size, "validated Pro helper")?;
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
        return Ok((reader, artifact_sha256));
    }
    bail!("invalid_response: allocate unique Pro execution snapshot")
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

#[cfg(test)]
mod streaming_tests {
    use super::*;

    #[test]
    #[ignore = "streams the maximum supported Pro artifact"]
    fn maximum_artifact_digest_uses_the_fixed_streaming_buffer() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("maximum-artifact");
        let file = fs::File::create(&path)?;
        file.set_len(ctx_pro_lifecycle::release_manifest::MAX_ARTIFACT_BYTES)?;
        drop(file);
        let file = fs::File::open(path)?;
        let (size, digest) = stream_digest(
            &file,
            ctx_pro_lifecycle::release_manifest::MAX_ARTIFACT_BYTES,
            "maximum Pro helper",
        )?;
        assert_eq!(
            size,
            ctx_pro_lifecycle::release_manifest::MAX_ARTIFACT_BYTES
        );
        assert_eq!(digest.len(), 64);
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use ctx_history_core::platform_security::{
        restrict_private_directory, restrict_private_executable,
    };
    use ctx_pro_lifecycle::{
        installed_artifact::open_test_artifact_identity, operation::LifecycleOperation,
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
        fs::write(&helper, b"signed helper bytes")?;
        restrict_private_executable(&helper)?;

        let operation = LifecycleOperation::begin(&data_root, true)?.unwrap();
        let identity = open_test_artifact_identity(&operation, &helper)?;
        let locked = VerifiedHelperExecutable::from_validated(identity)?;
        assert!(fs::remove_file(&helper).is_err());
        assert!(fs::rename(&helper, bin.join("replaced.exe")).is_err());
        assert!(fs::write(&helper, b"attacker replacement").is_err());
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
        restrict_private_directory, restrict_private_executable,
    };
    use ctx_pro_lifecycle::{
        installed_artifact::open_test_artifact_identity, operation::LifecycleOperation,
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
    fn staged_path_replacement_executes_retained_lifecycle_bytes() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let data_root = parent.path().join("ctx-data");
        fs::create_dir(&data_root)?;
        restrict_private_directory(&data_root)?;
        let operation = LifecycleOperation::begin(&data_root, true)?.unwrap();
        let stage = ProFilesystemLayout::new(&data_root)
            .downloads_dir()
            .join("bundle-test");
        fs::create_dir_all(&stage)?;
        for directory in [
            ProFilesystemLayout::new(&data_root).downloads_dir(),
            stage.clone(),
        ] {
            restrict_private_directory(&directory)?;
        }
        let path = stage.join("ctx-pro");
        write_executable(&path, TRUSTED_HELPER)?;
        restrict_private_executable(&path)?;

        let identity = open_test_artifact_identity(&operation, &path)?;
        let executable = VerifiedHelperExecutable::from_validated(identity)?;
        fs::rename(&path, stage.join("original-replaced-path"))?;
        write_executable(&path, ATTACKER_HELPER)?;
        restrict_private_executable(&path)?;

        assert_eq!(execute(&executable)?, b"trusted-snapshot");
        Ok(())
    }

    #[test]
    fn unsealed_snapshot_stream_revalidation_rejects_in_place_mutation() -> Result<()> {
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

        file.seek(SeekFrom::Start(0))?;
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
