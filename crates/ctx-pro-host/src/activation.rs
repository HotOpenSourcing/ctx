use std::{
    io::Read,
    path::Path,
    process::Stdio,
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context as _, Result};
use ctx_pro_lifecycle::installed_artifact::ValidatedArtifactIdentity;

use crate::{helper_command, InstalledProHost, VerifiedHelperExecutable};

const DEVICE_EVIDENCE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_DEVICE_EVIDENCE_BYTES: u64 = 32 * 1024;

/// Runs pre-authorization activation evidence with the exact lifecycle-
/// validated staged executable. Process setup and executable identity remain
/// host responsibilities; release bytes are not read or hashed here.
pub fn activation_material(
    host: &(impl InstalledProHost + ?Sized),
    data_root: &Path,
    identity: ValidatedArtifactIdentity,
    challenge_base64url: &str,
    installation_public_key_base64url: &str,
) -> Result<serde_json::Value> {
    identity.operation().require_data_root(data_root)?;
    let executable = VerifiedHelperExecutable::from_validated(identity)?;
    activation_material_with_executable(
        host,
        data_root,
        executable,
        challenge_base64url,
        installation_public_key_base64url,
    )
}

fn activation_material_with_executable(
    host: &(impl InstalledProHost + ?Sized),
    data_root: &Path,
    executable: VerifiedHelperExecutable,
    challenge_base64url: &str,
    installation_public_key_base64url: &str,
) -> Result<serde_json::Value> {
    let prepared = executable.prepare_execution()?;
    let installation_id = host
        .existing_installation_id(data_root)
        .context("key_store_unavailable: load local Pro installation identity")?
        .ok_or_else(|| {
            anyhow!("key_store_unavailable: local Pro installation identity is missing")
        })?;
    let mut command = helper_command::new(prepared.program(), data_root, &installation_id, None)?;
    command
        .arg("_activation-material")
        .arg(challenge_base64url)
        .arg(installation_public_key_base64url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    prepared.configure_command(&mut command);
    let mut child = command
        .spawn()
        .context("helper_crashed: start signed Pro activation helper")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("helper_crashed: activation helper stdout is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("helper_crashed: activation helper stderr is unavailable"))?;
    let stdout_reader = thread::spawn(move || read_bounded_pipe(stdout));
    let stderr_reader = thread::spawn(move || read_bounded_pipe(stderr));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .context("helper_crashed: poll activation helper")?
        {
            break status;
        }
        if started.elapsed() >= DEVICE_EVIDENCE_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            bail!("helper_timeout: Pro activation helper timed out");
        }
        thread::sleep(Duration::from_millis(25));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow!("helper_crashed: activation helper output reader failed"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow!("helper_crashed: activation helper error reader failed"))??;
    drop((stderr, prepared, executable));
    if !status.success() {
        bail!("helper_crashed: Pro activation evidence is unavailable");
    }
    serde_json::from_slice(&stdout)
        .context("invalid_response: Pro activation helper returned malformed evidence")
}

fn read_bounded_pipe(pipe: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.take(MAX_DEVICE_EVIDENCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("helper_crashed: read activation helper output")?;
    if bytes.len() as u64 > MAX_DEVICE_EVIDENCE_BYTES {
        bail!("invalid_response: Pro activation helper output exceeds maximum size");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::{fs, os::unix::fs::PermissionsExt as _};

    use ctx_pro_host_protocol::AUTHORIZATION_CHALLENGE_BYTES;

    use super::*;
    use crate::{AuthorizationMode, AuthorizationReceipt};

    struct ActivationHost {
        installation_id: String,
    }

    impl InstalledProHost for ActivationHost {
        fn host_version(&self) -> &str {
            "test"
        }

        fn existing_installation_id(&self, _data_root: &Path) -> Result<Option<String>> {
            Ok(Some(self.installation_id.clone()))
        }

        fn validated_installed_helper(
            &self,
            _data_root: &Path,
            _operation: Option<&ctx_pro_lifecycle::operation::LifecycleOperation>,
        ) -> Result<ValidatedArtifactIdentity> {
            unreachable!("activation fixture receives an explicit validated identity")
        }

        fn authorization_for_challenge(
            &self,
            _data_root: &Path,
            _challenge: &[u8; AUTHORIZATION_CHALLENGE_BYTES],
            _mode: AuthorizationMode,
        ) -> Result<AuthorizationReceipt> {
            unreachable!("activation fixture does not request protocol authorization")
        }

        fn unix_time(&self) -> Result<i64> {
            Ok(0)
        }
    }

    #[cfg(unix)]
    fn write_activation_fixture(path: &Path, body: &str) {
        fs::write(path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }

    #[cfg(unix)]
    #[test]
    fn activation_process_preserves_environment_contract() {
        let root = tempfile::tempdir().unwrap();
        let installation_id = "12345678-1234-4234-8234-123456789abc".to_owned();
        let pro_root = ctx_pro_host_protocol::ProFilesystemLayout::new(root.path()).pro_root();
        let helper = root.path().join("activation-fixture");
        let evidence = serde_json::json!({
            "schema_version": 1,
            "payload_type": "activation_material",
            "evidence": {"anchor": "opaque-fixture"},
        });
        let body = format!(
            r#"
expected_data_root={}
expected_pro_root={}
expected_installation_id={}
[ "${{CTX_DATA_ROOT-}}" = "$expected_data_root" ] || exit 21
[ "${{CTX_PRO_DATA_ROOT-}}" = "$expected_pro_root" ] || exit 22
[ "${{CTX_PRO_INSTALLATION_ID-}}" = "$expected_installation_id" ] || exit 23
[ "${{CTX_PRO_GIT_EXECUTABLE+x}}" != x ] || exit 26
[ "$#" -eq 3 ] || exit 31
[ "$1" = "_activation-material" ] || exit 32
[ "$2" = "challenge-base64url" ] || exit 33
[ "$3" = "installation-public-key-base64url" ] || exit 34
printf '%s' '{}'
"#,
            shell_quote(&root.path().to_string_lossy()),
            shell_quote(&pro_root.to_string_lossy()),
            shell_quote(&installation_id),
            evidence,
        );
        write_activation_fixture(&helper, &body);
        let host = ActivationHost { installation_id };
        let executable = VerifiedHelperExecutable::open_developer(&helper).unwrap();

        let actual = activation_material_with_executable(
            &host,
            root.path(),
            executable,
            "challenge-base64url",
            "installation-public-key-base64url",
        )
        .unwrap();
        assert_eq!(actual, evidence);
    }

    #[cfg(unix)]
    #[test]
    fn activation_failure_does_not_expose_output_or_invocation_material() {
        let root = tempfile::tempdir().unwrap();
        let helper = root.path().join("failing-activation-fixture");
        write_activation_fixture(
            &helper,
            "printf '%s' 'fixture-stdout-must-not-escape'; printf '%s' 'fixture-stderr-must-not-escape' >&2; exit 41",
        );
        let host = ActivationHost {
            installation_id: "12345678-1234-4234-8234-123456789abc".to_owned(),
        };
        let executable = VerifiedHelperExecutable::open_developer(&helper).unwrap();
        let error = activation_material_with_executable(
            &host,
            root.path(),
            executable,
            "challenge-must-not-escape",
            "public-key-must-not-escape",
        )
        .unwrap_err();
        let message = error.to_string();
        assert_eq!(
            message,
            "helper_crashed: Pro activation evidence is unavailable"
        );
        for forbidden in [
            "fixture-stdout-must-not-escape",
            "fixture-stderr-must-not-escape",
            "challenge-must-not-escape",
            "public-key-must-not-escape",
            root.path().to_string_lossy().as_ref(),
        ] {
            assert!(
                !message.contains(forbidden),
                "{forbidden} escaped: {message}"
            );
        }
    }
}
