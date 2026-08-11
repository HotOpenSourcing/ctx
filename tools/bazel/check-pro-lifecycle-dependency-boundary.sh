#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'usage: check-pro-lifecycle-dependency-boundary.sh ROOT_BUILD' >&2
  exit 64
fi

root_build="$(readlink -f "$1")"
repo_root="$(dirname "${root_build}")"
scratch="$(mktemp -d "${TEST_TMPDIR:-/tmp}/ctx-pro-lifecycle-boundary.XXXXXX")"
trap 'rm -rf -- "${scratch}"' EXIT
mkdir -p "${scratch}/home"

query() {
  env -u BUILD_WORKSPACE_DIRECTORY \
    HOME="${scratch}/home" \
    BAZEL_OUTPUT_USER_ROOT="${scratch}/bazel-output" \
    CTX_BAZEL_SANDBOX_BASE="${scratch}/bazel-sandboxes" \
    CTX_BAZEL_WORKSPACE="${repo_root}" \
    "${repo_root}/scripts/bazelw" query "$1" --output=label
}

for target in lib test_support_lib; do
  printf '%s\n' \
    '//crates/ctx-history-core:lib' \
    '//crates/ctx-pro-access:lib' \
    '//crates/ctx-pro-host-protocol:lib' \
    "//crates/ctx-pro-lifecycle:${target}" \
    | LC_ALL=C sort -u >"${scratch}/${target}-expected.txt"
  query "kind(\"rust_library rule\", deps(//crates/ctx-pro-lifecycle:${target}, 1)) intersect //crates/..." \
    | LC_ALL=C sort -u >"${scratch}/${target}-actual.txt"
  if ! diff -u "${scratch}/${target}-expected.txt" "${scratch}/${target}-actual.txt"; then
    echo "unexpected direct internal dependency set for ctx-pro-lifecycle:${target}" >&2
    exit 1
  fi
done

for consumer in '//crates/ctx-cli:ctx' '//crates/ctx-pro-host:lib'; do
  if [[ -z "$(query "somepath(${consumer}, //crates/ctx-pro-lifecycle:lib)")" ]]; then
    echo "${consumer} has no production dependency path to ctx-pro-lifecycle" >&2
    exit 1
  fi
done
if [[ -n "$(query 'somepath(//crates/ctx-pro-lifecycle:lib, //crates/ctx-pro-host:lib)')" ]]; then
  echo 'ctx-pro-lifecycle has a forbidden dependency path to ctx-pro-host' >&2
  exit 1
fi

python3 - "${repo_root}" <<'PY'
import importlib.util
import pathlib
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
manifest_path = root / "crates/ctx-pro-lifecycle/Cargo.toml"
manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))

dependencies = set(manifest.get("dependencies", {}))
for target in manifest.get("target", {}).values():
    dependencies.update(target.get("dependencies", {}))
expected = {
    "anyhow",
    "base64",
    "ctx-history-core",
    "ctx-pro-access",
    "ctx-pro-host-protocol",
    "fs2",
    "libc",
    "ring",
    "secret-service",
    "security-framework",
    "security-framework-sys",
    "serde",
    "serde_json",
    "sha2",
    "thiserror",
    "ureq",
    "url",
    "uuid",
    "windows-sys",
}
if dependencies != expected:
    raise SystemExit(
        "ctx-pro-lifecycle dependency inventory differs: "
        f"missing={sorted(expected - dependencies)} extra={sorted(dependencies - expected)}"
    )
expected_dev = {"ctx-pro-access", "ed25519-dalek", "tempfile"}
actual_dev = set(manifest.get("dev-dependencies", {}))
if actual_dev != expected_dev:
    raise SystemExit(
        "ctx-pro-lifecycle dev dependency inventory differs: "
        f"missing={sorted(expected_dev - actual_dev)} extra={sorted(actual_dev - expected_dev)}"
    )
if manifest.get("features") != {"default": [], "test-support": []}:
    raise SystemExit("ctx-pro-lifecycle feature inventory differs")

reverse = []
for candidate in sorted((root / "crates").glob("*/Cargo.toml")):
    candidate_manifest = tomllib.loads(candidate.read_text(encoding="utf-8"))
    candidate_dependencies = set(candidate_manifest.get("dependencies", {}))
    candidate_dependencies.update(candidate_manifest.get("dev-dependencies", {}))
    candidate_dependencies.update(candidate_manifest.get("build-dependencies", {}))
    for target in candidate_manifest.get("target", {}).values():
        candidate_dependencies.update(target.get("dependencies", {}))
        candidate_dependencies.update(target.get("dev-dependencies", {}))
        candidate_dependencies.update(target.get("build-dependencies", {}))
    if candidate != manifest_path and "ctx-pro-lifecycle" in candidate_dependencies:
        reverse.append(candidate.relative_to(root).as_posix())
if reverse != ["crates/ctx-cli/Cargo.toml", "crates/ctx-pro-host/Cargo.toml"]:
    raise SystemExit(f"unexpected reverse Cargo consumer of ctx-pro-lifecycle: {reverse}")

spec = importlib.util.spec_from_file_location(
    "check_rust_crate_size", root / "scripts/check-rust-crate-size.py"
)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
measurement = next(
    item for item in module.live_measurements(root)
    if item.package.name == "ctx-pro-lifecycle"
)
if measurement.cloc > 17_500:
    raise SystemExit(
        f"ctx-pro-lifecycle exceeds its 17,500 physical CLOC ceiling: {measurement.cloc}"
    )
print(f"ctx-pro-lifecycle physical CLOC: {measurement.cloc}")
PY

lifecycle_root="${repo_root}/crates/ctx-pro-lifecycle"
host_root="${repo_root}/crates/ctx-pro-host"
if grep -En 'ctx-pro-host([^[:alnum:]_-]|$)' "${lifecycle_root}/Cargo.toml"; then
  echo 'ctx-pro-host dependency leaked into ctx-pro-lifecycle' >&2
  exit 1
fi
if grep -REn --include='*.rs' \
  'ctx_pro_host::|crate::(analytics|config|daemon|output|semantic|ui|upgrade)::|(^|[^[:alnum:]_])clap::' \
  "${lifecycle_root}/src"; then
  echo 'host, CLI, daemon, or presentation authority leaked into ctx-pro-lifecycle' >&2
  exit 1
fi
if grep -REn --include='*.rs' \
  'pub struct (ProManifest|ProInstallMarker|PairIdentity)|PRO_RELEASE_(STABLE|STAGING)_PUBLIC_KEY_PEM' \
  "${repo_root}/crates" \
  | grep -v '/ctx-pro-lifecycle/src/'; then
  echo 'duplicate Pro release trust or signed-pair authority exists outside ctx-pro-lifecycle' >&2
  exit 1
fi
if grep -REn --include='*.rs' \
  'ctx-local-pro-initialized-v1|\.ctx-pro\.initialized' \
  "${repo_root}/crates" \
  | grep -v '/ctx-pro-lifecycle/src/state_markers.rs:'; then
  echo 'initialization marker bytes or path are duplicated outside their lifecycle owner' >&2
  exit 1
fi
grep -F 'pub struct ValidatedArtifactIdentity' \
  "${lifecycle_root}/src/installed_artifact.rs" >/dev/null
grep -F 'artifact: Arc<fs::File>' "${lifecycle_root}/src/installed_artifact.rs" >/dev/null
grep -F 'operation: LifecycleOperation' "${lifecycle_root}/src/installed_artifact.rs" >/dev/null
grep -F 'pub struct LifecycleOperation' "${lifecycle_root}/src/operation.rs" >/dev/null
grep -F 'ValidatedArtifactIdentity' "${host_root}/src/host_port.rs" >/dev/null
grep -F 'STREAM_BUFFER_BYTES' "${host_root}/src/verified_executable.rs" >/dev/null
grep -F 'stream_copy_and_digest' "${host_root}/src/verified_executable.rs" >/dev/null
if grep -En 'read_to_end|Vec::with_capacity|fs::read\(' \
  "${host_root}/src/verified_executable.rs"; then
  echo 'host retained-executable verification must remain fixed-buffer streaming' >&2
  exit 1
fi

printf 'ctx-pro-lifecycle release, mutation, guard, and host-port boundary ok\n'
