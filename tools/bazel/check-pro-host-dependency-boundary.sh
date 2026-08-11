#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'usage: check-pro-host-dependency-boundary.sh ROOT_BUILD' >&2
  exit 64
fi

root_build="$(readlink -f "$1")"
repo_root="$(dirname "${root_build}")"
scratch="$(mktemp -d "${TEST_TMPDIR:-/tmp}/ctx-pro-host-boundary.XXXXXX")"
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

check_direct_internal_deps() {
  local target="$1"
  local access_target="$2"
  local lifecycle_target="$3"
  local expected="${scratch}/${target}-expected.txt"
  printf '%s\n' \
    '//crates/ctx-history-core:lib' \
    '//crates/ctx-history-index-format:lib' \
    '//crates/ctx-history-index-generation:lib' \
    '//crates/ctx-history-index-query:lib' \
    '//crates/ctx-history-refresh:lib' \
    "//crates/ctx-pro-access:${access_target}" \
    "//crates/ctx-pro-host:${target}" \
    '//crates/ctx-pro-host-protocol:lib' \
    "//crates/ctx-pro-lifecycle:${lifecycle_target}" \
    | LC_ALL=C sort -u >"${expected}"
  query "kind(\"rust_library rule\", deps(//crates/ctx-pro-host:${target}, 1)) intersect //crates/..." \
    | LC_ALL=C sort -u >"${scratch}/${target}-actual.txt"
  if ! diff -u "${expected}" "${scratch}/${target}-actual.txt"; then
    echo "unexpected direct internal dependency set for ctx-pro-host:${target}" >&2
    exit 1
  fi
}

check_direct_internal_deps lib lib lib
check_direct_internal_deps test_support_lib test_support_lib test_support_lib
check_direct_internal_deps qualification_lib qualification_lib qualification_lib
check_direct_internal_deps qualification_test_support_lib qualification_lib qualification_test_support_lib

if [[ -z "$(query 'somepath(//crates/ctx-cli:ctx, //crates/ctx-pro-host:lib)')" ]]; then
  echo 'ctx-cli has no production dependency path to ctx-pro-host' >&2
  exit 1
fi

python3 - "${repo_root}" <<'PY'
import importlib.util
import pathlib
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
manifest_path = root / "crates/ctx-pro-host/Cargo.toml"
manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))

dependencies = set(manifest.get("dependencies", {}))
for target in manifest.get("target", {}).values():
    dependencies.update(target.get("dependencies", {}))
expected = {
    "anyhow",
    "base64",
    "ctx-history-core",
    "ctx-history-index-format",
    "ctx-history-index-generation",
    "ctx-history-index-query",
    "ctx-history-refresh",
    "ctx-pro-access",
    "ctx-pro-host-protocol",
    "ctx-pro-lifecycle",
    "libc",
    "ring",
    "serde",
    "serde_json",
    "sha2",
    "thiserror",
    "uuid",
    "windows-sys",
}
if dependencies != expected:
    raise SystemExit(
        "ctx-pro-host dependency inventory differs: "
        f"missing={sorted(expected - dependencies)} extra={sorted(dependencies - expected)}"
    )
if set(manifest.get("dev-dependencies", {})) != {
    "ctx-history-index",
    "ctx-pro-lifecycle",
    "tempfile",
}:
    raise SystemExit("ctx-pro-host dev dependency inventory differs")
if manifest.get("features") != {
    "default": [],
    "qualification": ["ctx-pro-access/qualification"],
    "test-support": ["ctx-pro-access/test-support"],
}:
    raise SystemExit("ctx-pro-host feature inventory differs")

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
    if candidate != manifest_path and "ctx-pro-host" in candidate_dependencies:
        reverse.append(candidate.relative_to(root).as_posix())
if reverse != ["crates/ctx-cli/Cargo.toml"]:
    raise SystemExit(f"unexpected reverse Cargo consumer of ctx-pro-host: {reverse}")

spec = importlib.util.spec_from_file_location(
    "check_rust_crate_size", root / "scripts/check-rust-crate-size.py"
)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
measurement = next(
    item for item in module.live_measurements(root)
    if item.package.name == "ctx-pro-host"
)
if measurement.cloc > 18_500:
    raise SystemExit(
        f"ctx-pro-host exceeds its 18,500 physical CLOC ceiling: {measurement.cloc}"
    )
print(f"ctx-pro-host physical CLOC: {measurement.cloc}")
PY

host_root="${repo_root}/crates/ctx-pro-host"
if grep -En 'ctx-(agent-integrations|cli|client-observability|daemon-runtime|daemon-service|semantic-index|semantic-model|upgrade-engine)[^[:alnum:]_-]' \
  "${host_root}/Cargo.toml"; then
  echo 'product composition dependency leaked into ctx-pro-host' >&2
  exit 1
fi
if grep -REn --include='*.rs' \
  'ctx_(agent_integrations|client_observability|daemon_runtime|daemon_service|semantic_index|semantic_model|upgrade_engine)::|crate::(analytics|config|daemon|output|semantic|ui|upgrade)::|(^|[^[:alnum:]_])clap::' \
  "${host_root}/src"; then
  echo 'CLI, daemon, observability, presentation, or product policy leaked into ctx-pro-host' >&2
  exit 1
fi
if [[ -e "${host_root}/build.rs" ]]; then
  echo 'ctx-pro-host unexpectedly gained a build-script cfg authority' >&2
  exit 1
fi
if grep -REn --include='*.rs' \
  'pub struct (ProManifest|ProInstallMarker|PairIdentity)|PRO_RELEASE_(STABLE|STAGING)_PUBLIC_KEY_PEM|signed_manifest|validate_manifest_release_trust|read_marker' \
  "${host_root}/src"; then
  echo 'signed lifecycle manifest authority leaked into the host port or protocol transport' >&2
  exit 1
fi

cli_manifest="${repo_root}/crates/ctx-cli/Cargo.toml"
cli_build="${repo_root}/crates/ctx-cli/BUILD.bazel"
cli_lifecycle="${repo_root}/crates/ctx-cli/src/pro/lifecycle.rs"
grep -F 'ctx-pro-host = { path = "../ctx-pro-host" }' "${cli_manifest}" >/dev/null
grep -F 'ctx-pro-host = { path = "../ctx-pro-host", features = ["test-support"] }' \
  "${cli_manifest}" >/dev/null
for target in lib test_support_lib qualification_lib qualification_test_support_lib; do
  grep -F "\"//crates/ctx-pro-host:${target}\"" "${cli_build}" >/dev/null
done
grep -F 'ValidatedArtifactIdentity' "${host_root}/src/host_port.rs" >/dev/null
grep -F 'LifecycleOperation' "${host_root}/src/host_port.rs" >/dev/null
grep -F 'ctx_pro_lifecycle::installation::discover_installed_artifact' \
  "${repo_root}/crates/ctx-cli/src/pro/client.rs" >/dev/null
grep -F 'ValidatedArtifactIdentity' "${host_root}/src/verified_executable.rs" >/dev/null
grep -F 'STREAM_BUFFER_BYTES' "${host_root}/src/verified_executable.rs" >/dev/null
grep -F 'stream_digest(' "${host_root}/src/verified_executable.rs" >/dev/null
if grep -REn --include='*.rs' \
  'LifecycleValidatedHelper|helper\.(read_helper|read_marker)|retain_installation_guard' \
  "${repo_root}/crates/ctx-cli/src/pro" "${host_root}/src"; then
  echo 'CLI or host duplicates lifecycle artifact reads or guard binding' >&2
  exit 1
fi
if grep -En 'read_to_end|Vec::with_capacity|fs::read\(' \
  "${host_root}/src/verified_executable.rs"; then
  echo 'host executable verification must use fixed-buffer retained-handle streaming' >&2
  exit 1
fi

for stale in \
  client/materialization.rs \
  client/operations.rs \
  client/transport.rs \
  client_errors.rs \
  client_output.rs \
  client_output \
  client_status.rs \
  client_support.rs \
  client_tests.rs \
  core_worker_budget.rs \
  diagnostic.rs \
  evidence_preview \
  helper_command_tests.rs \
  lifecycle_manifest.rs \
  verified_executable.rs; do
  if [[ -e "${repo_root}/crates/ctx-cli/src/pro/${stale}" ]]; then
    echo "stale duplicate Pro host authority remains in ctx-cli: ${stale}" >&2
    exit 1
  fi
done

grep -Fq 'fn materialization_finalization_receipt_preserves_exact_output_bytes()' \
  "${host_root}/src/client_tests.rs"
grep -Fq 'fn active_core_pin_lifetime_covers_the_complete_status_exchange()' \
  "${host_root}/src/client_tests.rs"

printf 'ctx-pro-host dependency, composition, and contract boundary ok\n'
