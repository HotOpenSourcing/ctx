#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'usage: check-client-observability-boundary.sh ROOT_BUILD' >&2
  exit 64
fi

root_build="$(readlink -f "$1")"
repo_root="$(dirname "${root_build}")"
scratch="$(mktemp -d "${TEST_TMPDIR:-/tmp}/ctx-client-observability-boundary.XXXXXX")"
trap 'rm -rf -- "${scratch}"' EXIT

query() {
  env -u BUILD_WORKSPACE_DIRECTORY \
    BAZEL_OUTPUT_USER_ROOT="${scratch}/bazel-output" \
    CTX_BAZEL_SANDBOX_BASE="${scratch}/bazel-sandboxes" \
    CTX_BAZEL_WORKSPACE="${repo_root}" \
    "${repo_root}/scripts/bazelw" query "$1" --output=label
}

for target in lib test_support_lib; do
  actual="$(query "kind(\"rust_library rule\", deps(//crates/ctx-client-observability:${target})) intersect //crates/..." | LC_ALL=C sort -u)"
  expected="$(printf '%s\n' \
    '//crates/ctx-client-observability:'"${target}" \
    '//crates/ctx-history-core:lib')"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "unexpected internal dependency closure for ctx-client-observability:${target}" >&2
    diff -u <(printf '%s\n' "${expected}") <(printf '%s\n' "${actual}") || true
    exit 1
  fi
done

if [[ -z "$(query 'somepath(//crates/ctx-cli:ctx, //crates/ctx-client-observability:lib)')" ]]; then
  echo 'ctx-cli has no dependency path to ctx-client-observability' >&2
  exit 1
fi
for forbidden in \
  '//crates/ctx-cli:ctx' \
  '//crates/ctx-daemon-service:lib' \
  '//crates/ctx-history-capture:lib' \
  '//crates/ctx-history-index:lib' \
  '//crates/ctx-history-refresh:lib' \
  '//crates/ctx-pro-host-protocol:lib' \
  '//crates/ctx-semantic-index:lib' \
  '//crates/ctx-semantic-model:lib' \
  '//crates/ctx-upgrade-engine:lib'; do
  if [[ -n "$(query "somepath(//crates/ctx-client-observability:lib, ${forbidden})")" ]]; then
    echo "ctx-client-observability has forbidden dependency path to ${forbidden}" >&2
    exit 1
  fi
done

python3 - "${repo_root}" <<'PY'
import importlib.util
import pathlib
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
manifest = tomllib.loads((root / "crates/ctx-client-observability/Cargo.toml").read_text())
dependencies = set(manifest.get("dependencies", {}))
for target in manifest.get("target", {}).values():
    dependencies.update(target.get("dependencies", {}))
allowed = {
    "anyhow", "chrono", "ctx-history-core", "libc", "rusqlite", "same-file",
    "serde", "serde_json", "thiserror", "uuid", "windows-sys",
}
if dependencies != allowed:
    raise SystemExit(
        "ctx-client-observability dependency inventory differs: "
        f"missing={sorted(allowed - dependencies)} extra={sorted(dependencies - allowed)}"
    )
if set(manifest.get("dev-dependencies", {})) != {"tempfile"}:
    raise SystemExit("ctx-client-observability dev dependencies must be exactly tempfile")
if set(manifest.get("features", {})) != {"test-support"}:
    raise SystemExit("ctx-client-observability features must be exactly test-support")

sys.modules["tomli"] = tomllib
spec = importlib.util.spec_from_file_location(
    "check_rust_crate_size", root / "scripts/check-rust-crate-size.py"
)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
measurement = next(
    item for item in module.live_measurements(root)
    if item.package.name == "ctx-client-observability"
)
if measurement.cloc > 11_500:
    raise SystemExit(
        "ctx-client-observability exceeds its 11,500 physical CLOC ceiling: "
        f"{measurement.cloc}"
    )
print(f"ctx-client-observability physical CLOC: {measurement.cloc}")
PY

crate_root="${repo_root}/crates/ctx-client-observability"
if grep -En 'ctx-(agent-integrations|cli|daemon-runtime|history-capture|history-index|history-refresh|pro-host|semantic|upgrade)([^[:alnum:]_-]|$)|(^|[^[:alnum:]_-])(clap|ureq)([^[:alnum:]_-]|$)' \
  "${crate_root}/Cargo.toml"; then
  echo 'forbidden Cargo dependency in ctx-client-observability' >&2
  exit 1
fi
if grep -REn --include='*.rs' \
  'ctx_(agent_integrations|history_capture|history_index|history_refresh|pro_host|semantic|upgrade)::|(^|[^[:alnum:]_])(AppConfig|CommandRoot|McpHandled|RequestDescriptor)([^[:alnum:]_]|$)|(^|[^[:alnum:]_])(clap|ureq)::|crate::(config|net|output|pro|ui)::' \
  "${crate_root}/src"; then
  echo 'runtime, presentation, raw protocol, or sibling authority leaked into ctx-client-observability' >&2
  exit 1
fi

grep -Fq 'crate::identity::device_id' "${repo_root}/crates/ctx-cli/src/observability_composition.rs"
grep -Fq 'crate::net::post_telemetry_json' "${repo_root}/crates/ctx-cli/src/observability_composition.rs"
grep -Fq 'ctx_pro_host_protocol' "${repo_root}/crates/ctx-cli/src/observability_product.rs"
grep -Fq 'RequestDescriptor' "${repo_root}/crates/ctx-cli/src/mcp.rs"

printf 'ctx-client-observability dependency and composition boundary ok\n'
