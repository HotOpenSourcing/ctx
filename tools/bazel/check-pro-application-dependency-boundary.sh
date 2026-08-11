#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'usage: check-pro-application-dependency-boundary.sh ROOT_BUILD' >&2
  exit 64
fi

root_build="$(readlink -f "$1")"
repo_root="$(dirname "${root_build}")"
scratch="$(mktemp -d "${TEST_TMPDIR:-/tmp}/ctx-pro-application-boundary.XXXXXX")"
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
  local host_target="$3"
  local lifecycle_target="$4"
  local expected="${scratch}/${target}-expected.txt"
  printf '%s\n' \
    '//crates/ctx-history-index:lib' \
    "//crates/ctx-pro-access:${access_target}" \
    "//crates/ctx-pro-application:${target}" \
    "//crates/ctx-pro-host:${host_target}" \
    '//crates/ctx-pro-host-protocol:lib' \
    "//crates/ctx-pro-lifecycle:${lifecycle_target}" \
    | LC_ALL=C sort -u >"${expected}"
  query "kind(\"rust_library rule\", deps(//crates/ctx-pro-application:${target}, 1)) intersect //crates/..." \
    | LC_ALL=C sort -u >"${scratch}/${target}-actual.txt"
  if ! diff -u "${expected}" "${scratch}/${target}-actual.txt"; then
    echo "unexpected direct internal dependency set for ctx-pro-application:${target}" >&2
    exit 1
  fi
}

check_direct_internal_deps lib lib lib lib
check_direct_internal_deps test_support_lib test_support_lib test_support_lib test_support_lib
check_direct_internal_deps qualification_lib qualification_lib qualification_lib qualification_lib
check_direct_internal_deps \
  qualification_test_support_lib qualification_lib qualification_test_support_lib qualification_test_support_lib

check_reverse_consumers() {
  local target="$1"
  local kinds="$2"
  shift 2
  printf '%s\n' "$@" | LC_ALL=C sort -u >"${scratch}/${target}-reverse-expected.txt"
  query "${kinds}" | LC_ALL=C sort -u >"${scratch}/${target}-reverse-actual.txt"
  if ! diff -u \
    "${scratch}/${target}-reverse-expected.txt" \
    "${scratch}/${target}-reverse-actual.txt"; then
    echo "unexpected consumer of ctx-pro-application:${target}" >&2
    exit 1
  fi
}

check_reverse_consumers lib \
  'kind("rust_binary rule", rdeps(//crates/..., //crates/ctx-pro-application:lib)) union kind("rust_library rule", rdeps(//crates/..., //crates/ctx-pro-application:lib))' \
  '//crates/ctx-cli:ctx' \
  '//crates/ctx-pro-application:lib'
check_reverse_consumers test_support_lib \
  'kind("rust_library rule", rdeps(//crates/..., //crates/ctx-pro-application:test_support_lib)) union kind("rust_test rule", rdeps(//crates/..., //crates/ctx-pro-application:test_support_lib))' \
  '//crates/ctx-cli:unit_tests' \
  '//crates/ctx-pro-application:test_support_lib'
check_reverse_consumers qualification_lib \
  'kind("rust_binary rule", rdeps(//crates/..., //crates/ctx-pro-application:qualification_lib)) union kind("rust_library rule", rdeps(//crates/..., //crates/ctx-pro-application:qualification_lib))' \
  '//crates/ctx-cli:ctx_auto_upgrade_acceptance_fixture' \
  '//crates/ctx-cli:ctx_hosted_uninstall_test_host' \
  '//crates/ctx-cli:ctx_upgrade_test_harness' \
  '//crates/ctx-pro-application:qualification_lib'
check_reverse_consumers qualification_test_support_lib \
  'kind("rust_binary rule", rdeps(//crates/..., //crates/ctx-pro-application:qualification_test_support_lib)) union kind("rust_library rule", rdeps(//crates/..., //crates/ctx-pro-application:qualification_test_support_lib)) union kind("rust_test rule", rdeps(//crates/..., //crates/ctx-pro-application:qualification_test_support_lib))' \
  '//crates/ctx-cli:ctx_pro_test_host' \
  '//crates/ctx-cli:pro_host_tests' \
  '//crates/ctx-cli:pro_mcp_tests' \
  '//crates/ctx-cli:pro_test_control_tests' \
  '//crates/ctx-pro-application:qualification_test_support_lib'

python3 - "${repo_root}" <<'PY'
import pathlib
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
manifest_path = root / "crates/ctx-pro-application/Cargo.toml"
manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
expected_dependencies = {
    "anyhow",
    "ctx-history-index",
    "ctx-pro-access",
    "ctx-pro-host",
    "ctx-pro-host-protocol",
    "ctx-pro-lifecycle",
    "serde",
    "serde_json",
    "url",
    "uuid",
}
actual_dependencies = set(manifest.get("dependencies", {}))
if actual_dependencies != expected_dependencies:
    raise SystemExit(
        "ctx-pro-application dependency inventory differs: "
        f"missing={sorted(expected_dependencies - actual_dependencies)} "
        f"extra={sorted(actual_dependencies - expected_dependencies)}"
    )
expected_dev_dependencies = {"ctx-history-core", "sha2", "tempfile"}
actual_dev_dependencies = set(manifest.get("dev-dependencies", {}))
if actual_dev_dependencies != expected_dev_dependencies:
    raise SystemExit(
        "ctx-pro-application dev dependency inventory differs: "
        f"missing={sorted(expected_dev_dependencies - actual_dev_dependencies)} "
        f"extra={sorted(actual_dev_dependencies - expected_dev_dependencies)}"
    )
if manifest.get("features"):
    raise SystemExit("ctx-pro-application must not define feature-selected authority")

reverse = []
for candidate in sorted((root / "crates").glob("*/Cargo.toml")):
    if candidate == manifest_path:
        continue
    candidate_manifest = tomllib.loads(candidate.read_text(encoding="utf-8"))
    dependencies = set(candidate_manifest.get("dependencies", {}))
    dependencies.update(candidate_manifest.get("dev-dependencies", {}))
    dependencies.update(candidate_manifest.get("build-dependencies", {}))
    for target in candidate_manifest.get("target", {}).values():
        dependencies.update(target.get("dependencies", {}))
        dependencies.update(target.get("dev-dependencies", {}))
        dependencies.update(target.get("build-dependencies", {}))
    if "ctx-pro-application" in dependencies:
        reverse.append(candidate.relative_to(root).as_posix())
if reverse != ["crates/ctx-cli/Cargo.toml"]:
    raise SystemExit(f"unexpected reverse Cargo consumer of ctx-pro-application: {reverse}")

physical = sum(
    len(path.read_text(encoding="utf-8").splitlines())
    for path in (root / "crates/ctx-pro-application/src").rglob("*.rs")
)
if physical > 13_000:
    raise SystemExit(
        "ctx-pro-application exceeds its 13,000 physical Rust reshape boundary: "
        f"{physical}"
    )
print(f"ctx-pro-application physical Rust lines: {physical}")
PY

application_root="${repo_root}/crates/ctx-pro-application"
if find "${application_root}" -type l -print -quit | grep -q .; then
  echo 'ctx-pro-application must contain no symlinked source or metadata' >&2
  exit 1
fi
if find "${application_root}" -name '*.rs' ! -path "${application_root}/src/*" -print -quit | grep -q .; then
  echo 'ctx-pro-application Rust sources must remain package-local under src' >&2
  exit 1
fi
if grep -En 'ctx-(agent-integrations|cli|client-observability|daemon-application|daemon-runtime|daemon-service|history-capture|history-jsonl|history-query|history-refresh|history-repository-evidence|semantic-index|semantic-model|terminal|upgrade-engine)([^[:alnum:]_-]|$)|(^|[^[:alnum:]_-])(clap|git2|ureq)([^[:alnum:]_-]|$)' \
  "${application_root}/Cargo.toml"; then
  echo 'excluded presentation, daemon, provider, semantic, or concrete network dependency leaked into ctx-pro-application' >&2
  exit 1
fi
if grep -REn --include='*.rs' \
  'ctx_(agent_integrations|client_observability|daemon_application|daemon_runtime|daemon_service|history_capture|history_jsonl|history_query|history_refresh|history_repository_evidence|semantic_index|semantic_model|terminal|upgrade_engine)::|(^|[^[:alnum:]_])(clap|git2|ureq)::|crate::(analytics|commands|config|daemon|identity|output|pro|semantic|ui|upgrade)::|std::process::|\b(Command|Ui)\b' \
  "${application_root}/src"; then
  echo 'CLI, daemon, provider, browser/process, or generic semantic authority leaked into ctx-pro-application source' >&2
  exit 1
fi
if grep -REn --include='*.rs' \
  'thread_local!|ACTIVE_HOST|Box::leak|#\[path|include!|(^|[^[:alnum:]_])unsafe([^[:alnum:]_]|$)' \
  "${application_root}/src"; then
  echo 'global host registry, lifetime escape, source indirection, or unsafe boundary leaked into ctx-pro-application' >&2
  exit 1
fi

cli_pro="${repo_root}/crates/ctx-cli/src/pro"
if [[ -e "${cli_pro}/commercial_production_record.rs" ]] || \
   [[ -e "${cli_pro}/lifecycle_commands/validation.rs" ]]; then
  echo 'superseded production record or validation authority remains in ctx-cli' >&2
  exit 1
fi
if grep -REn --include='*.rs' \
  'struct StoredAuthorizationProvider|struct CommercialChannelRecord|store_anonymous_trial_state|VaultAuthorizationProvider|fetch_latest\(|fn (setup_with_access_policy|anonymous_trial_requires_conversion|anonymous_trial_precedes_paid_conversion|resolve_active_state|poll_checkout_account|poll_checkout_access|checkout_poll_ended|entitlement_still_usable|refresh_entitlement_noninteractive|clear_refresh_backoff|defer_entitlement_refresh|checkout_anonymous_trial|local_entitlement_deadlines)\b' \
  "${cli_pro}"; then
  echo 'superseded authorization, commercial lifecycle, trial storage, or artifact acquisition authority remains in ctx-cli' >&2
  exit 1
fi

printf 'ctx-pro-application dependency, locality, and single-authority boundary ok\n'
