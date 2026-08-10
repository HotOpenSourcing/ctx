#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${RUNFILES_DIR:-}" ]]; then
  root="${RUNFILES_DIR}/_main"
elif [[ -n "${TEST_SRCDIR:-}" ]]; then
  root="${TEST_SRCDIR}/_main"
else
  root="${BUILD_WORKSPACE_DIRECTORY:-$(cd "$(dirname "$0")/../.." && pwd)}"
fi

access_build="${root}/crates/ctx-pro-access/BUILD.bazel"
access_manifest="${root}/crates/ctx-pro-access/Cargo.toml"
access_sources="${root}/crates/ctx-pro-access/src"
cli_build="${root}/crates/ctx-cli/BUILD.bazel"
cli_manifest="${root}/crates/ctx-cli/Cargo.toml"

grep -F '[features]' "${access_manifest}" >/dev/null
grep -F 'qualification = []' "${access_manifest}" >/dev/null
grep -F 'test-support = []' "${access_manifest}" >/dev/null

for target in lib test_support_lib qualification_lib unit_tests qualification_authorizer_tests; do
  grep -F "name = \"${target}\"" "${access_build}" >/dev/null
done
grep -F -- '--check-cfg=cfg(feature, values("qualification", "test-support"))' "${access_build}" >/dev/null
grep -F -- '--cfg=feature="qualification"' "${access_build}" >/dev/null
grep -F -- '--cfg=feature="test-support"' "${access_build}" >/dev/null

grep -F 'target_os = "linux"' "${access_manifest}" >/dev/null
grep -F 'target_os = "macos"' "${access_manifest}" >/dev/null
grep -F "cfg(windows)" "${access_manifest}" >/dev/null
for source in linux.rs macos.rs secret_service.rs windows.rs windows_file.rs; do
  test -f "${access_sources}/credential_vault/${source}"
done

grep -F '"//crates/ctx-pro-access:lib"' "${cli_build}" >/dev/null
grep -F '"//crates/ctx-pro-access:test_support_lib"' "${cli_build}" >/dev/null
grep -F '"//crates/ctx-pro-access:qualification_lib"' "${cli_build}" >/dev/null
grep -F 'ctx-pro-access = { path = "../ctx-pro-access" }' "${cli_manifest}" >/dev/null
grep -F 'ctx-pro-access = { path = "../ctx-pro-access", features = ["test-support"] }' \
  "${cli_manifest}" >/dev/null

if [[ -e "${root}/crates/ctx-pro-access/build.rs" ]]; then
  echo 'ctx-pro-access unexpectedly gained a build-script cfg authority' >&2
  exit 1
fi

printf 'ctx-pro-access Cargo/Bazel cfg, qualification, and platform parity ok\n'
