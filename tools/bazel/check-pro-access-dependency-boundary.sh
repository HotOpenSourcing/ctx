#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'usage: check-pro-access-dependency-boundary.sh ROOT_BUILD' >&2
  exit 64
fi

root_build="$(readlink -f "$1")"
repo_root="$(dirname "${root_build}")"
tmp="$(mktemp -d "${TEST_TMPDIR:-/tmp}/ctx-pro-access-boundary.XXXXXX")"
trap 'rm -rf -- "${tmp}"' EXIT
mkdir -p "${tmp}/home"

query() {
  env -u BUILD_WORKSPACE_DIRECTORY \
    HOME="${tmp}/home" \
    BAZEL_OUTPUT_USER_ROOT="${tmp}/bazel-output" \
    CTX_BAZEL_SANDBOX_BASE="${tmp}/bazel-sandboxes" \
    CTX_BAZEL_WORKSPACE="${repo_root}" \
    "${repo_root}/scripts/bazelw" query "$1" --output=label
}

for target in lib test_support_lib qualification_lib; do
  expected="${tmp}/${target}-expected.txt"
  printf '%s\n' \
    '//crates/ctx-history-core:lib' \
    "//crates/ctx-pro-access:${target}" \
    '//crates/ctx-pro-host-protocol:lib' >"${expected}"
  query "kind(\"rust_library rule\", deps(//crates/ctx-pro-access:${target})) intersect //crates/..." \
    | LC_ALL=C sort -u >"${tmp}/${target}-actual.txt"
  if ! diff -u "${expected}" "${tmp}/${target}-actual.txt"; then
    echo "unexpected internal dependency closure for ctx-pro-access:${target}" >&2
    exit 1
  fi
done

for forbidden in \
  '//crates/ctx-cli:ctx' \
  '//crates/ctx-history-capture:lib' \
  '//crates/ctx-history-index:lib' \
  '//crates/ctx-history-index-generation:lib' \
  '//crates/ctx-history-refresh:lib' \
  '//crates/ctx-protocol:lib' \
  '//crates/ctx-semantic-index:lib' \
  '//crates/ctx-semantic-model:lib' \
  '//crates/ctx-upgrade-engine:lib'; do
  if [[ -n "$(query "somepath(//crates/ctx-pro-access:lib, ${forbidden})")" ]]; then
    echo "ctx-pro-access has forbidden Bazel dependency path to ${forbidden}" >&2
    exit 1
  fi
done
if [[ -z "$(query 'somepath(//crates/ctx-cli:ctx, //crates/ctx-pro-access:lib)')" ]]; then
  echo 'ctx-cli has no Bazel dependency path to ctx-pro-access' >&2
  exit 1
fi

access_root="${repo_root}/crates/ctx-pro-access"
if grep -En 'ctx-(cli|history-(capture|index|index-generation|refresh)|protocol|semantic|upgrade)|(^|[^[:alnum:]_-])clap([^[:alnum:]_-]|$)' \
  "${access_root}/Cargo.toml"; then
  echo 'forbidden Cargo dependency in ctx-pro-access' >&2
  exit 1
fi
if grep -REn --include='*.rs' \
  'Commercial(Config|LifecycleService)|crate::(analytics|capture|daemon|index|mcp|output|semantic|ui|upgrade)::|ctx_(history_capture|history_index|history_refresh|protocol|semantic|upgrade)|(^|[^[:alnum:]_])clap::' \
  "${access_root}/src"; then
  echo 'forbidden host or product-policy source dependency in ctx-pro-access' >&2
  exit 1
fi
if grep -REn --include='*.rs' \
  '(home_dir|device_state_dir|data_local_dir|config_dir|cache_dir)[[:space:]]*\(' \
  "${access_root}/src"; then
  echo 'ctx-pro-access must receive explicit storage scope from its host' >&2
  exit 1
fi
if grep -REn --include='*.rs' --exclude-dir='pro' \
  'ctx_pro_access' "${repo_root}/crates/ctx-cli/src"; then
  echo 'ctx-pro-access must remain confined to the CLI Pro control plane' >&2
  exit 1
fi
if grep -F 'SystemTime' "${access_root}/src/request_identity.rs"; then
  echo 'commercial request identity must use the injected clock' >&2
  exit 1
fi
grep -F '&new_idempotency_key("cli", self.unix_time()?)?' \
  "${access_root}/src/commercial_api.rs" >/dev/null
grep -F '#[derive(Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]' \
  "${access_root}/src/workos_device.rs" >/dev/null
grep -F 'impl std::fmt::Debug for DeviceAuthorization' \
  "${access_root}/src/workos_device.rs" >/dev/null

printf 'ctx-pro-access dependency and composition boundary ok\n'
