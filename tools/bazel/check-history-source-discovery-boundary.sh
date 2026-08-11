#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'usage: check-history-source-discovery-boundary.sh ROOT_BUILD' >&2
  exit 64
fi

root_build="$(readlink -f "$1")"
root="$(dirname "${root_build}")"
manifest="${root}/crates/ctx-history-source-discovery/Cargo.toml"

python3 - "${manifest}" "${root}/crates/ctx-history-source-discovery/src" <<'PY'
import pathlib
import re
import sys
import tomllib

manifest_path = pathlib.Path(sys.argv[1])
source_root = pathlib.Path(sys.argv[2])
manifest = tomllib.loads(manifest_path.read_text())
normal = manifest["dependencies"]
dev = manifest["dev-dependencies"]

if normal.get("ctx-history-source-io") != {"path": "../ctx-history-source-io"}:
    raise SystemExit("discovery production source-I/O dependency must not enable test-support")
if "tempfile" in normal:
    raise SystemExit("discovery production dependency graph must not include tempfile")
if dev.get("ctx-history-source-io") != {
    "path": "../ctx-history-source-io",
    "features": ["test-support"],
}:
    raise SystemExit("discovery tests must opt into source-I/O test-support explicitly")
if "tempfile" not in dev:
    raise SystemExit("discovery test fixtures must keep tempfile in dev-dependencies")

forbidden = {
    "ctx-history-capture",
    "ctx-history-jsonl",
    "ctx-history-index",
    "ctx-history-refresh",
    "ctx-history-repository-evidence",
}
if forbidden & normal.keys():
    raise SystemExit(f"discovery production dependency boundary violated: {sorted(forbidden & normal.keys())}")

production_source = "\n".join(
    path.read_text()
    for path in source_root.rglob("*.rs")
    if "tests" not in path.parts and not path.name.endswith("_tests.rs")
)
if re.search(r"\\bctx_history_capture(?:\\b|::)", production_source):
    raise SystemExit("discovery production source must not reference capture")
PY
