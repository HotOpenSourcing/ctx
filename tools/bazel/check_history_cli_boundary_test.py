#!/usr/bin/env python3
"""Adversarial mutations for the history CLI static boundary."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from check_history_cli_boundary import BoundaryError, validate


REPOSITORY = (
    Path(sys.argv[1]).resolve().parent
    if len(sys.argv) == 2
    else Path(__file__).resolve().parents[2]
)
if len(sys.argv) == 2:
    sys.argv.pop()
CHECKER = REPOSITORY / "tools/bazel/check_history_cli_boundary.py"


class HistoryCliBoundaryMutations(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        shutil.copy2(REPOSITORY / "Cargo.toml", self.root / "Cargo.toml")
        for manifest in (REPOSITORY / "crates").glob("*/Cargo.toml"):
            destination = self.root / manifest.relative_to(REPOSITORY)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(manifest, destination)
        for relative in (
            "crates/ctx-history-cli/BUILD.bazel",
            "crates/ctx-cli/BUILD.bazel",
            "crates/ctx-cli/src/provider_args.rs",
            "crates/ctx-cli/src/provider_sources.rs",
        ):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPOSITORY / relative, destination)
        shutil.copytree(
            REPOSITORY / "crates/ctx-history-cli/src",
            self.root / "crates/ctx-history-cli/src",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def reset(self) -> None:
        self.tearDown()
        self.setUp()

    @property
    def history_cargo(self) -> Path:
        return self.root / "crates/ctx-history-cli/Cargo.toml"

    @property
    def history_build(self) -> Path:
        return self.root / "crates/ctx-history-cli/BUILD.bazel"

    @property
    def final_build(self) -> Path:
        return self.root / "crates/ctx-cli/BUILD.bazel"

    def arguments(self) -> tuple[Path, ...]:
        return (
            self.root / "Cargo.toml",
            self.history_cargo,
            self.history_build,
            self.root / "crates/ctx-cli/Cargo.toml",
            self.final_build,
            self.root / "crates/ctx-history-cli/src",
            self.root / "crates/ctx-cli/src/provider_args.rs",
            self.root / "crates/ctx-cli/src/provider_sources.rs",
            *sorted((self.root / "crates").glob("*/Cargo.toml")),
        )

    def validate(self) -> None:
        arguments = self.arguments()
        validate(*arguments[:8], arguments[8:])

    def replace(self, path: Path, before: str, after: str) -> None:
        source = path.read_text(encoding="utf-8")
        self.assertIn(before, source)
        path.write_text(source.replace(before, after, 1), encoding="utf-8")

    def test_clean_head_passes(self) -> None:
        self.validate()

    def test_renamed_workspace_and_target_cargo_dependencies_fail_closed(self) -> None:
        cases = (
            (
                "renamed",
                "forbidden Cargo dependencies",
            ),
            (
                "workspace",
                "forbidden Cargo dependencies",
            ),
            (
                "target",
                "forbidden Cargo dependencies",
            ),
        )
        for kind, error in cases:
            with self.subTest(kind=kind, error=error):
                if kind == "renamed":
                    self.replace(self.history_cargo, "[dev-dependencies]\n", "[dev-dependencies]\ncli_alias = { package = \"ctx-cli\", path = \"../ctx-cli\" }\n")
                elif kind == "workspace":
                    self.replace(self.root / "Cargo.toml", "[patch.crates-io]", "cli_alias = { package = \"ctx-cli\", version = \"1\" }\n[patch.crates-io]")
                    self.replace(self.history_cargo, "[dev-dependencies]\n", "[dev-dependencies]\ncli_alias.workspace = true\n")
                else:
                    self.history_cargo.write_text(self.history_cargo.read_text(encoding="utf-8") + "\n[target.'cfg(unix)'.build-dependencies]\npro_alias = { package = \"ctx-pro-host\", path = \"../ctx-pro-host\" }\n", encoding="utf-8")
                with self.assertRaisesRegex(BoundaryError, error):
                    self.validate()
                self.reset()

    def test_malformed_and_ambiguous_cargo_entries_fail_closed(self) -> None:
        for kind, error in (
            ("malformed", "must be a string or inline table"),
            ("ambiguous", "ambiguous workspace"),
            ("\n[target.'cfg(unix)']\nunsupported = {}\n", "unsupported tables"),
        ):
            with self.subTest(kind=kind):
                if kind == "malformed":
                    self.replace(self.history_cargo, "[dev-dependencies]\n", "[dev-dependencies]\ncli_alias = 1\n")
                elif kind == "ambiguous":
                    self.replace(self.history_cargo, "[dev-dependencies]\n", "[dev-dependencies]\ncli_alias = { workspace = false }\n")
                else:
                    self.history_cargo.write_text(self.history_cargo.read_text(encoding="utf-8") + kind, encoding="utf-8")
                with self.assertRaisesRegex(BoundaryError, error):
                    self.validate()
                self.reset()

    def test_agent_and_pro_identifier_families_fail_closed(self) -> None:
        source = self.root / "crates/ctx-history-cli/src/lib.rs"
        for identifier in ("ctx_agent_application::authority", "ctx_agent_integrations::authority", "ctx_pro_host::authority", "ctx_pro_lifecycle::authority"):
            with self.subTest(identifier=identifier):
                source.write_text(source.read_text(encoding="utf-8") + f"\nfn forbidden() {{ {identifier}(); }}\n", encoding="utf-8")
                with self.assertRaisesRegex(BoundaryError, "prohibited identifiers"):
                    self.validate()
                self.reset()
                source = self.root / "crates/ctx-history-cli/src/lib.rs"

    def test_comments_are_not_false_positives(self) -> None:
        source = self.root / "crates/ctx-history-cli/src/lib.rs"
        source.write_text(source.read_text(encoding="utf-8") + "\n// ctx_agent_application::comment_only()\n/* ctx_pro_host::comment_only() */\n", encoding="utf-8")
        self.validate()

    def test_reverse_cargo_consumer_fails_closed(self) -> None:
        consumer = self.root / "crates/ctx-terminal/Cargo.toml"
        consumer.write_text(consumer.read_text(encoding="utf-8") + "\n[dev-dependencies]\nhistory_alias = { package = \"ctx-history-cli\", path = \"../ctx-history-cli\" }\n", encoding="utf-8")
        with self.assertRaisesRegex(BoundaryError, "reverse Cargo consumers"):
            self.validate()

    def test_bazel_raw_composed_aliased_and_proc_macro_edges_fail_closed(self) -> None:
        cases = (
            ("history", "\ncustom_rust_target(name = \"concealed\", deps = [\"//crates/ctx-agent-application:lib\"])\n", "unsupported rule or macro"),
            ("history", "\nCOPIED_DEPS = HISTORY_CLI_DEPS\n", "may only be assigned"),
            ("history", "\nHISTORY_CLI_DEPS = [\"//crates/ctx-history-capture:lib\"] + [\"//crates/ctx-history-core:lib\"]\n", "inventory drifted"),
            ("history", "\nrust_library(name = \"raw\", deps = [\"//crates/ctx-agent-application:lib\"], proc_macro_deps = [\"//crates/ctx-pro-host:lib\"])\n", "exactly two rust_library"),
            ("final", "\nCTX_CLI_DEPS.append(\"//crates/ctx-history-cli:lib\")\n", "unsupported rule or macro"),
        )
        for target, addition, error in cases:
            with self.subTest(target=target, error=error):
                path = self.history_build if target == "history" else self.final_build
                path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")
                with self.assertRaisesRegex(BoundaryError, error):
                    self.validate()
                self.reset()

    def test_unexpected_reverse_bazel_label_fails_closed(self) -> None:
        self.replace(
            self.final_build,
            '"//crates/ctx-history-cli:lib",\n    "//crates/ctx-history-core:lib",',
            '"//crates/ctx-history-cli:lib",\n    "//crates/ctx-history-cli:unexpected",\n    "//crates/ctx-history-core:lib",',
        )
        with self.assertRaisesRegex(BoundaryError, "reverse history-cli labels"):
            self.validate()

    def test_proc_macro_composition_fails_closed(self) -> None:
        self.replace(
            self.history_build,
            "proc_macro_deps = all_crate_deps(proc_macro = True),",
            'proc_macro_deps = all_crate_deps(proc_macro = True) + ["//crates/ctx-pro-host:lib"],',
        )
        with self.assertRaisesRegex(BoundaryError, "proc_macro_deps must be exactly"):
            self.validate()

    def test_malformed_toml_checker_cli_fails_closed(self) -> None:
        self.history_cargo.write_text("[dependencies\n", encoding="utf-8")
        result = subprocess.run([sys.executable, str(CHECKER), *(str(path) for path in self.arguments())], check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_checker_cli_returns_failure(self) -> None:
        self.history_cargo.write_text(self.history_cargo.read_text(encoding="utf-8") + "\n[build-dependencies]\nclap_alias = { package = \"clap\", version = \"4\" }\n", encoding="utf-8")
        result = subprocess.run([sys.executable, str(CHECKER), *(str(path) for path in self.arguments())], check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("forbidden Cargo dependencies", result.stderr)


if __name__ == "__main__":
    unittest.main()
