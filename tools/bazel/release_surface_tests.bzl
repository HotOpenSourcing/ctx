"""Release-surface smoke and audit test declarations."""

load("@rules_shell//shell:sh_test.bzl", "sh_test")


def release_surface_tests():
    sh_test(
        name = "native_ctx_binary_smoke",
        srcs = ["scripts/bazel-native-ctx-smoke.sh"],
        args = [
            "$(rootpath //crates/ctx-cli:ctx)",
            "$(rootpath //crates/ctx-cli:Cargo.toml)",
        ],
        data = [
            "//crates/ctx-cli:Cargo.toml",
            "//crates/ctx-cli:ctx",
        ],
    )

    sh_test(
        name = "release_binary_string_audit_tests",
        srcs = ["scripts/tests/audit-release-binary-strings-test.sh"],
        data = [
            "scripts/check-release-binary-strings.sh",
            "scripts/tests/fixtures/release-binary-strings/protocol-v1-local-runtime.txt",
            "scripts/tests/fixtures/release-binary-strings/removed-cloud-history.txt",
        ],
        tags = ["non-rust-action"],
    )

    sh_test(
        name = "release_source_surface_audit_tests",
        srcs = ["scripts/tests/audit-release-source-surface-test.sh"],
        data = [
            "scripts/check-release-source-surface.sh",
            "scripts/tests/fixtures/release-source-surface/retained-pro-uninstall/crates/ctx-cli/src/pro/lifecycle_commands.rs.fixture",
            "scripts/tests/fixtures/release-source-surface/retained-upgrade-status/crates/ctx-cli/src/upgrade/command/status.rs.fixture",
            "scripts/tests/fixtures/release-source-surface/retired-command-surfaces/crates/ctx-cli/src/main.rs.fixture",
            "scripts/tests/fixtures/release-source-surface/retired-capture-pro-output-authority/crates/ctx-history-capture/src/pro_output.rs.fixture",
            "scripts/tests/fixtures/release-source-surface/retired-capture-repository-authority/crates/ctx-history-capture/src/repository_attribution/mod.rs.fixture",
            "scripts/tests/fixtures/release-source-surface/retired-misplaced-pro-uninstall/crates/ctx-cli/src/pro/other.rs.fixture",
            "scripts/tests/fixtures/release-source-surface/retired-repository-exact-json-authority/crates/ctx-history-repository-evidence/src/exact_json.rs.fixture",
            "scripts/tests/fixtures/release-source-surface/retired-top-level-uninstall/crates/ctx-cli/src/main.rs.fixture",
            "scripts/tests/fixtures/release-source-surface/retired-update-invocation/crates/ctx-cli/src/main.rs.fixture",
            "scripts/tests/fixtures/release-source-surface/retired-update-route/crates/ctx-cli/src/main.rs.fixture",
        ],
        tags = ["non-rust-action"],
    )
