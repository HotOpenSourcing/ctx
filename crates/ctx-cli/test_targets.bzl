"""Native Bazel integration-test helper for the ctx CLI package."""

load("@crates//:defs.bzl", "crate_deps")
load(
    "//tools/bazel:binary_contracts.bzl",
    "CTX_BINARY_CONTRACT_RUSTC_FLAGS",
    "ctx_binary_contract_test",
)

CTX_CLI_RUSTC_FLAGS = CTX_BINARY_CONTRACT_RUSTC_FLAGS

_CTX_CLI_TEST_SUPPORT = {
    "base": struct(
        crates = [
            "assert_cmd",
            "predicates",
            "serde_json",
            "tempfile",
            "uuid",
        ],
        deps = [],
        rustc_flags = [],
        srcs = [
            "tests/support/mod.rs",
            "tests/support/analytics.rs",
            "tests/support/assertions.rs",
            "tests/support/history_plugins.rs",
            "//crates/ctx-agent-application:tests/contracts/support/mcp.rs",
            "tests/support/runner.rs",
        ],
    ),
    "fixtures": struct(
        crates = [
            "libc",
            "rusqlite",
            "sha2",
            "windows-sys",
        ],
        deps = ["//crates/ctx-history-index:lib"],
        rustc_flags = ["--cfg=ctx_cli_test_support_fixtures"],
        srcs = [
            "tests/support/daemon.rs",
            "tests/support/fixtures.rs",
            "tests/support/native_fixtures.rs",
            "tests/support/native_fixtures/appends.rs",
            "tests/support/native_fixtures/installs.rs",
            "tests/support/native_fixtures/json_tree.rs",
            "tests/support/native_fixtures/sqlite.rs",
        ],
    ),
    "pro": struct(
        crates = [],
        deps = ["//crates/ctx-pro-host-protocol:lib"],
        rustc_flags = ["--cfg=ctx_cli_test_support_pro"],
        srcs = ["tests/support/pro.rs"],
    ),
    "upgrade": struct(
        crates = [
            "base64",
            "chrono",
            "flate2",
            "ring",
            "sha2",
            "tar",
        ],
        deps = ["//crates/ctx-history-core:lib"],
        rustc_flags = ["--cfg=ctx_cli_test_support_upgrade"],
        srcs = ["tests/support/upgrade.rs"],
    ),
}

def _ctx_cli_test_support(groups):
    crates = []
    deps = []
    rustc_flags = []
    srcs = []
    seen = {}
    seen_crates = {}
    seen_deps = {}
    seen_rustc_flags = {}
    seen_srcs = {}
    for group in groups:
        if group not in _CTX_CLI_TEST_SUPPORT:
            fail("unknown ctx CLI test support group %r; expected one of %s" % (
                group,
                sorted(_CTX_CLI_TEST_SUPPORT.keys()),
            ))
        if group in seen:
            fail("duplicate ctx CLI test support group %r" % group)
        seen[group] = True
        support = _CTX_CLI_TEST_SUPPORT[group]
        for crate in support.crates:
            if crate not in seen_crates:
                seen_crates[crate] = True
                crates.append(crate)
        for dep in support.deps:
            if dep not in seen_deps:
                seen_deps[dep] = True
                deps.append(dep)
        for flag in support.rustc_flags:
            if flag not in seen_rustc_flags:
                seen_rustc_flags[flag] = True
                rustc_flags.append(flag)
        for src in support.srcs:
            if src not in seen_srcs:
                seen_srcs[src] = True
                srcs.append(src)
    return struct(
        deps = crate_deps(crates) + deps,
        rustc_flags = rustc_flags,
        srcs = srcs,
    )

def ctx_cli_test_data():
    return ["//:public_test_fixtures"] + native.glob([
        "testdata/**",
        "tests/fixtures/**",
    ])

def ctx_cli_integration_test(
        name,
        src,
        binary = ":ctx",
        crate_features = [],
        extra_crates = [],
        extra_env = {},
        extra_compile_data = [],
        extra_data = [],
        extra_deps = [],
        extra_srcs = [],
        tags = [],
        test_support = ["base"]):
    test_support = _ctx_cli_test_support(test_support)
    ctx_binary_contract_test(
        name = name,
        src = src,
        binary = binary,
        cargo_manifest_dir = "crates/ctx-cli",
        support_deps = test_support.deps,
        support_srcs = test_support.srcs,
        support_rustc_flags = test_support.rustc_flags,
        crate_features = crate_features,
        extra_crates = extra_crates,
        extra_env = extra_env,
        extra_compile_data = [
            "//:ctx_bundled_skills",
            "//:ctx_embedded_docs",
        ] + native.glob(["tests/fixtures/**"]) + extra_compile_data,
        extra_data = ctx_cli_test_data() + extra_data,
        extra_deps = extra_deps,
        extra_srcs = extra_srcs,
        rustc_env_files = [":cargo_toml_env_vars"],
        tags = tags,
    )
