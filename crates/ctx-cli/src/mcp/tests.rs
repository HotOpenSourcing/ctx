use std::{
    env,
    ffi::OsString,
    io::{Cursor, Error, ErrorKind},
    sync::{Arc, Mutex, MutexGuard},
};

use ctx_agent_integrations::tool_backend::{
    ToolBackendError, ToolExecutionError, ToolOperation, ToolOutcome, ToolUsageFacts,
};
use ctx_history_core::{platform_security::restrict_private_directory, CaptureProvider};

use super::*;

#[derive(Clone, Copy)]
enum OutputFailure {
    None,
    Write,
    Flush,
}

struct TracedWriter {
    failure: OutputFailure,
    trace: Arc<Mutex<Vec<&'static str>>>,
}

impl Write for TracedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if matches!(self.failure, OutputFailure::Write) {
            self.trace.lock().unwrap().push("write_failed");
            return Err(Error::new(ErrorKind::BrokenPipe, "test write failure"));
        }
        self.trace.lock().unwrap().push("write");
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if matches!(self.failure, OutputFailure::Flush) {
            self.trace.lock().unwrap().push("flush_failed");
            return Err(Error::new(ErrorKind::BrokenPipe, "test flush failure"));
        }
        self.trace.lock().unwrap().push("flush");
        Ok(())
    }
}

struct LocalUsageEnvGuard {
    _lock: MutexGuard<'static, ()>,
    saved: Option<OsString>,
}

impl LocalUsageEnvGuard {
    fn unset() -> Self {
        let lock = crate::config::TEST_LOCAL_USAGE_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let saved = env::var_os("CTX_LOCAL_USAGE_ENABLED");
        env::remove_var("CTX_LOCAL_USAGE_ENABLED");
        Self { _lock: lock, saved }
    }
}

impl Drop for LocalUsageEnvGuard {
    fn drop(&mut self) {
        match &self.saved {
            Some(value) => env::set_var("CTX_LOCAL_USAGE_ENABLED", value),
            None => env::remove_var("CTX_LOCAL_USAGE_ENABLED"),
        }
    }
}

fn run_one_status_response(
    failure: OutputFailure,
) -> (
    std::result::Result<(), McpServeFailure>,
    Vec<&'static str>,
    bool,
) {
    struct PostFlushBackend;

    impl ToolBackend for PostFlushBackend {
        fn execute(
            &self,
            _operation: ToolOperation,
        ) -> std::result::Result<ToolOutcome, ToolExecutionError> {
            Ok(ToolOutcome {
                structured: json!({"access_state": "test"}),
                compact: None,
                usage: ToolUsageFacts::default(),
                integration_receipt: Some(ToolIntegrationReceipt {
                    facts: ToolTransportFacts::ProStatus {
                        access_state: Some("test".to_owned()),
                        helper_connected: true,
                        error_code: None,
                    },
                    success: true,
                    duration: std::time::Duration::ZERO,
                }),
            })
        }

        fn invalid_blame_request(&self) -> ToolBackendError {
            panic!("pro_status test must not parse blame")
        }

        fn render_text(&self, value: &Value) -> String {
            text::render_tool_text(value)
        }

        fn parse_provider(&self, _value: &str) -> Option<CaptureProvider> {
            None
        }

        fn provider_names(&self) -> Vec<&'static str> {
            Vec::new()
        }
    }

    let root = tempfile::tempdir().unwrap();
    restrict_private_directory(root.path()).unwrap();
    std::fs::write(
        root.path().join("config.toml"),
        "[analytics]\nenabled = true\n[local_usage]\nenabled = true\n",
    )
    .unwrap();
    let request = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": "status",
        "method": "tools/call",
        "params": {"name": "pro_status", "arguments": {}}
    }))
    .unwrap();
    let mut input = Cursor::new([request, vec![b'\n']].concat());
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut output = TracedWriter {
        failure,
        trace: trace.clone(),
    };
    let mut initialized = true;
    let delivery_trace = trace.clone();
    let mut telemetry = McpTelemetry::start_for_test(move |events| {
        let mut trace = delivery_trace.lock().unwrap();
        for event in events {
            let label = match event {
                crate::analytics::PublicEventV1::OperationCompleted(event) => {
                    match &event.descriptor {
                        crate::operation_descriptor::OperationDescriptor::Mcp(_) => "submit_mcp",
                        crate::operation_descriptor::OperationDescriptor::ProHost(_) => {
                            "submit_pro"
                        }
                        _ => continue,
                    }
                }
                _ => continue,
            };
            trace.push(label);
        }
        Ok(())
    });
    let mut control = crate::observability_composition::LocalUsageControlAuthority::new(
        root.path().to_path_buf(),
    );
    let mut usage = McpUsageRecorder::start(
        crate::observability_composition::local_usage_storage_authority(root.path()),
        move || control.snapshot(),
    );
    usage.set_test_trace(trace.clone());

    let result = serve_stdio_loop_with_backend(
        &mut input,
        &mut output,
        &mut initialized,
        &mut telemetry,
        &mut usage,
        &PostFlushBackend,
    );
    let (reason, outcome) = match &result {
        Ok(()) => (McpStopReasonV1::Eof, Outcome::Success),
        Err(failure) => (failure.reason, Outcome::Failure),
    };
    telemetry.stop(reason, outcome, std::time::Duration::ZERO);
    let recorded = root.path().join("usage.sqlite").exists();
    let trace = trace.lock().unwrap().clone();
    (result, trace, recorded)
}

#[test]
fn post_flush_observations_follow_one_local_commit_and_skip_it_on_output_failure() {
    let _env = LocalUsageEnvGuard::unset();

    let (delivered, trace, recorded) = run_one_status_response(OutputFailure::None);
    assert!(delivered.is_ok());
    assert!(recorded);
    assert_eq!(
        trace
            .iter()
            .filter(|entry| **entry == "local_usage")
            .count(),
        1
    );
    let flushed_at = trace.iter().position(|entry| *entry == "flush").unwrap();
    let recorded_at = trace
        .iter()
        .position(|entry| *entry == "local_usage")
        .unwrap();
    assert!(flushed_at < recorded_at, "{trace:?}");
    for submitted in ["submit_mcp", "submit_pro"] {
        let submitted_at = trace.iter().position(|entry| *entry == submitted).unwrap();
        assert!(recorded_at < submitted_at, "{trace:?}");
    }

    let (write_failed, trace, recorded) = run_one_status_response(OutputFailure::Write);
    assert!(matches!(
        write_failed.unwrap_err().reason,
        McpStopReasonV1::StdoutWriteError
    ));
    assert!(!recorded);
    assert!(!trace.contains(&"local_usage"));

    let (flush_failed, trace, recorded) = run_one_status_response(OutputFailure::Flush);
    assert!(matches!(
        flush_failed.unwrap_err().reason,
        McpStopReasonV1::StdoutFlushError
    ));
    assert!(!recorded);
    assert!(!trace.contains(&"local_usage"));
}
