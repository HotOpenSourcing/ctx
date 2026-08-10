use std::{io::Write, path::Path};

use anyhow::{bail, Result};
use ctx_history_capture::DiscoveryContext;
use ctx_history_index::VerifiedIndex;
use ctx_pro_host_protocol::CoreMaterializationFinalizationProgress;
use ctx_semantic_model::{
    ArtifactFetchRequest, ArtifactFetcher, SemanticModelConfig, SemanticModelPaths,
    SemanticOnnxRuntimePaths,
};

use crate::{
    DaemonAvailability, DaemonAvailabilityPort, DaemonConfigPort, DaemonConfigSnapshot,
    DaemonTrigger, ProCatchUpOutcome, ProCatchUpPort,
};

pub(crate) static CONFIG: TestConfig = TestConfig;
pub(crate) static SOURCE_REFRESH_CONFIG: SourceRefreshConfig = SourceRefreshConfig;
pub(crate) static AVAILABILITY: TestAvailability = TestAvailability;
pub(crate) static PRO: TestPro = TestPro;
pub(crate) static ARTIFACT: TestArtifact = TestArtifact;

pub(crate) struct TestConfig;
pub(crate) struct SourceRefreshConfig;

pub(crate) struct TestAvailability;

impl DaemonAvailabilityPort for TestAvailability {
    fn ensure_available(
        &self,
        _data_root: &Path,
        _trigger: DaemonTrigger,
    ) -> Result<DaemonAvailability> {
        Ok(DaemonAvailability::Available)
    }
}

impl DaemonConfigPort for TestConfig {
    fn load(&self, _data_root: &Path) -> Result<DaemonConfigSnapshot> {
        let mut config = DaemonConfigSnapshot::default();
        config.daemon.enabled = true;
        Ok(config)
    }

    fn semantic_model_config(&self, data_root: &Path) -> SemanticModelConfig {
        SemanticModelConfig::new(SemanticModelPaths::new(
            data_root.join("models"),
            SemanticOnnxRuntimePaths::new(data_root.join("runtime")),
        ))
    }

    fn discovery_context(&self, data_root: &Path) -> Result<DiscoveryContext> {
        Ok(DiscoveryContext::from_process(data_root))
    }
}

impl DaemonConfigPort for SourceRefreshConfig {
    fn load(&self, _data_root: &Path) -> Result<DaemonConfigSnapshot> {
        let mut config = DaemonConfigSnapshot::default();
        config.daemon.enabled = true;
        config.daemon.mode = crate::DaemonMode::SourceRefreshOnly;
        Ok(config)
    }

    fn semantic_model_config(&self, data_root: &Path) -> SemanticModelConfig {
        CONFIG.semantic_model_config(data_root)
    }

    fn discovery_context(&self, data_root: &Path) -> Result<DiscoveryContext> {
        CONFIG.discovery_context(data_root)
    }
}

pub(crate) struct TestArtifact;

impl ArtifactFetcher for TestArtifact {
    fn fetch_to_writer(
        &self,
        _request: ArtifactFetchRequest<'_>,
        _writer: &mut dyn Write,
    ) -> Result<u64> {
        bail!("test artifact fetch is disabled")
    }
}

pub(crate) struct TestPro;

impl ProCatchUpPort for TestPro {
    fn preflight(&self, _data_root: &Path) -> Result<()> {
        bail!("Pro is not installed")
    }

    fn sync(&self, _data_root: &Path, _index: &VerifiedIndex) -> Result<ProCatchUpOutcome> {
        unreachable!("preflight fails")
    }

    fn reconcile_finalization_lease(&self, _data_root: &Path) -> Result<()> {
        Ok(())
    }
    fn cancel_finalization_lease(&self, _data_root: &Path, _reason: &str) -> Result<bool> {
        Ok(false)
    }
    fn reconstruct_finalization_lease(
        &self,
        _data_root: &Path,
        _progress: &CoreMaterializationFinalizationProgress,
    ) -> Result<()> {
        Ok(())
    }
    fn validate_finalization_lease(
        &self,
        _data_root: &Path,
        _progress: &CoreMaterializationFinalizationProgress,
    ) -> Result<()> {
        Ok(())
    }
    fn release_finalization_lease(
        &self,
        _data_root: &Path,
        _generation_id: Option<&str>,
    ) -> Result<bool> {
        Ok(false)
    }
    fn selected_helper_artifact_sha256(&self, _data_root: &Path) -> Result<Option<String>> {
        Ok(None)
    }
    fn stable_error_code(&self, _error: &anyhow::Error) -> Option<&'static str> {
        Some("pro_not_installed")
    }
}
