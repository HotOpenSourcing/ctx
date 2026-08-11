use std::path::Path;

use anyhow::{bail, Result};
use ctx_pro_host::{
    BlameFreshnessPolicy, CoreGenerationHost, CoreGenerationPin, CoreMaterializationSyncOutcome,
    HostedBlameResult, ProStatus,
};
use ctx_pro_host_protocol::BlameTarget;
use ctx_pro_lifecycle::operation::LifecycleOperation;

/// Coarse Core policy boundary. The CLI owns daemon admission and Core refresh
/// mechanics; Pro policy only specifies the operation phase that needs one.
pub trait CoreOrchestration {
    /// Performs the exact daemon/refresh/wait sequence and returns the pinned
    /// generation that may be finalized into the helper.
    fn prepare_materialization_generation(&self, data_root: &Path) -> Result<String>;

    fn wait_for_pro_generation(&self, data_root: &Path, generation_id: &str) -> Result<()>;

    /// Requests, but never waits for, ordinary blame's one permitted background
    /// source refresh.
    fn wake_blame_refresh(&self, data_root: &Path) -> Result<()>;

    fn cancel_core_finalization(&self, data_root: &Path, reason: &str) -> Result<()>;
}

/// Installed-helper plus Core orchestration authority.  Keeping this as one
/// coarse adapter prevents per-event and serialization boundaries.
pub trait ProApplicationHost: CoreGenerationHost + CoreOrchestration {}
impl<T: CoreGenerationHost + CoreOrchestration> ProApplicationHost for T {}

/// Borrowed Pro application facade. Construction is allocation- and I/O-free.
#[derive(Clone, Copy)]
pub struct ProApplication<'a, H: ProApplicationHost + ?Sized> {
    host: &'a H,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializationMode {
    Full,
    Incremental,
    NoOp,
}

#[derive(Debug, Clone)]
pub struct MaterializationOutcome {
    pub report: ctx_pro_host::MaterializationFinalizationReceipt,
    pub mode: MaterializationMode,
}

impl<'a, H: ProApplicationHost + ?Sized> ProApplication<'a, H> {
    pub const fn new(host: &'a H) -> Self {
        Self { host }
    }

    /// Passive status: this calls the helper once and does not refresh, wake a
    /// daemon, open a browser, migrate state, or perform network I/O itself.
    pub fn status(&self, data_root: &Path) -> ProStatus {
        ctx_pro_host::status(self.host, data_root)
    }

    /// Uses a Core generation already opened by aggregate status, preserving
    /// the single Core-open/single Pro-query pinning contract.
    pub fn status_for_core(
        &self,
        data_root: &Path,
        active_core: Option<&ctx_history_index::VerifiedIndex>,
    ) -> ProStatus {
        ctx_pro_host::status_for_core(self.host, data_root, active_core)
    }

    pub fn preflight_core_materialization(&self, data_root: &Path) -> Result<()> {
        ctx_pro_host::preflight_core_materialization(self.host, data_root)
    }

    pub fn selected_helper_artifact_sha256(&self, data_root: &Path) -> Result<Option<String>> {
        ctx_pro_host::selected_helper_artifact_sha256(self.host, data_root)
    }

    pub fn sync_core_materialization(
        &self,
        data_root: &Path,
        index: &ctx_history_index::VerifiedIndex,
    ) -> Result<CoreMaterializationSyncOutcome> {
        ctx_pro_host::sync_core_materialization(self.host, data_root, index)
    }

    pub fn materialize(&self, data_root: &Path) -> Result<MaterializationOutcome> {
        self.materialize_in(data_root, None)
    }

    pub fn materialize_in(
        &self,
        data_root: &Path,
        operation: Option<&LifecycleOperation>,
    ) -> Result<MaterializationOutcome> {
        let start = match operation {
            Some(operation) => {
                ctx_pro_host::start_materialization_in(self.host, data_root, operation)
            }
            None => ctx_pro_host::start_materialization(self.host, data_root),
        }?;
        let generation_id = self.host.prepare_materialization_generation(data_root)?;
        let was_unmaterialized = start.prior_core_generation_id.is_none();
        let no_op = start.prior_core_generation_id.as_deref() == Some(generation_id.as_str());
        let report = match operation {
            Some(operation) => ctx_pro_host::finish_materialization_in(
                self.host,
                data_root,
                operation,
                start,
                generation_id,
            ),
            None => {
                ctx_pro_host::finish_materialization(self.host, data_root, start, generation_id)
            }
        }?;
        match operation {
            Some(operation) => {
                operation.require_data_root(data_root)?;
                ctx_pro_lifecycle::state_markers::clear_materialization(operation)?;
            }
            None => ctx_pro_lifecycle::state_markers::clear_materialization_at(data_root)?,
        }
        Ok(MaterializationOutcome {
            report,
            mode: if no_op {
                MaterializationMode::NoOp
            } else if was_unmaterialized {
                MaterializationMode::Full
            } else {
                MaterializationMode::Incremental
            },
        })
    }

    fn wait_for_current_blame_generation(&self, data_root: &Path) -> Result<String> {
        self.materialize(data_root)?;
        let mut expected = self
            .host
            .pin_active_core_generation(data_root)?
            .generation_id()
            .to_owned();
        for _ in 0..3 {
            self.host.wait_for_pro_generation(data_root, &expected)?;
            let active = self
                .host
                .pin_active_core_generation(data_root)?
                .generation_id()
                .to_owned();
            if active == expected {
                return Ok(expected);
            }
            expected = active;
        }
        bail!("stale_source: active verified Core generation advanced repeatedly while preparing blame")
    }

    pub fn blame(
        &self,
        data_root: &Path,
        target: &BlameTarget,
        limit: u32,
        cursor: Option<String>,
    ) -> Result<HostedBlameResult> {
        let expected_active_generation = ctx_pro_host::prepare_blame_freshness_with(
            BlameFreshnessPolicy::LatestCommitted,
            || self.host.wake_blame_refresh(data_root),
            || self.wait_for_current_blame_generation(data_root),
        )
        .map_err(|error| ctx_pro_host::blame_boundary_error(error, target))?;
        ctx_pro_host::blame(
            self.host,
            data_root,
            target,
            limit,
            cursor,
            expected_active_generation,
        )
    }

    pub fn uninstall(
        &self,
        data_root: &Path,
        deletion: Option<&mut dyn crate::ProDeletionService>,
        disposition: crate::UninstallDataDisposition,
    ) -> Result<crate::UninstallOutcome> {
        crate::uninstall::uninstall(self.host, data_root, deletion, disposition)
    }
}
