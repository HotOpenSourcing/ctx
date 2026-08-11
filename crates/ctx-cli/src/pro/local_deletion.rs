use std::path::Path;

use anyhow::Result;
use ctx_pro_lifecycle::operation::LifecycleOperation;

use super::lifecycle::ProDeletionService;

pub(super) use ctx_pro_lifecycle::deletion::{
    local_pro_graph_data_exists, local_pro_graph_key_cleanup_phase_exists,
    local_pro_initialization_indicator_exists,
};

pub(super) struct LocalDeletionService {
    inner: ctx_pro_lifecycle::deletion::LocalDeletionService,
}

impl LocalDeletionService {
    pub(super) fn production() -> Self {
        Self {
            inner: ctx_pro_lifecycle::deletion::LocalDeletionService::production(
                crate::identity::existing_installation_id,
            ),
        }
    }
}

impl ProDeletionService for LocalDeletionService {
    fn delete_graph_data(&mut self, data_root: &Path) -> Result<()> {
        self.inner.delete_graph_data(data_root)
    }

    fn delete_commercial_credentials(&mut self, data_root: &Path) -> Result<()> {
        self.inner.delete_commercial_credentials(data_root)
    }

    fn finish_deletion(&mut self, data_root: &Path) -> Result<()> {
        self.inner.finish_deletion(data_root)
    }
}

pub(super) fn clear_local_pro_initialization_indicator(
    operation: &LifecycleOperation,
) -> Result<()> {
    ctx_pro_lifecycle::deletion::clear_local_pro_initialization_indicator(operation)
}

#[cfg(test)]
pub(super) fn write_local_pro_initialization_indicator(data_root: &Path) -> Result<()> {
    ctx_pro_lifecycle::deletion::write_local_pro_initialization_indicator(data_root)
}

#[cfg(test)]
pub(super) fn write_empty_graph_key_cleanup_phase_for_test(
    data_root: &Path,
    installation_id: &str,
) -> Result<()> {
    ctx_pro_lifecycle::deletion::write_empty_graph_key_cleanup_phase_for_test(
        data_root,
        installation_id,
    )
}
