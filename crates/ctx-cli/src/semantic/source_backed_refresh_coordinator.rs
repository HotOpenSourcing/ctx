use std::path::Path;

use anyhow::Result;
use ctx_history_refresh::ExplicitSourceCatalogAuthority;

use super::daemon_service_ports::AVAILABILITY;

pub(crate) use ctx_daemon_service::{
    pin_active_verified_generation, published_explicit_source_relocation_authority,
    PinnedSourceBackedGeneration, RefreshStatus, SourceBackedCurrentSourceProgress,
    SourceBackedRefreshDaemonUnavailable, SourceBackedRefreshMode, SourceBackedRefreshObservation,
    SourceBackedRefreshPendingPublication,
};
#[cfg(test)]
pub(crate) use ctx_history_refresh::count_verified_index_opens;
pub(crate) use ctx_history_refresh::{
    open_verified_index, source_backed_index_root, verified_generation_is_query_ready,
};

pub(crate) fn coordinate_source_backed_refresh(
    data_root: &Path,
    mode: SourceBackedRefreshMode,
) -> Result<SourceBackedRefreshObservation> {
    ctx_daemon_service::coordinate_source_backed_refresh(&AVAILABILITY, data_root, mode)
}

pub(crate) fn coordinate_source_backed_refresh_with_progress(
    data_root: &Path,
    mode: SourceBackedRefreshMode,
    report_progress: &mut dyn FnMut(&RefreshStatus) -> Result<()>,
) -> Result<SourceBackedRefreshObservation> {
    ctx_daemon_service::coordinate_source_backed_refresh_with_progress(
        &AVAILABILITY,
        data_root,
        mode,
        report_progress,
    )
}

pub(crate) fn coordinate_import_source_backed_refresh_with_progress(
    data_root: &Path,
    mode: SourceBackedRefreshMode,
    explicit_source_catalog: Option<&ExplicitSourceCatalogAuthority>,
    allow_daemon_autostart: bool,
    report_progress: &mut dyn FnMut(&RefreshStatus) -> Result<()>,
) -> Result<SourceBackedRefreshObservation> {
    ctx_daemon_service::coordinate_import_source_backed_refresh_with_progress(
        &AVAILABILITY,
        data_root,
        mode,
        explicit_source_catalog,
        allow_daemon_autostart,
        report_progress,
    )
}
