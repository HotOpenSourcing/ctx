use std::{path::Path, process::Command};

use anyhow::{anyhow, Context as _, Result};

pub(super) fn new(
    helper: &Path,
    data_root: &Path,
    git_executable: Option<&Path>,
) -> Result<Command> {
    let installation_id = crate::identity::existing_installation_id(data_root)
        .context("key_store_unavailable: load local Pro installation identity")?
        .ok_or_else(|| {
            anyhow!("key_store_unavailable: local Pro installation identity is missing")
        })?;
    ctx_pro_host::helper_command::new(helper, data_root, &installation_id, git_executable)
}
