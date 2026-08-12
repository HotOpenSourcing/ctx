use std::path::Path;

use anyhow::Result;
use ctx_pro_lifecycle::operation::LifecycleOperation;

use super::{
    artifact_delivery::SetupArtifactBundle,
    client,
    commercial_lifecycle::{unix_time, CommercialLifecycleService},
    lifecycle::ProSetupPlan,
};

fn context(service: &CommercialLifecycleService) -> ctx_pro_application::AnonymousTrialContext<'_> {
    ctx_pro_application::AnonymousTrialContext {
        config: &service.config,
        api: &service.api,
        vault: &service.vault,
    }
}

pub(super) fn refresh_entitlement(service: &CommercialLifecycleService) -> Result<()> {
    ctx_pro_application::refresh_anonymous_trial_entitlement(context(service), unix_time()?)
}

pub(super) fn defer_refresh(service: &CommercialLifecycleService, now: i64) {
    ctx_pro_application::defer_anonymous_trial_refresh(context(service), now);
}

pub(super) fn setup(
    service: &CommercialLifecycleService,
    operation: &LifecycleOperation,
    data_root: &Path,
    installed_version: Option<&str>,
    referral_codename: Option<&str>,
) -> Result<ProSetupPlan> {
    let setup = client::setup_anonymous_trial(
        context(service),
        operation,
        data_root,
        installed_version,
        referral_codename,
    )?;
    Ok(ProSetupPlan {
        artifact: Some(SetupArtifactBundle::release(setup.artifact)),
        account_state: setup.account_state.to_owned(),
    })
}
