#[cfg(not(ctx_pro_test_helper))]
use anyhow::bail;
use anyhow::Result;
#[cfg(ctx_pro_test_helper)]
use ctx_pro_access::authorization::EntitlementTrust;
#[cfg(ctx_pro_test_helper)]
use ctx_pro_lifecycle::release_manifest::{release_trust, ReleaseChannel, ReleaseTrust};

pub(super) use ctx_pro_application::{selected_channel, CommercialConfig};
pub(super) const TEST_CONTROL_MANIFEST_ENV: &str = "CTX_PRO_TEST_CONTROL_MANIFEST";

pub(super) fn reject_test_control_outside_test_host() -> Result<()> {
    #[cfg(not(ctx_pro_test_helper))]
    if std::env::var_os(TEST_CONTROL_MANIFEST_ENV).is_some() {
        bail!("invalid_request: {TEST_CONTROL_MANIFEST_ENV} is accepted only by ctx_pro_test_host");
    }
    Ok(())
}

#[cfg(ctx_pro_test_helper)]
pub(super) fn test_control_release_trust() -> Result<ReleaseTrust> {
    release_trust(ReleaseChannel::Stable)
}

#[cfg(ctx_pro_test_helper)]
pub(super) const fn test_control_entitlement_trust() -> EntitlementTrust {
    EntitlementTrust::new("https://pro-test.ctx.invalid", &["ctx-pro-test-control-v1"])
}
