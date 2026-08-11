pub(crate) use ctx_pro_application::VerifiedArtifactBundle;

#[derive(Debug)]
#[cfg_attr(test, allow(dead_code))]
pub(crate) enum SetupArtifactBundle {
    Release(VerifiedArtifactBundle),
    #[cfg(ctx_pro_test_helper)]
    TestControl(crate::pro::test_control::TestControlHelperBundle),
}
