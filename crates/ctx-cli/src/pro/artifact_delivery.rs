pub(crate) use ctx_pro_application::VerifiedArtifactBundle;

#[cfg(ctx_pro_test_helper)]
type SetupReleaseArtifact = Box<VerifiedArtifactBundle>;
#[cfg(not(ctx_pro_test_helper))]
type SetupReleaseArtifact = VerifiedArtifactBundle;

#[derive(Debug)]
#[cfg_attr(test, allow(dead_code))]
pub(crate) enum SetupArtifactBundle {
    Release(SetupReleaseArtifact),
    #[cfg(ctx_pro_test_helper)]
    TestControl(crate::pro::test_control::TestControlHelperBundle),
}

impl SetupArtifactBundle {
    pub(crate) fn release(bundle: VerifiedArtifactBundle) -> Self {
        #[cfg(ctx_pro_test_helper)]
        {
            Self::Release(Box::new(bundle))
        }
        #[cfg(not(ctx_pro_test_helper))]
        {
            Self::Release(bundle)
        }
    }
}
