use std::path::Path;

use anyhow::{bail, Context, Result};
use ctx_pro_access::commercial_api::{
    valid_referral_codename, ReferralCreateResult, ReferralPayoutResult, ReferralStatusResult,
    REFERRAL_CODENAME_MAX_BYTES, REFERRAL_CODENAME_MIN_BYTES,
};
use ctx_pro_host::stable_error_code;
use ctx_pro_lifecycle::{
    installation::acquire_commercial_lifecycle_lock, operation::LifecycleOperation,
};

const REFERRAL_PAYOUT_COUNTRY_REQUIRED: &str = "referral_payout_country_required";

/// Concrete installation identity access remains in the executable. Referral
/// admission owns whether cached identity is sufficient or identity creation is
/// allowed.
pub trait ReferralIdentity {
    fn existing_referral_identity(&self, data_root: &Path) -> Result<Option<String>>;
    fn initialize_referral_identity(&self, data_root: &Path) -> Result<()>;
}

/// Holds the commercial lifecycle lock for the full referral command.
pub struct ReferralAdmission {
    _operation: LifecycleOperation,
}

pub fn admit_referral<I: ReferralIdentity + ?Sized>(
    identity: &I,
    data_root: &Path,
    cached_identity_only: bool,
    create_lifecycle_root: bool,
) -> Result<ReferralAdmission> {
    if cached_identity_only {
        if identity
            .existing_referral_identity(data_root)
            .context("authentication_required: load cached ctx identity")?
            .is_none()
        {
            bail!(
                "authentication_required: rerun the referral command without --format json to sign in"
            );
        }
    } else {
        identity
            .initialize_referral_identity(data_root)
            .context("key_store_unavailable: initialize local ctx identity")?;
    }
    let operation = acquire_commercial_lifecycle_lock(data_root, create_lifecycle_root)?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "authentication_required: rerun the referral command without --format=json to sign in"
            )
        })?;
    Ok(ReferralAdmission {
        _operation: operation,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferralAuthMode {
    Interactive { browser_enabled: bool },
    CachedOnly,
}

/// One commercial operation per method. Implementations may perform identity,
/// session, and HTTP work, but receive no rendering or serialization callback.
pub trait ReferralService {
    fn create(
        &mut self,
        codename: &str,
        auth_mode: ReferralAuthMode,
    ) -> Result<ReferralCreateResult>;
    fn status(&mut self, auth_mode: ReferralAuthMode) -> Result<ReferralStatusResult>;
    fn payout(
        &mut self,
        country: Option<&str>,
        auth_mode: ReferralAuthMode,
    ) -> Result<ReferralPayoutResponse>;
}

/// Production transport responses require application validation. An isolated
/// host may instead provide a response already checked against its non-live
/// URL and deterministic-clock contract.
#[derive(Debug)]
pub enum ReferralPayoutResponse {
    Unvalidated(ReferralPayoutResult),
    Prevalidated(ReferralPayoutResult),
}

/// A payout response is clock-bounded after the service response and before it
/// is exposed to presentation.
pub trait ReferralClock {
    fn unix_time(&self) -> Result<i64>;
}

#[derive(Debug, Clone, Copy)]
pub enum ReferralCommand<'a> {
    Create {
        codename: &'a str,
    },
    Status,
    Payout {
        country: Option<&'a str>,
        no_open: bool,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct ReferralRequest<'a> {
    pub command: ReferralCommand<'a>,
    pub machine_output: bool,
    pub interactive: bool,
}

#[derive(Debug)]
pub enum ReferralOutcome {
    Created(ReferralCreateResult),
    Status(ReferralStatusResult),
    Payout(ReferralPayoutResult),
    CountryRequired(ReferralPayoutRetry),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferralPayoutRetry {
    auth_mode: ReferralAuthMode,
}

pub fn execute_referral<S, C>(
    service: &mut S,
    clock: &C,
    request: ReferralRequest<'_>,
) -> Result<ReferralOutcome>
where
    S: ReferralService + ?Sized,
    C: ReferralClock + ?Sized,
{
    match request.command {
        ReferralCommand::Create { codename } => {
            validate_referral_codename(codename)?;
            let auth_mode = referral_auth_mode(request, true);
            let result = service.create(codename, auth_mode)?;
            result.validate(codename)?;
            Ok(ReferralOutcome::Created(result))
        }
        ReferralCommand::Status => {
            let auth_mode = referral_auth_mode(request, true);
            let result = service.status(auth_mode)?;
            result.validate()?;
            Ok(ReferralOutcome::Status(result))
        }
        ReferralCommand::Payout { country, no_open } => {
            validate_referral_country(country)?;
            let auth_mode = if request.machine_output || !request.interactive {
                ReferralAuthMode::CachedOnly
            } else {
                ReferralAuthMode::Interactive {
                    browser_enabled: !no_open,
                }
            };
            match service.payout(country, auth_mode) {
                Ok(response) => {
                    let result = validate_payout_response(response, clock)?;
                    Ok(ReferralOutcome::Payout(result))
                }
                Err(error)
                    if country.is_none()
                        && stable_error_code(&error) == Some(REFERRAL_PAYOUT_COUNTRY_REQUIRED) =>
                {
                    if request.machine_output || !request.interactive {
                        bail!(
                            "{REFERRAL_PAYOUT_COUNTRY_REQUIRED}: a payout country is required; supply --country <CC>"
                        );
                    }
                    Ok(ReferralOutcome::CountryRequired(ReferralPayoutRetry {
                        auth_mode,
                    }))
                }
                Err(error) => Err(error),
            }
        }
    }
}

pub fn retry_referral_payout<S, C>(
    service: &mut S,
    clock: &C,
    retry: ReferralPayoutRetry,
    country: &str,
) -> Result<ReferralPayoutResult>
where
    S: ReferralService + ?Sized,
    C: ReferralClock + ?Sized,
{
    validate_referral_country(Some(country))?;
    let response = service.payout(Some(country), retry.auth_mode)?;
    validate_payout_response(response, clock)
}

fn validate_payout_response<C: ReferralClock + ?Sized>(
    response: ReferralPayoutResponse,
    clock: &C,
) -> Result<ReferralPayoutResult> {
    match response {
        ReferralPayoutResponse::Unvalidated(result) => {
            result.validate_at(clock.unix_time()?)?;
            Ok(result)
        }
        ReferralPayoutResponse::Prevalidated(result) => Ok(result),
    }
}

fn referral_auth_mode(request: ReferralRequest<'_>, browser_enabled: bool) -> ReferralAuthMode {
    if request.machine_output {
        ReferralAuthMode::CachedOnly
    } else {
        ReferralAuthMode::Interactive { browser_enabled }
    }
}

pub fn validate_referral_codename(value: &str) -> Result<()> {
    if !valid_referral_codename(value) {
        bail!(
            "invalid_request: referral codename must be \
             {REFERRAL_CODENAME_MIN_BYTES}-{REFERRAL_CODENAME_MAX_BYTES} lowercase ASCII \
             letters, digits, or single hyphens, and must start with a letter"
        );
    }
    Ok(())
}

pub fn validate_referral_country(country: Option<&str>) -> Result<()> {
    if country.is_some_and(|value| !is_iso_country_code(value)) {
        bail!("invalid_request: referral payout identity is invalid");
    }
    Ok(())
}

pub fn is_iso_country_code(value: &str) -> bool {
    value.len() == 2
        && value.bytes().all(|byte| byte.is_ascii_uppercase())
        && ISO_COUNTRY_CODES
            .split_ascii_whitespace()
            .any(|code| code == value)
}

// Fixed ISO 3166-1 alpha-2 admission set. Keeping this in policy makes country
// handling independent of host locale and optional system data files.
const ISO_COUNTRY_CODES: &str = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW";

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
    };

    use super::*;

    struct FixedClock;

    impl ReferralClock for FixedClock {
        fn unix_time(&self) -> Result<i64> {
            Ok(1_000)
        }
    }

    #[derive(Default)]
    struct FakeService {
        calls: Vec<String>,
        payouts: RefCell<VecDeque<Result<ReferralPayoutResult>>>,
    }

    impl ReferralService for FakeService {
        fn create(
            &mut self,
            codename: &str,
            auth_mode: ReferralAuthMode,
        ) -> Result<ReferralCreateResult> {
            self.calls.push(format!("create:{codename}:{auth_mode:?}"));
            Ok(ReferralCreateResult {
                codename: codename.to_owned(),
                disposition: "created".to_owned(),
            })
        }

        fn status(&mut self, auth_mode: ReferralAuthMode) -> Result<ReferralStatusResult> {
            self.calls.push(format!("status:{auth_mode:?}"));
            Ok(ReferralStatusResult {
                codename: "agent-smith".to_owned(),
                attributed: 0,
                subscribed: 0,
                earned_cents: 0,
                pending_cents: 0,
                manual_review_cents: 0,
                payable_cents: 0,
                processing_cents: 0,
                paid_cents: 0,
                debt_cents: 0,
                currency: "usd".to_owned(),
                payout_state: "not_eligible".to_owned(),
            })
        }

        fn payout(
            &mut self,
            country: Option<&str>,
            auth_mode: ReferralAuthMode,
        ) -> Result<ReferralPayoutResponse> {
            self.calls.push(format!("payout:{country:?}:{auth_mode:?}"));
            self.payouts
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Ok(valid_payout()))
                .map(ReferralPayoutResponse::Unvalidated)
        }
    }

    fn valid_payout() -> ReferralPayoutResult {
        ReferralPayoutResult {
            kind: "payout_onboarding_created".to_owned(),
            payout_state: "onboarding_pending".to_owned(),
            url: "https://connect.stripe.com/setup/s/test".to_owned(),
            expires_at_unix: 1_300,
        }
    }

    struct FakeIdentity {
        existing: Option<String>,
        existing_calls: Cell<usize>,
        initialize_calls: Cell<usize>,
    }

    impl ReferralIdentity for FakeIdentity {
        fn existing_referral_identity(&self, _data_root: &Path) -> Result<Option<String>> {
            self.existing_calls.set(self.existing_calls.get() + 1);
            Ok(self.existing.clone())
        }

        fn initialize_referral_identity(&self, _data_root: &Path) -> Result<()> {
            self.initialize_calls.set(self.initialize_calls.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn referral_admission_selects_identity_mode_before_the_lifecycle_lock() {
        let root = tempfile::tempdir().unwrap();
        let cached = FakeIdentity {
            existing: None,
            existing_calls: Cell::new(0),
            initialize_calls: Cell::new(0),
        };
        let error = admit_referral(&cached, root.path(), true, false)
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "authentication_required: rerun the referral command without --format json to sign in"
        );
        assert_eq!(cached.existing_calls.get(), 1);
        assert_eq!(cached.initialize_calls.get(), 0);

        let interactive = FakeIdentity {
            existing: None,
            existing_calls: Cell::new(0),
            initialize_calls: Cell::new(0),
        };
        let _admission = admit_referral(&interactive, root.path(), false, true).unwrap();
        assert_eq!(interactive.existing_calls.get(), 0);
        assert_eq!(interactive.initialize_calls.get(), 1);
        ctx_history_core::platform_security::verify_private_directory(
            &ctx_pro_host_protocol::ProFilesystemLayout::new(root.path()).pro_root(),
        )
        .unwrap();
    }

    #[test]
    fn stable_codename_and_country_validation_is_headless() {
        for valid in ["abc", "agent-smith", "a1b2", &"a".repeat(32)] {
            validate_referral_codename(valid).unwrap();
        }
        for invalid in [
            "",
            "ab",
            "-agent",
            "9agent",
            "agent-",
            "agent--smith",
            "Agent",
            "agent_name",
            "café",
            "agent smith",
            &"a".repeat(33),
        ] {
            assert!(validate_referral_codename(invalid).is_err(), "{invalid:?}");
        }
        for valid in ["US", "GB", "AQ", "ZW"] {
            validate_referral_country(Some(valid)).unwrap();
        }
        for invalid in ["us", "USA", "U1", "ZZ", ""] {
            assert!(validate_referral_country(Some(invalid)).is_err());
        }
    }

    #[test]
    fn payout_retries_once_only_for_the_stable_country_required_code() {
        let mut service = FakeService {
            payouts: RefCell::new(VecDeque::from([
                Err(anyhow::anyhow!(
                    "referral_payout_country_required: country is required"
                )),
                Ok(valid_payout()),
            ])),
            ..FakeService::default()
        };
        let outcome = execute_referral(
            &mut service,
            &FixedClock,
            ReferralRequest {
                command: ReferralCommand::Payout {
                    country: None,
                    no_open: true,
                },
                machine_output: false,
                interactive: true,
            },
        )
        .unwrap();
        let ReferralOutcome::CountryRequired(retry) = outcome else {
            panic!("expected country retry");
        };
        retry_referral_payout(&mut service, &FixedClock, retry, "US").unwrap();
        assert_eq!(
            service.calls,
            [
                "payout:None:Interactive { browser_enabled: false }",
                "payout:Some(\"US\"):Interactive { browser_enabled: false }",
            ]
        );
    }

    #[test]
    fn noninteractive_country_required_is_actionable_without_retry() {
        let mut service = FakeService {
            payouts: RefCell::new(VecDeque::from([Err(anyhow::anyhow!(
                "referral_payout_country_required: country is required"
            ))])),
            ..FakeService::default()
        };
        let error = execute_referral(
            &mut service,
            &FixedClock,
            ReferralRequest {
                command: ReferralCommand::Payout {
                    country: None,
                    no_open: false,
                },
                machine_output: true,
                interactive: false,
            },
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "referral_payout_country_required: a payout country is required; supply --country <CC>"
        );
        assert_eq!(service.calls, ["payout:None:CachedOnly"]);
    }

    #[test]
    fn unrelated_payout_error_is_not_reclassified() {
        let mut service = FakeService {
            payouts: RefCell::new(VecDeque::from([Err(anyhow::anyhow!(
                "invalid_request: unrelated"
            ))])),
            ..FakeService::default()
        };
        let error = execute_referral(
            &mut service,
            &FixedClock,
            ReferralRequest {
                command: ReferralCommand::Payout {
                    country: None,
                    no_open: true,
                },
                machine_output: false,
                interactive: true,
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "invalid_request: unrelated");
        assert_eq!(service.calls.len(), 1);
    }

    #[test]
    fn application_validates_each_service_result() {
        struct InvalidService;

        impl ReferralService for InvalidService {
            fn create(
                &mut self,
                _codename: &str,
                _auth_mode: ReferralAuthMode,
            ) -> Result<ReferralCreateResult> {
                Ok(ReferralCreateResult {
                    codename: "other-agent".to_owned(),
                    disposition: "created".to_owned(),
                })
            }

            fn status(&mut self, _auth_mode: ReferralAuthMode) -> Result<ReferralStatusResult> {
                unreachable!()
            }

            fn payout(
                &mut self,
                _country: Option<&str>,
                _auth_mode: ReferralAuthMode,
            ) -> Result<ReferralPayoutResponse> {
                unreachable!()
            }
        }

        let error = execute_referral(
            &mut InvalidService,
            &FixedClock,
            ReferralRequest {
                command: ReferralCommand::Create {
                    codename: "agent-smith",
                },
                machine_output: false,
                interactive: true,
            },
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid_response: referral creation result is invalid"
        );
    }
}
