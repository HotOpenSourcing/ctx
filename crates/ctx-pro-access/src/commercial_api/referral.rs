use std::fmt;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::workos_device::WorkOsAccessToken;

use super::{validate_https_url, CommercialApiClient};

const MAX_REFERRAL_CLAIM_TOKEN_BYTES: usize = 1024;
const MAX_REFERRAL_COUNT: u64 = 1_000_000_000;
const REFERRAL_COMMISSION_CENTS: u64 = 1_000;
const MAX_COMMISSIONED_INVOICES_PER_ATTRIBUTION: u64 = 12;
pub const MAX_REFERRAL_CENTS_PER_ATTRIBUTION: u64 =
    REFERRAL_COMMISSION_CENTS * MAX_COMMISSIONED_INVOICES_PER_ATTRIBUTION;
pub const MAX_REFERRAL_CENTS: u64 = MAX_REFERRAL_COUNT * MAX_REFERRAL_CENTS_PER_ATTRIBUTION;
const MAX_PAYOUT_ONBOARDING_LIFETIME_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const REFERRALS_PATH: &str = "/v1/referrals";
pub const REFERRAL_PAYOUT_PATH: &str = "/v1/referrals/payout";

pub const REFERRAL_CODENAME_MIN_BYTES: usize = 3;
pub const REFERRAL_CODENAME_MAX_BYTES: usize = 32;

pub fn valid_referral_codename(value: &str) -> bool {
    (REFERRAL_CODENAME_MIN_BYTES..=REFERRAL_CODENAME_MAX_BYTES).contains(&value.len())
        && value.is_ascii()
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.as_bytes().windows(2).any(|pair| pair == b"--")
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferralCreateResult {
    pub codename: String,
    pub disposition: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferralStatusResult {
    pub codename: String,
    pub attributed: u64,
    pub subscribed: u64,
    pub earned_cents: u64,
    pub pending_cents: u64,
    pub manual_review_cents: u64,
    pub payable_cents: u64,
    pub processing_cents: u64,
    pub paid_cents: u64,
    pub debt_cents: u64,
    pub currency: String,
    pub payout_state: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferralPayoutResult {
    pub kind: String,
    pub payout_state: String,
    pub url: String,
    pub expires_at_unix: i64,
}

impl fmt::Debug for ReferralCreateResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReferralCreateResult([REDACTED])")
    }
}

impl fmt::Debug for ReferralStatusResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReferralStatusResult([REDACTED])")
    }
}

impl fmt::Debug for ReferralPayoutResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReferralPayoutResult([REDACTED])")
    }
}

impl CommercialApiClient {
    pub fn referral_create(
        &self,
        access_token: &WorkOsAccessToken,
        codename: &str,
    ) -> Result<ReferralCreateResult> {
        validate_codename(codename)?;
        self.post(
            REFERRALS_PATH,
            access_token,
            &ReferralCreateRequest { codename },
        )
    }

    pub fn referral_status(
        &self,
        access_token: &WorkOsAccessToken,
    ) -> Result<ReferralStatusResult> {
        self.get(REFERRALS_PATH, access_token)
    }

    pub fn referral_payout(
        &self,
        access_token: &WorkOsAccessToken,
        country: Option<&str>,
    ) -> Result<ReferralPayoutResult> {
        validate_payout_country(country)?;
        self.post(
            REFERRAL_PAYOUT_PATH,
            access_token,
            &ReferralPayoutRequest { country },
        )
    }
}

impl ReferralCreateResult {
    pub fn validate(&self, requested_codename: &str) -> Result<()> {
        if !valid_referral_codename(&self.codename)
            || self.codename != requested_codename
            || !matches!(self.disposition.as_str(), "created" | "existing")
        {
            bail!("invalid_response: referral creation result is invalid");
        }
        Ok(())
    }
}

impl ReferralStatusResult {
    pub fn validate(&self) -> Result<()> {
        let amounts = [
            self.earned_cents,
            self.pending_cents,
            self.manual_review_cents,
            self.payable_cents,
            self.processing_cents,
            self.paid_cents,
            self.debt_cents,
        ];
        let earned_plus_debt = self.earned_cents.checked_add(self.debt_cents);
        let ledger_total = self
            .pending_cents
            .checked_add(self.manual_review_cents)
            .and_then(|value| value.checked_add(self.payable_cents))
            .and_then(|value| value.checked_add(self.processing_cents))
            .and_then(|value| value.checked_add(self.paid_cents));
        let payout_state_is_coherent = match (
            self.manual_review_cents,
            self.debt_cents,
            self.processing_cents,
        ) {
            (review, debt, processing) if review > 0 || debt > 0 || processing > 0 => {
                self.payout_state == "paused"
            }
            (0, 0, 0) if self.payable_cents == 0 => self.payout_state == "not_eligible",
            (0, 0, 0) => matches!(
                self.payout_state.as_str(),
                "eligible" | "onboarding_pending" | "ready"
            ),
            _ => false,
        };
        if !valid_referral_codename(&self.codename)
            || self.attributed > MAX_REFERRAL_COUNT
            || self.subscribed > self.attributed
            || amounts.into_iter().any(|value| {
                value > MAX_REFERRAL_CENTS || !value.is_multiple_of(REFERRAL_COMMISSION_CENTS)
            })
            || self.earned_cents
                > self
                    .subscribed
                    .saturating_mul(MAX_REFERRAL_CENTS_PER_ATTRIBUTION)
            || self.debt_cents > self.paid_cents
            || earned_plus_debt != ledger_total
            || self.currency != "usd"
            || !payout_state_is_coherent
        {
            bail!("invalid_response: referral status is invalid");
        }
        Ok(())
    }
}

impl ReferralPayoutResult {
    #[cfg(test)]
    pub fn validate(&self) -> Result<()> {
        self.validate_at(super::system_unix_time()?)
    }

    pub fn validate_at(&self, now: i64) -> Result<()> {
        if self.kind != "payout_onboarding_created" || self.payout_state != "onboarding_pending" {
            bail!("invalid_response: referral payout result is invalid");
        }
        validate_stripe_hosted_url(&self.url)?;
        if self.expires_at_unix <= now
            || self.expires_at_unix > now.saturating_add(MAX_PAYOUT_ONBOARDING_LIFETIME_SECONDS)
        {
            bail!("invalid_response: referral payout URL expiry is outside allowed bounds");
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub struct ReferralCreateRequest<'a> {
    pub codename: &'a str,
}

#[derive(Serialize)]
pub struct ReferralPayoutRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<&'a str>,
}

pub fn validate_optional_codename(codename: Option<&str>) -> Result<()> {
    if let Some(codename) = codename {
        validate_codename(codename)?;
    }
    Ok(())
}

fn validate_codename(codename: &str) -> Result<()> {
    if !valid_referral_codename(codename) {
        bail!("invalid_request: referral codename is invalid");
    }
    Ok(())
}

pub fn validate_optional_claim_token(token: Option<&str>) -> Result<()> {
    if let Some(token) = token {
        validate_referral_claim_token(token)?;
    }
    Ok(())
}

pub fn validate_referral_claim_token(token: &str) -> Result<()> {
    if token.len() < 16
        || token.len() > MAX_REFERRAL_CLAIM_TOKEN_BYTES
        || token.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
        })
    {
        bail!("invalid_response: referral claim token is invalid");
    }
    Ok(())
}

pub fn validate_payout_country(country: Option<&str>) -> Result<()> {
    if country.is_some_and(|value| {
        value.len() != 2 || !value.bytes().all(|byte| byte.is_ascii_uppercase())
    }) {
        bail!("invalid_request: referral payout identity is invalid");
    }
    Ok(())
}

fn validate_stripe_hosted_url(value: &str) -> Result<()> {
    let parsed = validate_https_url(value, "Stripe payout onboarding")?;
    let host = parsed.host_str().unwrap_or_default();
    if host != "stripe.com" && !host.ends_with(".stripe.com") {
        bail!("invalid_response: payout onboarding URL is not Stripe-hosted");
    }
    Ok(())
}

pub(super) fn is_never_retryable_error_code(code: &str) -> bool {
    matches!(
        code,
        "referral_unavailable"
            | "payout_setup_unavailable"
            | "referral_claim_conflict"
            | "referral_claim_invalid"
            | "referral_codename_conflict"
            | "referral_codename_immutable"
            | "referral_codename_invalid"
            | "referral_codename_not_found"
            | "referral_codename_reserved"
            | "referral_codename_taken"
            | "referral_not_eligible"
            | "referral_not_found"
            | "referral_payout_country_required"
            | "referral_payout_not_eligible"
            | "referral_payout_unavailable"
            | "referral_self_referral"
            | "referral_verified_email_required"
    )
}

pub(super) fn commercial_error_message(code: &str) -> Option<&'static str> {
    match code {
        "referral_unavailable" => Some("referrals are not currently available"),
        "payout_setup_unavailable" => Some("referral payout onboarding is not currently available"),
        "referral_claim_conflict" => {
            Some("referral attribution conflicts with existing account state")
        }
        "referral_claim_invalid" => Some("referral attribution is invalid"),
        "referral_codename_conflict" | "referral_codename_immutable" => {
            Some("this account already has a different referral codename")
        }
        "referral_codename_invalid" => Some("referral codename is invalid"),
        "referral_codename_not_found" => Some("the referral codename was not found"),
        "referral_codename_reserved" => Some("the referral codename is reserved"),
        "referral_codename_taken" => Some("the referral codename is already claimed"),
        "referral_not_eligible" | "referral_payout_not_eligible" => {
            Some("a payable referral balance is required")
        }
        "referral_not_found" => Some("create a referral codename first"),
        "referral_payout_country_required" => {
            Some("a payout country is required; supply --country <CC>")
        }
        "referral_payout_unavailable" => {
            Some("referral payout onboarding is not currently available")
        }
        "referral_self_referral" => Some("self-referrals are not eligible"),
        "referral_verified_email_required" => {
            Some("a verified WorkOS email is required for referrals")
        }
        _ => None,
    }
}

pub(super) fn public_commercial_error_code(code: &str) -> Option<&str> {
    match code {
        "referral_unavailable"
        | "referral_codename_conflict"
        | "referral_not_eligible"
        | "referral_not_found"
        | "referral_payout_country_required"
        | "referral_payout_unavailable"
        | "referral_self_referral" => Some(code),
        "payout_setup_unavailable" => Some("referral_payout_unavailable"),
        "referral_claim_conflict" => Some("commercial_identity_conflict"),
        "referral_claim_invalid" | "referral_codename_invalid" | "referral_codename_reserved" => {
            Some("invalid_request")
        }
        "referral_codename_immutable" | "referral_codename_taken" => {
            Some("referral_codename_conflict")
        }
        "referral_codename_not_found" => Some("referral_not_found"),
        "referral_payout_not_eligible" => Some("referral_not_eligible"),
        "referral_verified_email_required" => Some("authentication_required"),
        _ => None,
    }
}
