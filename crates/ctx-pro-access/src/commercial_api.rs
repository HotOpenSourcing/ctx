use std::{
    fmt, io,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use ctx_pro_host_protocol::SignedEntitlement;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;
use zeroize::{Zeroize as _, ZeroizeOnDrop, Zeroizing};

use crate::workos_device::{WorkOsAccessToken, WorkOsTokens};
use crate::{
    authorization::EntitlementTrust,
    credential_vault::{
        vault_error, AnonymousTrialMaterial, BoundedSignedEntitlement, CredentialVaultError,
    },
};

use super::request_identity::new_idempotency_key;

mod referral;
mod response;
mod urls;

pub use referral::{
    valid_referral_codename, ReferralCreateResult, ReferralPayoutResult, ReferralStatusResult,
    REFERRAL_CODENAME_MAX_BYTES, REFERRAL_CODENAME_MIN_BYTES,
};
#[cfg(test)]
use response::{
    classify_error_response, commercial_error_message, malformed_error_failure, media_type_is,
    parse_retry_after, typed_api_failure, ErrorResponseKind,
};
pub use response::{commercial_http_error, is_retryable_checkout_failure};
use response::{read_success_json, require_success_json, validate_envelope};

const MAX_API_RESPONSE_BYTES: u64 = 96 * 1024;
const MAX_ACCESS_TOKEN_BYTES: usize = 16 * 1024;
const MAX_TRIAL_ACCESS_TOKEN_BYTES: usize = 2 * 1024;
const MAX_URL_BYTES: usize = 4096;
const MAX_TIMESTAMP: i64 = 253_402_300_799;
const MAX_CHECKOUT_LIFETIME_SECONDS: i64 = 7 * 24 * 60 * 60;
const MAX_RETRY_AFTER_SECONDS: u64 = 30 * 60;
const MAX_TRIAL_CHALLENGE_LIFETIME_SECONDS: i64 = 10 * 60;
pub const COMMERCIAL_ACCEPT: &str = "application/json, application/problem+json";
const STAGING_ACCESS_ORIGIN: &str = "https://pro-staging.ctx.rs/";
const MAX_ACCESS_HEADER_BYTES: usize = 4096;
const MAX_COMMERCIAL_REQUEST_BYTES: usize = 16 * 1024;
const COMMERCIAL_REQUEST_BUFFER_BYTES: usize = MAX_COMMERCIAL_REQUEST_BYTES + 1;
const CLOUDFLARE_ACCESS_CLIENT_ID_HEADER: &str = "CF-Access-Client-Id";
const CLOUDFLARE_ACCESS_CLIENT_SECRET_HEADER: &str = "CF-Access-Client-Secret";

#[derive(Clone)]
pub struct CloudflareAccessCredentials {
    client_id: Zeroizing<String>,
    client_secret: Zeroizing<String>,
}

impl CloudflareAccessCredentials {
    pub fn new(client_id: String, client_secret: String) -> Result<Self> {
        validate_access_header_value(&client_id)?;
        validate_access_header_value(&client_secret)?;
        Ok(Self {
            client_id: Zeroizing::new(client_id),
            client_secret: Zeroizing::new(client_secret),
        })
    }
}

impl fmt::Debug for CloudflareAccessCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareAccessCredentials")
            .field("client_id", &"[REDACTED]")
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub struct CommercialApiConfig {
    origin: Url,
    staging_access: Option<CloudflareAccessCredentials>,
}

impl fmt::Debug for CommercialApiConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommercialApiConfig")
            .field("origin", &self.origin)
            .field(
                "staging_access",
                &self.staging_access.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl CommercialApiConfig {
    pub fn new(origin: Url, staging_access: Option<CloudflareAccessCredentials>) -> Result<Self> {
        validate_origin(&origin)?;
        if staging_access.is_some() && origin.as_str() != STAGING_ACCESS_ORIGIN {
            bail!(
                "invalid_request: staging Cloudflare Access credentials require the fixed staging origin"
            );
        }
        Ok(Self {
            origin,
            staging_access,
        })
    }

    pub fn origin(&self) -> &Url {
        &self.origin
    }

    pub fn apply_transport_credentials(
        &self,
        request: ureq::Request,
        url: &Url,
    ) -> Result<ureq::Request> {
        if url.origin() != self.origin.origin() {
            bail!("invalid_request: commercial request escaped its fixed origin");
        }
        let request_url = Url::parse(request.url())
            .context("invalid_request: commercial request URL is invalid")?;
        if request_url.origin() != url.origin() {
            bail!("invalid_request: commercial request URL does not match its credential scope");
        }
        let Some(access) = &self.staging_access else {
            return Ok(request);
        };
        if self.origin.as_str() != STAGING_ACCESS_ORIGIN {
            bail!(
                "invalid_request: staging Cloudflare Access credentials require the fixed staging origin"
            );
        }
        Ok(request
            .set(
                CLOUDFLARE_ACCESS_CLIENT_ID_HEADER,
                access.client_id.as_str(),
            )
            .set(
                CLOUDFLARE_ACCESS_CLIENT_SECRET_HEADER,
                access.client_secret.as_str(),
            ))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommercialState {
    pub subject: String,
    pub account_id: String,
    pub access_state: String,
    pub access_deadline_unix: Option<i64>,
    pub billing: BillingState,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingState {
    pub customer_associated: bool,
    pub subscription_status: Option<String>,
    pub trial_end_unix: Option<i64>,
    pub current_period_end_unix: Option<i64>,
    pub cancel_at_period_end: bool,
    pub canceled_at_unix: Option<i64>,
    pub latest_invoice_status: Option<String>,
    pub latest_payment_state: String,
}

impl CommercialState {
    pub fn grants_access(&self) -> bool {
        matches!(
            self.access_state.as_str(),
            "trial" | "active" | "canceling_paid"
        ) && self.access_deadline_unix.is_some()
    }

    fn validate(&self) -> Result<()> {
        validate_identifier(&self.subject, "subject")?;
        validate_identifier(&self.account_id, "account")?;
        if !matches!(
            self.access_state.as_str(),
            "active" | "canceling_paid" | "locked" | "none" | "trial"
        ) {
            bail!("invalid_response: commercial access state is invalid");
        }
        validate_timestamp(self.access_deadline_unix, "access deadline")?;
        let grants_access = matches!(
            self.access_state.as_str(),
            "active" | "canceling_paid" | "trial"
        );
        if (grants_access && self.access_deadline_unix.is_none())
            || (self.access_state == "none" && self.access_deadline_unix.is_some())
        {
            bail!("invalid_response: commercial access deadline is inconsistent");
        }
        self.billing.validate()
    }
}

impl BillingState {
    fn validate(&self) -> Result<()> {
        for (value, label) in [
            (self.subscription_status.as_deref(), "subscription status"),
            (self.latest_invoice_status.as_deref(), "invoice status"),
        ] {
            if value.is_some_and(|value| {
                value.is_empty()
                    || value.len() > 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            }) {
                bail!("invalid_response: commercial {label} is invalid");
            }
        }
        if !matches!(
            self.latest_payment_state.as_str(),
            "failed" | "open" | "paid" | "refunded" | "unknown"
        ) {
            bail!("invalid_response: commercial payment state is invalid");
        }
        for (value, label) in [
            (self.trial_end_unix, "trial end"),
            (self.current_period_end_unix, "period end"),
            (self.canceled_at_unix, "cancellation time"),
        ] {
            validate_timestamp(value, label)?;
        }
        if !self.customer_associated
            && (self.subscription_status.is_some()
                || self.trial_end_unix.is_some()
                || self.current_period_end_unix.is_some()
                || self.cancel_at_period_end
                || self.canceled_at_unix.is_some()
                || self.latest_invoice_status.is_some()
                || self.latest_payment_state != "unknown")
        {
            bail!("invalid_response: commercial billing state is inconsistent");
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckoutResult {
    pub kind: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub expires_at_unix: Option<i64>,
    #[serde(default)]
    pub state: Option<CommercialState>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortalResult {
    pub kind: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkOsBootstrapResult {
    organization_id: String,
}

#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct IssuedEntitlement(SignedEntitlement);

impl IssuedEntitlement {
    pub(crate) fn into_inner(self) -> SignedEntitlement {
        self.0
    }

    pub fn matches_account(&self, state: &CommercialState) -> bool {
        self.0.grant.subject == state.subject && self.0.grant.account_id == state.account_id
    }
}

impl fmt::Debug for IssuedEntitlement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IssuedEntitlement([REDACTED])")
    }
}

#[derive(Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct TrialChallenge {
    challenge_id: String,
    challenge_base64url: String,
    expires_at_unix: i64,
    trial_activation_token: String,
}

#[derive(Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct TrialActivation {
    disposition: String,
    #[zeroize(skip)]
    entitlement: IssuedEntitlement,
    trial_access_token: String,
    trial_deadline_unix: i64,
    #[serde(default)]
    referral_claim_token: Option<String>,
}

#[derive(Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct TrialRefresh {
    #[zeroize(skip)]
    entitlement: IssuedEntitlement,
    trial_access_token: String,
    trial_deadline_unix: i64,
    #[serde(default)]
    referral_claim_token: Option<String>,
}

impl fmt::Debug for TrialChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrialChallenge")
            .field("challenge_id", &self.challenge_id)
            .field("challenge_base64url", &self.challenge_base64url)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("trial_activation_token", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for TrialActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrialActivation")
            .field("disposition", &self.disposition)
            .field("entitlement", &"[REDACTED]")
            .field("trial_access_token", &"[REDACTED]")
            .field("trial_deadline_unix", &self.trial_deadline_unix)
            .finish()
    }
}

impl fmt::Debug for TrialRefresh {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrialRefresh")
            .field("entitlement", &"[REDACTED]")
            .field("trial_access_token", &"[REDACTED]")
            .field("trial_deadline_unix", &self.trial_deadline_unix)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiSuccess<T> {
    api_version: String,
    request_id: String,
    data: T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiFailure {
    api_version: String,
    request_id: String,
    error: ApiError,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiError {
    code: String,
    message: String,
    retryable: bool,
}

#[derive(Debug, thiserror::Error)]
enum CommercialApiFailure {
    #[error("service_unavailable: {operation} failed")]
    Transport { operation: String },
    #[error("service_unavailable: commercial API returned transient HTTP {status}")]
    Proxy {
        status: u16,
        retry_after: Option<Duration>,
    },
    #[error(
        "invalid_response: commercial API error response is not contracted JSON (HTTP {status})"
    )]
    InvalidResponse { status: u16 },
    #[error("{code}: {message} (HTTP {status})")]
    Response {
        code: String,
        message: &'static str,
        status: u16,
        retryable: bool,
        retry_after: Option<Duration>,
    },
}

impl CommercialApiFailure {
    fn is_retryable(&self) -> bool {
        match self {
            Self::Transport { .. } | Self::Proxy { .. } => true,
            Self::InvalidResponse { .. } => false,
            Self::Response {
                code,
                status,
                retryable,
                ..
            } => {
                if matches!(*status, 401 | 403 | 404 | 409)
                    || matches!(
                        code.as_str(),
                        "authentication_required"
                            | "billing_conflict"
                            | "commercial_access_locked"
                            | "commercial_identity_conflict"
                            | "dependency_invalid_response"
                            | "idempotency_key_invalid"
                            | "idempotency_key_required"
                            | "invalid_request"
                            | "invalid_response"
                            | "invalid_json"
                            | "invalid_installation_public_key"
                            | "method_not_allowed"
                            | "not_found"
                            | "request_body_too_large"
                            | "unsupported_media_type"
                    )
                    || referral::is_never_retryable_error_code(code)
                {
                    return false;
                }
                *retryable
            }
        }
    }

    fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Proxy { retry_after, .. } => *retry_after,
            Self::Response { retry_after, .. } if self.is_retryable() => *retry_after,
            Self::Transport { .. } | Self::InvalidResponse { .. } | Self::Response { .. } => None,
        }
    }
}

pub trait CommercialClock: Send + Sync {
    fn unix_time(&self) -> Result<i64>;
}

#[derive(Debug, Default)]
pub struct SystemCommercialClock;

impl CommercialClock for SystemCommercialClock {
    fn unix_time(&self) -> Result<i64> {
        system_unix_time()
    }
}

pub struct CommercialApiClient {
    config: CommercialApiConfig,
    agent: ureq::Agent,
    clock: Arc<dyn CommercialClock>,
}

impl CommercialApiClient {
    pub fn new(config: CommercialApiConfig, clock: Arc<dyn CommercialClock>) -> Result<Self> {
        validate_origin(&config.origin)?;
        if config.staging_access.is_some() && config.origin.as_str() != STAGING_ACCESS_ORIGIN {
            bail!(
                "invalid_request: staging Cloudflare Access credentials require the fixed staging origin"
            );
        }
        Ok(Self {
            config,
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout_connect(Duration::from_secs(10))
                .timeout_read(Duration::from_secs(20))
                .timeout_write(Duration::from_secs(10))
                .build(),
            clock,
        })
    }

    pub fn account(&self, access_token: &WorkOsAccessToken) -> Result<CommercialState> {
        let state: CommercialState = self.get("/v1/account", access_token)?;
        state.validate()?;
        Ok(state)
    }

    pub fn checkout(
        &self,
        access_token: &WorkOsAccessToken,
        anonymous_trial: Option<&AnonymousTrialMaterial>,
    ) -> Result<CheckoutResult> {
        let referral_claim_token =
            anonymous_trial.and_then(AnonymousTrialMaterial::referral_claim_token);
        referral::validate_optional_claim_token(referral_claim_token)?;
        let result: CheckoutResult = self.post(
            "/v1/billing/checkout",
            access_token,
            &CheckoutRequest {
                referral_claim_token,
            },
        )?;
        result.validate_at(self.unix_time()?)?;
        Ok(result)
    }

    pub fn portal(&self, access_token: &WorkOsAccessToken) -> Result<PortalResult> {
        let result: PortalResult =
            self.post("/v1/billing/portal", access_token, &EmptyRequest {})?;
        if result.kind != "portal_created" {
            bail!("invalid_response: commercial API returned an invalid portal result");
        }
        urls::validate_portal_url(&result.url)?;
        Ok(result)
    }

    pub fn bootstrap_workos_personal_organization(&self, tokens: &WorkOsTokens) -> Result<String> {
        let result: WorkOsBootstrapResult = self.post_raw(
            "/v1/identity/bootstrap",
            tokens.access_token(),
            &EmptyRequest {},
        )?;
        validate_identifier(&result.organization_id, "organization")?;
        Ok(result.organization_id)
    }

    pub fn entitlement(
        &self,
        access_token: &WorkOsAccessToken,
        installation_public_key_base64url: &str,
    ) -> Result<IssuedEntitlement> {
        if installation_public_key_base64url.len() != 43
            || !installation_public_key_base64url
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            bail!("invalid_request: installation public key is invalid");
        }
        self.post(
            "/v1/entitlements",
            access_token,
            &EntitlementRequest {
                installation_public_key_base64url,
            },
        )
    }

    pub fn trial_challenge(&self, request: TrialChallengeRequest<'_>) -> Result<TrialChallenge> {
        validate_fixed_base64url(
            request.installation_public_key_base64url,
            "installation public key",
        )?;
        referral::validate_optional_codename(request.referral_codename)?;
        let challenge: TrialChallenge =
            self.post_authorized("/v1/trials/challenge", None, &request)?;
        challenge.validate_at(self.unix_time()?)?;
        Ok(challenge)
    }

    pub fn activate_trial(
        &self,
        challenge: &TrialChallenge,
        installation_public_key_base64url: &str,
        evidence: &serde_json::Value,
    ) -> Result<TrialActivation> {
        validate_identifier(&challenge.challenge_id, "trial challenge")?;
        validate_fixed_base64url(installation_public_key_base64url, "installation public key")?;
        let authorization = trial_authorization(&challenge.trial_activation_token)?;
        let activation: TrialActivation = self.post_authorized(
            "/v1/trials/activate",
            Some(authorization),
            &TrialActivationRequest {
                schema_version: 1,
                challenge_id: &challenge.challenge_id,
                installation_public_key_base64url,
                evidence,
            },
        )?;
        activation.validate()?;
        Ok(activation)
    }

    pub fn refresh_trial(
        &self,
        trial: &AnonymousTrialMaterial,
        installation_public_key_base64url: &str,
    ) -> Result<TrialRefresh> {
        validate_fixed_base64url(installation_public_key_base64url, "installation public key")?;
        let authorization = trial_authorization(trial.access_token())?;
        let refresh: TrialRefresh = self.post_authorized(
            "/v1/trials/refresh",
            Some(authorization),
            &TrialRefreshRequest {
                schema_version: 1,
                installation_public_key_base64url,
            },
        )?;
        refresh.validate()?;
        Ok(refresh)
    }

    pub fn config(&self) -> &CommercialApiConfig {
        &self.config
    }

    pub(crate) fn unix_time(&self) -> Result<i64> {
        self.clock.unix_time()
    }

    fn get<T: DeserializeOwned>(&self, path: &str, access_token: &WorkOsAccessToken) -> Result<T> {
        let url = self.endpoint(path)?;
        let response = {
            let authorization = bearer_authorization(access_token.as_str())?;
            let request = self.config.apply_transport_credentials(
                self.agent
                    .get(url.as_str())
                    .set("accept", COMMERCIAL_ACCEPT)
                    .set("authorization", authorization.as_str()),
                &url,
            )?;
            request.call()
        };
        self.finish(response, "commercial API request")
    }

    fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        access_token: &WorkOsAccessToken,
        body: &B,
    ) -> Result<T> {
        let authorization = bearer_authorization(access_token.as_str())?;
        self.post_authorized(path, Some(authorization), body)
    }

    fn post_raw<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        access_token: &str,
        body: &B,
    ) -> Result<T> {
        let authorization = bearer_authorization(access_token)?;
        self.post_authorized(path, Some(authorization), body)
    }

    fn post_authorized<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        authorization: Option<Zeroizing<String>>,
        body: &B,
    ) -> Result<T> {
        let url = self.endpoint(path)?;
        let body = encode_commercial_request(body)?;
        let mut request = self.config.apply_transport_credentials(
            self.agent
                .post(url.as_str())
                .set("accept", COMMERCIAL_ACCEPT)
                .set("content-type", "application/json")
                .set(
                    "idempotency-key",
                    &new_idempotency_key("cli", self.unix_time()?)?,
                ),
            &url,
        )?;
        if let Some(authorization) = authorization.as_deref() {
            validate_authorization_header(authorization)?;
            request = request.set("authorization", authorization);
        }
        let response = request.send_bytes(&body);
        drop(body);
        drop(authorization);
        self.finish(response, "commercial API request")
    }

    fn finish<T: DeserializeOwned>(
        &self,
        response: std::result::Result<ureq::Response, ureq::Error>,
        operation: &str,
    ) -> Result<T> {
        match response {
            Ok(response) => {
                require_success_json(&response)?;
                let success: ApiSuccess<T> = read_success_json(response)?;
                validate_envelope(&success.api_version, &success.request_id)?;
                Ok(success.data)
            }
            Err(error) => Err(commercial_http_error(error, operation)),
        }
    }

    fn endpoint(&self, path: &str) -> Result<Url> {
        self.config
            .origin
            .join(path)
            .context("invalid_request: invalid commercial API route")
    }
}

fn encode_commercial_request<B: Serialize>(body: &B) -> Result<Zeroizing<Vec<u8>>> {
    let mut writer = BoundedCommercialRequestWriter::new();
    match serde_json::to_writer(&mut writer, body) {
        Ok(()) => {}
        Err(_) if writer.overflowed => {
            bail!("invalid_request: commercial request is too large")
        }
        Err(error) => return Err(error).context("invalid_request: encode commercial request"),
    }
    if writer.body.len() > MAX_COMMERCIAL_REQUEST_BYTES {
        bail!("invalid_request: commercial request is too large");
    }
    Ok(writer.into_body())
}

struct BoundedCommercialRequestWriter {
    body: Zeroizing<Vec<u8>>,
    overflowed: bool,
}

impl BoundedCommercialRequestWriter {
    fn new() -> Self {
        Self {
            body: Zeroizing::new(Vec::with_capacity(COMMERCIAL_REQUEST_BUFFER_BYTES)),
            overflowed: false,
        }
    }

    fn into_body(self) -> Zeroizing<Vec<u8>> {
        self.body
    }
}

impl io::Write for BoundedCommercialRequestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let remaining = COMMERCIAL_REQUEST_BUFFER_BYTES.saturating_sub(self.body.len());
        if remaining == 0 {
            self.overflowed = true;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "bounded commercial request buffer is full",
            ));
        }
        let written = remaining.min(bytes.len());
        self.body.extend_from_slice(&bytes[..written]);
        self.overflowed |= written < bytes.len();
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TrialChallenge {
    pub fn challenge_base64url(&self) -> &str {
        &self.challenge_base64url
    }

    #[cfg(test)]
    fn validate(&self) -> Result<()> {
        self.validate_at(system_unix_time()?)
    }

    fn validate_at(&self, now: i64) -> Result<()> {
        validate_identifier(&self.challenge_id, "trial challenge")?;
        validate_fixed_base64url(&self.challenge_base64url, "trial challenge")?;
        validate_trial_token(&self.trial_activation_token)?;
        if self.expires_at_unix <= now
            || self.expires_at_unix > now.saturating_add(MAX_TRIAL_CHALLENGE_LIFETIME_SECONDS)
        {
            bail!("invalid_response: trial challenge expiry is outside allowed bounds");
        }
        Ok(())
    }
}

impl TrialActivation {
    pub fn has_referral_claim(&self) -> bool {
        self.referral_claim_token.is_some()
    }

    pub fn into_anonymous_state(
        mut self,
        public_key: &[u8; ctx_pro_host_protocol::INSTALLATION_PUBLIC_KEY_BYTES],
        trust: EntitlementTrust,
    ) -> Result<(BoundedSignedEntitlement, AnonymousTrialMaterial)> {
        let deadline = self.trial_deadline_unix;
        let entitlement = BoundedSignedEntitlement::bind_anonymous_trial(
            self.entitlement.clone(),
            public_key,
            trust,
            deadline,
        )?;
        let trial = AnonymousTrialMaterial::from_server(
            std::mem::take(&mut self.trial_access_token),
            deadline,
            std::mem::take(&mut self.referral_claim_token),
        )
        .map_err(vault_error)?;
        Ok((entitlement, trial))
    }

    fn validate(&self) -> Result<()> {
        if !matches!(
            self.disposition.as_str(),
            "trial_started" | "trial_existing"
        ) {
            bail!("invalid_response: trial activation disposition is invalid");
        }
        validate_trial_token(&self.trial_access_token)?;
        referral::validate_optional_claim_token(self.referral_claim_token.as_deref())?;
        validate_timestamp(Some(self.trial_deadline_unix), "trial deadline")
    }
}

impl TrialRefresh {
    pub fn apply_to(
        mut self,
        trial: AnonymousTrialMaterial,
        public_key: &[u8; ctx_pro_host_protocol::INSTALLATION_PUBLIC_KEY_BYTES],
        trust: EntitlementTrust,
    ) -> Result<(BoundedSignedEntitlement, AnonymousTrialMaterial)> {
        if self.trial_deadline_unix != trial.trial_deadline_unix() {
            bail!("invalid_response: anonymous trial refresh changed the authoritative deadline");
        }
        let entitlement = BoundedSignedEntitlement::bind_anonymous_trial(
            self.entitlement.clone(),
            public_key,
            trust,
            self.trial_deadline_unix,
        )?;
        let refreshed = trial
            .apply_server_refresh(
                std::mem::take(&mut self.trial_access_token),
                std::mem::take(&mut self.referral_claim_token),
            )
            .map_err(|error| match error {
                CredentialVaultError::Corrupt => anyhow!(
                    "invalid_response: anonymous trial refresh changed referral attribution"
                ),
                error => vault_error(error),
            })?;
        Ok((entitlement, refreshed))
    }

    fn validate(&self) -> Result<()> {
        validate_trial_token(&self.trial_access_token)?;
        referral::validate_optional_claim_token(self.referral_claim_token.as_deref())?;
        validate_timestamp(Some(self.trial_deadline_unix), "trial deadline")
    }
}

impl CheckoutResult {
    #[cfg(test)]
    fn validate(&self) -> Result<()> {
        self.validate_at(system_unix_time()?)
    }

    fn validate_at(&self, now: i64) -> Result<()> {
        match self.kind.as_str() {
            "checkout_created" => {
                let url = self
                    .url
                    .as_deref()
                    .ok_or_else(|| anyhow!("invalid_response: Checkout result has no URL"))?;
                urls::validate_checkout_url(url)?;
                self.validate_poll_expiry(now)?;
                if self.state.is_some() {
                    bail!("invalid_response: Checkout result unexpectedly contains account state");
                }
            }
            "checkout_pending" => {
                if self.url.is_some() || self.state.is_some() {
                    bail!("invalid_response: pending Checkout result contains unexpected data");
                }
                self.validate_poll_expiry(now)?;
            }
            "already_subscribed" => {
                if self.url.is_some() || self.expires_at_unix.is_some() {
                    bail!("invalid_response: subscription result unexpectedly contains Checkout");
                }
                self.state
                    .as_ref()
                    .ok_or_else(|| {
                        anyhow!("invalid_response: subscription result has no account state")
                    })?
                    .validate()?;
            }
            _ => bail!("invalid_response: commercial API returned an invalid Checkout result"),
        }
        Ok(())
    }

    fn validate_poll_expiry(&self, now: i64) -> Result<()> {
        let expires_at = self
            .expires_at_unix
            .ok_or_else(|| anyhow!("invalid_response: Checkout result has no expiry"))?;
        if expires_at <= now || expires_at > now.saturating_add(MAX_CHECKOUT_LIFETIME_SECONDS) {
            bail!("invalid_response: Checkout expiry is outside allowed bounds");
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct EmptyRequest {}

#[derive(Serialize)]
struct CheckoutRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    referral_claim_token: Option<&'a str>,
}

#[derive(Serialize)]
struct EntitlementRequest<'a> {
    installation_public_key_base64url: &'a str,
}

#[derive(Serialize)]
pub struct TrialChallengeRequest<'a> {
    pub schema_version: u16,
    pub channel: &'a str,
    pub target: &'a str,
    pub current_version: Option<&'a str>,
    pub protocol_version: u16,
    pub protocol_fingerprint: &'a str,
    pub installation_public_key_base64url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referral_codename: Option<&'a str>,
}

#[derive(Serialize)]
struct TrialActivationRequest<'a> {
    schema_version: u16,
    challenge_id: &'a str,
    installation_public_key_base64url: &'a str,
    evidence: &'a serde_json::Value,
}

#[derive(Serialize)]
struct TrialRefreshRequest<'a> {
    schema_version: u16,
    installation_public_key_base64url: &'a str,
}

fn validate_origin(origin: &Url) -> Result<()> {
    if origin.scheme() != "https"
        || origin.host_str().is_none()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !origin.username().is_empty()
        || origin.password().is_some()
    {
        bail!("invalid_request: commercial API must be an HTTPS origin");
    }
    Ok(())
}

fn validate_access_header_value(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_ACCESS_HEADER_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        bail!("invalid_request: staging Cloudflare Access credential is invalid");
    }
    Ok(())
}

fn validate_access_token(token: &str) -> Result<()> {
    if token.is_empty()
        || token.len() > MAX_ACCESS_TOKEN_BYTES
        || token.bytes().any(|byte| byte.is_ascii_control())
    {
        bail!("authentication_required: commercial access token is unavailable");
    }
    Ok(())
}

fn validate_authorization_header(value: &str) -> Result<()> {
    if value.len() > MAX_ACCESS_TOKEN_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
        || !(value.starts_with("Bearer ") || value.starts_with("CtxTrial "))
    {
        bail!("authentication_required: commercial access token is unavailable");
    }
    Ok(())
}

fn bearer_authorization(token: &str) -> Result<Zeroizing<String>> {
    validate_access_token(token)?;
    Ok(Zeroizing::new(format!("Bearer {token}")))
}

fn trial_authorization(token: &str) -> Result<Zeroizing<String>> {
    validate_trial_token(token)?;
    Ok(Zeroizing::new(format!("CtxTrial {token}")))
}

fn validate_trial_token(token: &str) -> Result<()> {
    if invalid_trial_token(token) {
        bail!("invalid_response: anonymous trial credential is invalid");
    }
    Ok(())
}

fn invalid_trial_token(token: &str) -> bool {
    token.len() < 16
        || token.len() > MAX_TRIAL_ACCESS_TOKEN_BYTES
        || token.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
        })
}

fn validate_fixed_base64url(value: &str, label: &str) -> Result<()> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("invalid_request: {label} is invalid");
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    if value.len() < 3
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("invalid_response: commercial {label} identifier is invalid");
    }
    Ok(())
}

fn validate_timestamp(value: Option<i64>, label: &str) -> Result<()> {
    if value.is_some_and(|value| value <= 0 || value > MAX_TIMESTAMP) {
        bail!("invalid_response: commercial {label} is invalid");
    }
    Ok(())
}

fn system_unix_time() -> Result<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("invalid_response: system clock is before Unix epoch")?
            .as_secs(),
    )
    .context("invalid_response: system time is invalid")
}

#[cfg(test)]
fn unix_time() -> Result<i64> {
    system_unix_time()
}

pub fn commercial_retry_after(error: &anyhow::Error) -> Option<Duration> {
    response::commercial_retry_after(error)
}

pub fn checkout_retry_after(error: &anyhow::Error) -> Option<Duration> {
    commercial_retry_after(error)
}

pub fn validate_https_url(value: &str, label: &str) -> Result<Url> {
    if value.is_empty() || value.len() > MAX_URL_BYTES {
        bail!("invalid_response: {label} URL is invalid");
    }
    let parsed =
        Url::parse(value).with_context(|| format!("invalid_response: invalid {label} URL"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        bail!("invalid_response: {label} URL must be HTTPS");
    }
    Ok(parsed)
}

#[cfg(test)]
#[path = "commercial_api_tests.rs"]
mod tests;
