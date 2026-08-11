use anyhow::{bail, Context as _, Result};

pub fn validate_portal_url(value: &str) -> Result<()> {
    if value.len() > 4096 {
        bail!("invalid_response: Pro management URL exceeds the maximum length");
    }
    let parsed = url::Url::parse(value).context("invalid_response: invalid Pro management URL")?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() || parsed.username() != "" {
        bail!("invalid_response: Pro management URL must be an HTTPS origin");
    }
    Ok(())
}

pub fn validate_access_status(
    state: &str,
    refresh_after_unix: Option<i64>,
    access_deadline_unix: Option<i64>,
    grace_deadline_unix: Option<i64>,
) -> Result<()> {
    if !matches!(
        state,
        "trial" | "active" | "canceling_paid" | "offline_grace" | "locked"
    ) {
        bail!("invalid_response: Pro access state is invalid");
    }
    if [
        refresh_after_unix,
        access_deadline_unix,
        grace_deadline_unix,
    ]
    .into_iter()
    .flatten()
    .any(|value| value <= 0)
    {
        bail!("invalid_response: Pro access deadline is invalid");
    }
    if matches!((access_deadline_unix, grace_deadline_unix), (Some(access), Some(grace)) if access > grace)
    {
        bail!("invalid_response: Pro access deadlines are inconsistent");
    }
    if matches!(state, "trial" | "active" | "canceling_paid") && access_deadline_unix.is_none() {
        bail!("invalid_response: Pro access deadline is missing");
    }
    if state == "offline_grace" && (access_deadline_unix.is_none() || grace_deadline_unix.is_none())
    {
        bail!("invalid_response: Pro offline-grace deadlines are missing");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_urls_require_bounded_https_urls_without_userinfo() {
        validate_portal_url("https://billing.example.test/session").unwrap();
        for invalid in [
            "http://billing.example.test/session",
            "https://user@billing.example.test/session",
            "/relative/session",
        ] {
            assert!(validate_portal_url(invalid).is_err(), "accepted {invalid}");
        }
        assert!(
            validate_portal_url(&format!("https://example.test/{}", "x".repeat(4096)))
                .unwrap_err()
                .to_string()
                .contains("exceeds the maximum length")
        );
    }

    #[test]
    fn access_status_accepts_only_complete_consistent_states() {
        for state in ["trial", "active", "canceling_paid"] {
            validate_access_status(state, None, Some(200), None).unwrap();
        }
        validate_access_status("offline_grace", Some(100), Some(200), Some(300)).unwrap();
        validate_access_status("locked", None, None, None).unwrap();

        for invalid in [
            validate_access_status("none", None, None, None),
            validate_access_status("active", None, None, None),
            validate_access_status("offline_grace", None, Some(200), None),
            validate_access_status("offline_grace", None, Some(300), Some(200)),
            validate_access_status("locked", Some(0), None, None),
        ] {
            assert!(invalid.is_err());
        }
    }
}
