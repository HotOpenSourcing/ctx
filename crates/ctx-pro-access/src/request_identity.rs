use anyhow::{Context, Result};
use uuid::Uuid;

pub(super) fn new_idempotency_key(domain: &str, now: i64) -> Result<String> {
    let now = u64::try_from(now).context("invalid_response: system clock is before Unix epoch")?;
    Ok(format!("ctx-{domain}-v1-{now}-{}", Uuid::new_v4()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_identity_carries_one_bounded_server_verifiable_time() {
        let key = new_idempotency_key("cli", 1_723_000_000).unwrap();
        let fields = key.split('-').collect::<Vec<_>>();
        assert_eq!(fields[0..3], ["ctx", "cli", "v1"]);
        assert_eq!(fields[3], "1723000000");
        assert_eq!(key.len(), "ctx-cli-v1--".len() + fields[3].len() + 36);
        assert!(key.len() <= 128);
        assert!(new_idempotency_key("cli", -1).is_err());
    }
}
