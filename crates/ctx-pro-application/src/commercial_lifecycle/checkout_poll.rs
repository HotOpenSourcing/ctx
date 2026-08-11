use std::time::Duration;

use anyhow::{anyhow, Result};

const CHECKOUT_POLL_INITIAL_SECONDS: u64 = 3;
const CHECKOUT_POLL_MAX_INTERVAL_SECONDS: u64 = 15;
const CHECKOUT_POLL_PROGRESS_SECONDS: u64 = 60;
pub(super) const CHECKOUT_POLL_MAX_SECONDS: u64 = 30 * 60;

pub(super) enum CheckoutPoll<T> {
    Granted(T),
    Pending,
    Retryable(Option<Duration>),
    Fatal(anyhow::Error),
}

pub(super) fn poll_checkout_access<T>(
    checkout_expires_at_unix: i64,
    mut now: impl FnMut() -> Result<i64>,
    mut elapsed: impl FnMut() -> Duration,
    mut sleep: impl FnMut(Duration),
    mut account: impl FnMut() -> CheckoutPoll<T>,
    mut progress: impl FnMut(u64),
) -> Result<T> {
    let maximum_elapsed = Duration::from_secs(CHECKOUT_POLL_MAX_SECONDS);
    let mut next_progress = Duration::from_secs(CHECKOUT_POLL_PROGRESS_SECONDS);
    let mut next_poll_eligible = Duration::ZERO;
    let mut poll_interval = Duration::from_secs(CHECKOUT_POLL_INITIAL_SECONDS);
    loop {
        let current_unix = now()?;
        if current_unix >= checkout_expires_at_unix {
            return Err(checkout_poll_ended(true));
        }
        let current_elapsed = elapsed();
        if current_elapsed >= maximum_elapsed {
            return Err(checkout_poll_ended(false));
        }
        if current_elapsed < next_poll_eligible {
            if current_elapsed >= next_progress {
                progress(current_elapsed.as_secs());
                next_progress = current_elapsed
                    .saturating_add(Duration::from_secs(CHECKOUT_POLL_PROGRESS_SECONDS));
            }
            let checkout_remaining = Duration::from_secs(
                u64::try_from(checkout_expires_at_unix - current_unix).unwrap_or(0),
            );
            let maximum_remaining = maximum_elapsed.saturating_sub(current_elapsed);
            let poll_remaining = next_poll_eligible.saturating_sub(current_elapsed);
            let progress_remaining = next_progress.saturating_sub(current_elapsed);
            sleep(
                poll_remaining
                    .min(progress_remaining)
                    .min(checkout_remaining)
                    .min(maximum_remaining),
            );
            continue;
        }
        let outcome = account();
        let current_unix = now()?;
        if current_unix >= checkout_expires_at_unix {
            return Err(checkout_poll_ended(true));
        }
        let current_elapsed = elapsed();
        if current_elapsed >= maximum_elapsed {
            return Err(checkout_poll_ended(false));
        }
        let retry_after = match outcome {
            CheckoutPoll::Granted(value) => return Ok(value),
            CheckoutPoll::Pending => None,
            CheckoutPoll::Retryable(retry_after) => retry_after,
            CheckoutPoll::Fatal(error) => return Err(error),
        };
        if current_elapsed >= next_progress {
            progress(current_elapsed.as_secs());
            next_progress =
                current_elapsed.saturating_add(Duration::from_secs(CHECKOUT_POLL_PROGRESS_SECONDS));
        }
        let requested_interval =
            retry_after.map_or(poll_interval, |retry_after| poll_interval.max(retry_after));
        next_poll_eligible = current_elapsed.saturating_add(requested_interval);
        poll_interval = poll_interval
            .saturating_mul(2)
            .min(Duration::from_secs(CHECKOUT_POLL_MAX_INTERVAL_SECONDS));
    }
}

fn checkout_poll_ended(expired: bool) -> anyhow::Error {
    if expired {
        anyhow!(
            "checkout_expired: Checkout expired before access was granted; rerun `ctx pro` to safely resume setup"
        )
    } else {
        anyhow!(
            "checkout_timeout: Checkout did not complete within 30 minutes; rerun `ctx pro` to safely resume setup"
        )
    }
}
