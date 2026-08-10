use super::*;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BlameFreshnessPolicy {
    LatestCommitted,
    WaitForCurrent,
}

pub fn prepare_blame_freshness_with(
    policy: BlameFreshnessPolicy,
    wake_daemon: impl FnOnce() -> Result<()>,
    wait_for_current: impl FnOnce() -> Result<String>,
) -> Result<Option<String>> {
    match policy {
        BlameFreshnessPolicy::LatestCommitted => {
            // Status selects the helper's latest atomically committed Pro
            // receipt. A bounded catch-up wake is useful but must not hide an
            // independently queryable committed Pro generation.
            let _ = wake_daemon();
            Ok(None)
        }
        BlameFreshnessPolicy::WaitForCurrent => wait_for_current().map(Some),
    }
}

pub fn start_materialization(
    host: &(impl InstalledProHost + ?Sized),
    data_root: &Path,
) -> Result<MaterializationStartReceipt> {
    let required = BTreeSet::from([Capability::Status]);
    // Status is part of the materialization authority decision, so bind it to
    // the stored installation identity exactly like the public status path.
    // A capability-only Status connection is intentionally unauthenticated
    // and helpers must reject it for an initialized graph.
    let mut client = ProClient::connect_for_status(host, data_root, &required)?;
    let prior_core_generation_id = helper_status(&mut client)?
        .core_receipt
        .map(|receipt| receipt.core_generation_id);
    Ok(MaterializationStartReceipt {
        prior_core_generation_id,
    })
}

pub fn finish_materialization(
    host: &(impl InstalledProHost + ?Sized),
    data_root: &Path,
    start: MaterializationStartReceipt,
    core_generation_id: String,
) -> Result<MaterializationFinalizationReceipt> {
    let required = BTreeSet::from([Capability::Status]);
    let mut client = ProClient::connect_for_status(host, data_root, &required)?;
    let status = helper_status_for(&mut client, Some(core_generation_id.clone()))?;
    if status.currentness != ctx_pro_host_protocol::CoreProjectionCurrentness::Current {
        bail!("not_materialized: Pro Core projection is not current");
    }
    let receipt = status.core_receipt.ok_or_else(|| {
        anyhow!("not_materialized: Pro helper has no completed Core materialization receipt")
    })?;
    if receipt.core_generation_id != core_generation_id {
        bail!(
            "stale_source: Pro helper generation {} does not match Core generation {}",
            receipt.core_generation_id,
            core_generation_id
        );
    }

    let source_count = u64::from(receipt.source_count);
    let no_op = start.prior_core_generation_id.as_deref() == Some(core_generation_id.as_str());

    Ok(MaterializationFinalizationReceipt {
        schema_version: 1,
        payload_type: "pro_core_materialization",
        core_generation_id,
        source_count,
        batches: u64::from(!no_op),
        observations: source_count,
        replayed_batches: 0,
    })
}

pub(super) fn required_blame_capabilities(target: &BlameTarget) -> BTreeSet<Capability> {
    let mut capabilities = BTreeSet::from([Capability::Status, Capability::Query]);
    if target.requires_git_read() {
        capabilities.insert(Capability::GitRead);
    }
    capabilities
}

pub(super) fn helper_status(client: &mut ProClient) -> Result<ctx_pro_host_protocol::StatusResult> {
    helper_status_for(client, None)
}

fn helper_status_for(
    client: &mut ProClient,
    requested_core_generation_id: Option<String>,
) -> Result<ctx_pro_host_protocol::StatusResult> {
    helper_status_with(requested_core_generation_id, &mut |message, timeout| {
        client.exchange(message, timeout)
    })
}

pub(super) fn helper_status_with(
    requested_core_generation_id: Option<String>,
    exchange: &mut impl FnMut(HostMessage, Duration) -> Result<HelperMessage>,
) -> Result<StatusResult> {
    match exchange(
        HostMessage::Status(StatusRequest {
            requested_core_generation_id,
        }),
        HANDSHAKE_TIMEOUT,
    )? {
        HelperMessage::Status(status) => {
            status
                .validate()
                .map_err(|error| anyhow!("invalid_response: {}", error.message))?;
            Ok(status)
        }
        HelperMessage::Error(error) => Err(protocol_error(error)),
        _ => bail!("invalid_response: helper returned a non-status response"),
    }
}
