use std::{
    io::{self, IsTerminal as _},
    path::Path,
    process::{Command, Stdio},
    time::Instant,
};

#[cfg(test)]
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
#[cfg(test)]
use ctx_pro_host_protocol::ProFilesystemLayout;
#[cfg(test)]
use ctx_pro_host_protocol::{
    Capability, CoreProjectionCurrentness, MaterializedCoverage, ProOperation, ProStorageEvidence,
    RepositoryCoverage, PROTOCOL_FINGERPRINT, PROTOCOL_VERSION,
};
use serde_json::json;

#[path = "lifecycle_commands/render.rs"]
mod render;
#[path = "lifecycle_commands/setup_replay.rs"]
mod setup_replay;
#[path = "lifecycle_commands/uninstall.rs"]
mod uninstall;

use super::{install_verified_bundle, SetupInstallation};
use crate::pro::artifact_delivery::SetupArtifactBundle;
#[cfg(ctx_pro_test_helper)]
use crate::pro::client::smoke_helper_at_path;
#[cfg(test)]
use crate::pro::client::HelperSmoke;
use crate::pro::client::{
    materialize, materialize_in, smoke_validated_helper, status, status_for_core, ProStatus,
};
use crate::pro::commercial_lifecycle::CommercialLifecycleService;
use crate::pro::lifecycle::lifecycle_manifest::ReleaseTrust;
use crate::pro::local_deletion::{local_pro_graph_key_cleanup_phase_exists, LocalDeletionService};
use crate::pro::pending_materialization;
use crate::pro::referral::{parse_referral_codename_unchecked, ReferralCodename};
use crate::pro::setup_validation::{
    setup_artifact, validate_account_state, validate_staged_helper,
};
#[cfg(test)]
use crate::pro::{
    client::default_helper_path,
    local_deletion::{
        local_pro_initialization_indicator_exists, write_local_pro_initialization_indicator,
    },
};
use crate::{
    analytics::{
        send_pro_operation, Outcome, ProAccessStateV1, ProHelperConnectionOutcomeV1,
        ProHostOperationV1, ProLifecycleOperationV1, ProLifecycleTelemetryV1,
        ProMaterializationTelemetryV1, ProReconcileOutcomeV1, ProUninstallDataDispositionV1,
    },
    output::JsonOutputFormat,
    pro::stable_error_code,
    ui::Ui,
};
#[cfg(test)]
use ctx_pro_application::ProSetupRepairability;
use ctx_pro_application::{validate_access_status, validate_portal_url};
use ctx_pro_lifecycle::operation::LifecycleOperation;
use render::{
    browser_notice as render_browser_notice, manage as render_manage_human,
    setup as render_setup_human,
};
#[cfg(test)]
use setup_replay::reusable_setup_access_state;
use setup_replay::{record_helper_smoke, replay_completed_setup, write_setup_result};
#[cfg(test)]
use std::fs;
#[cfg(test)]
use uninstall::uninstall_payload;
use uninstall::{preserved_data_marker_is_set, run_uninstall};

#[derive(Debug, Args)]
pub(crate) struct ProArgs {
    #[command(subcommand)]
    command: Option<ProCommand>,
    #[arg(long, value_enum, default_value_t = JsonOutputFormat::Text)]
    format: JsonOutputFormat,
    #[arg(
        long,
        value_parser = parse_referral_codename_unchecked,
        help = "Apply a referral codename when starting a new anonymous trial"
    )]
    referral: Option<ReferralCodename>,
}

#[derive(Debug, Subcommand)]
enum ProCommand {
    #[command(about = "Explicit synonym for `ctx pro`")]
    Setup(ProSetupArgs),
    #[command(about = "Open account and billing management")]
    Manage(ProManageArgs),
    #[command(about = "Remove Pro and choose whether to delete or preserve local Pro data")]
    Uninstall(ProUninstallArgs),
    #[cfg(ctx_pro_test_helper)]
    #[command(name = "_test-publish-helper-recheck", hide = true)]
    TestPublishHelperRecheck(TestPublishHelperRecheckArgs),
    #[cfg(ctx_pro_test_helper)]
    #[command(name = "_test-wake-helper-recheck", hide = true)]
    TestWakeHelperRecheck,
}

#[cfg(ctx_pro_test_helper)]
#[derive(Debug, Args)]
struct TestPublishHelperRecheckArgs {
    #[arg(long)]
    target_helper_sha256: String,
}

#[derive(Debug, Args)]
struct ProSetupArgs {
    #[arg(long, value_enum, default_value_t = JsonOutputFormat::Text)]
    format: JsonOutputFormat,
    #[arg(long, hide = true)]
    defer_materialization: bool,
    #[arg(long, hide = true)]
    trial_only: bool,
}

#[derive(Debug, Args)]
struct ProManageArgs {
    #[arg(long, help = "Print the portal URL without opening a browser")]
    no_open: bool,
    #[arg(long, value_enum, default_value_t = JsonOutputFormat::Text)]
    format: JsonOutputFormat,
}

#[derive(Debug, Args)]
struct ProUninstallArgs {
    #[arg(long, conflicts_with = "keep_data", help = "Delete local Pro data")]
    delete_data: bool,
    #[arg(
        long,
        conflicts_with = "delete_data",
        help = "Preserve local Pro data for later setup"
    )]
    keep_data: bool,
    #[arg(long, value_enum, default_value_t = JsonOutputFormat::Text)]
    format: JsonOutputFormat,
}

const UNINSTALL_DATA_PROMPT: &str =
    "Delete all local Pro data? It can be rebuilt if you set up Pro again. [Y/n]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UninstallDataDisposition {
    Delete,
    Keep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalProDataOutcome {
    Absent,
    Deleted,
    Preserved,
}

impl ProArgs {
    pub(crate) fn validate_invocation(&self) -> Result<()> {
        if let Some(referral) = &self.referral {
            referral.validate()?;
        }
        if self.referral.is_some() && self.command.is_some() {
            bail!("invalid_request: --referral is accepted only by bare `ctx pro`");
        }
        Ok(())
    }

    pub(crate) fn json_output(&self) -> bool {
        self.format.is_json()
            || match &self.command {
                Some(ProCommand::Setup(args)) => args.format.is_json(),
                Some(ProCommand::Manage(args)) => args.format.is_json(),
                Some(ProCommand::Uninstall(args)) => args.format.is_json(),
                #[cfg(ctx_pro_test_helper)]
                Some(
                    ProCommand::TestPublishHelperRecheck(_) | ProCommand::TestWakeHelperRecheck,
                ) => false,
                None => false,
            }
    }

    fn telemetry_operation(&self) -> ProLifecycleOperationV1 {
        match &self.command {
            Some(ProCommand::Manage(_)) => ProLifecycleOperationV1::Manage,
            Some(ProCommand::Uninstall(_)) => ProLifecycleOperationV1::Uninstall,
            #[cfg(ctx_pro_test_helper)]
            Some(ProCommand::TestPublishHelperRecheck(_) | ProCommand::TestWakeHelperRecheck) => {
                ProLifecycleOperationV1::Setup
            }
            None | Some(ProCommand::Setup(_)) => ProLifecycleOperationV1::Setup,
        }
    }

    pub(crate) fn operation_descriptor(&self) -> crate::operation_descriptor::CliOperation {
        match &self.command {
            Some(ProCommand::Manage(_)) => crate::operation_descriptor::CliOperation::ProManage,
            Some(ProCommand::Uninstall(_)) => {
                crate::operation_descriptor::CliOperation::ProUninstall
            }
            #[cfg(ctx_pro_test_helper)]
            Some(ProCommand::TestPublishHelperRecheck(_) | ProCommand::TestWakeHelperRecheck) => {
                crate::operation_descriptor::CliOperation::ProSetup
            }
            None | Some(ProCommand::Setup(_)) => {
                crate::operation_descriptor::CliOperation::ProSetup
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProSetupPlan {
    pub(crate) artifact: Option<SetupArtifactBundle>,
    pub(crate) account_state: String,
}

#[derive(Debug)]
pub(crate) struct ProManagePlan {
    pub(crate) portal_url: String,
    pub(crate) access_state: String,
    pub(crate) refresh_after_unix: Option<i64>,
    pub(crate) access_deadline_unix: Option<i64>,
    pub(crate) grace_deadline_unix: Option<i64>,
}

/// Narrow orchestration seam for the hosted commercial client. WorkOS/Stripe,
/// entitlement proof, and R2 delivery own their formats in separate modules.
pub(crate) trait ProLifecycleService {
    fn release_trust(&self) -> Result<ReleaseTrust>;
    #[allow(clippy::too_many_arguments)]
    fn setup(
        &mut self,
        operation: &LifecycleOperation,
        data_root: &Path,
        installed_version: Option<&str>,
        trial_only: bool,
        referral_codename: Option<&str>,
        ui: &mut Ui,
        human_output: bool,
        browser_enabled: bool,
    ) -> Result<ProSetupPlan>;
    fn manage(
        &mut self,
        data_root: &Path,
        ui: &mut Ui,
        human_output: bool,
        browser_enabled: bool,
    ) -> Result<ProManagePlan>;
}

/// Local-only destruction seam. Implementations may locate and delete native
/// vault records, but do not need commercial configuration or network access.
pub(crate) use ctx_pro_application::ProDeletionService;

pub(crate) fn run_lifecycle(
    args: ProArgs,
    data_root: &Path,
    usage_storage: &crate::local_usage::LocalUsageStorageAuthority,
    usage_control: &crate::local_usage::UsageControlSnapshot,
    ui: &mut Ui,
) -> Result<()> {
    let started = Instant::now();
    let human_output = !args.json_output();
    let retry_command = render::human_retry_command(&args);
    let mut telemetry = ProLifecycleTelemetryV1::new(args.telemetry_operation());
    let control_validation = crate::pro::commercial_config::reject_test_control_outside_test_host();
    let emit_telemetry = control_validation.is_ok();
    let result = control_validation.and_then(|()| {
        run_lifecycle_inner(
            args,
            data_root,
            usage_storage,
            usage_control,
            &mut telemetry,
            ui,
        )
    });
    #[cfg(ctx_pro_test_helper)]
    let result = crate::pro::test_control::finish(result);
    if let Err(error) = &result {
        telemetry.fail(stable_error_code(error));
    }
    if emit_telemetry {
        send_pro_operation(
            data_root,
            ProHostOperationV1::Lifecycle(telemetry),
            if result.is_ok() {
                Outcome::Success
            } else {
                Outcome::Failure
            },
            started.elapsed(),
        );
    }
    crate::pro::human_result(result, human_output, retry_command, ui)
}

fn run_lifecycle_inner(
    args: ProArgs,
    data_root: &Path,
    usage_storage: &crate::local_usage::LocalUsageStorageAuthority,
    usage_control: &crate::local_usage::UsageControlSnapshot,
    telemetry: &mut ProLifecycleTelemetryV1,
    ui: &mut Ui,
) -> Result<()> {
    #[cfg(ctx_pro_test_helper)]
    crate::pro::test_control::prepare()?;
    args.validate_invocation()?;
    let json_output = args.json_output();
    let defer_materialization = matches!(
        &args.command,
        Some(ProCommand::Setup(ProSetupArgs {
            defer_materialization: true,
            ..
        }))
    );
    let trial_only = matches!(
        &args.command,
        Some(ProCommand::Setup(ProSetupArgs {
            trial_only: true,
            ..
        }))
    );
    let ProArgs {
        command, referral, ..
    } = args;
    match command {
        #[cfg(ctx_pro_test_helper)]
        Some(ProCommand::TestPublishHelperRecheck(args)) => {
            crate::semantic::publish_source_backed_pro_recheck(
                data_root,
                &args.target_helper_sha256,
            )
        }
        #[cfg(ctx_pro_test_helper)]
        Some(ProCommand::TestWakeHelperRecheck) => {
            crate::semantic::wake_source_backed_pro_recheck(data_root);
            Ok(())
        }
        None | Some(ProCommand::Setup(_)) => {
            crate::identity::installation_id(data_root)
                .context("key_store_unavailable: initialize local Pro installation identity")?;
            if replay_completed_setup(
                data_root,
                json_output,
                trial_only,
                referral.as_ref().map(ReferralCodename::as_str),
                telemetry,
                ui,
            )? {
                return Ok(());
            }
            #[cfg(ctx_pro_test_helper)]
            if let Some(mut service) = crate::pro::test_control::lifecycle_service()? {
                return run_setup(
                    data_root,
                    &mut service,
                    json_output,
                    defer_materialization,
                    trial_only,
                    referral.as_ref().map(ReferralCodename::as_str),
                    telemetry,
                    ui,
                );
            }
            let mut service = CommercialLifecycleService::production(data_root)?;
            run_setup(
                data_root,
                &mut service,
                json_output,
                defer_materialization,
                trial_only,
                referral.as_ref().map(ReferralCodename::as_str),
                telemetry,
                ui,
            )
        }
        Some(ProCommand::Manage(args)) => {
            #[cfg(ctx_pro_test_helper)]
            if let Some(mut service) = crate::pro::test_control::lifecycle_service()? {
                return run_manage(
                    ManageContext {
                        data_root,
                        no_open: args.no_open,
                        json_output,
                        usage_storage,
                        usage_control,
                    },
                    &mut service,
                    telemetry,
                    ui,
                );
            }
            let mut service = CommercialLifecycleService::production(data_root)?;
            run_manage(
                ManageContext {
                    data_root,
                    no_open: args.no_open,
                    json_output,
                    usage_storage,
                    usage_control,
                },
                &mut service,
                telemetry,
                ui,
            )
        }
        Some(ProCommand::Uninstall(args)) => {
            let disposition = uninstall_data_disposition(&args, json_output, ui)?;
            telemetry.uninstall_data = Some(match disposition {
                UninstallDataDisposition::Delete => ProUninstallDataDispositionV1::Delete,
                UninstallDataDisposition::Keep => ProUninstallDataDispositionV1::Preserve,
            });
            match disposition {
                UninstallDataDisposition::Delete => {
                    let mut service = LocalDeletionService::production();
                    run_uninstall(data_root, Some(&mut service), disposition, json_output, ui)
                        .map(|_| ())
                }
                UninstallDataDisposition::Keep => {
                    run_uninstall(data_root, None, disposition, json_output, ui).map(|_| ())
                }
            }
        }
    }
}

fn uninstall_data_disposition(
    args: &ProUninstallArgs,
    json_output: bool,
    ui: &mut Ui,
) -> Result<UninstallDataDisposition> {
    if args.delete_data {
        return Ok(UninstallDataDisposition::Delete);
    }
    if args.keep_data {
        return Ok(UninstallDataDisposition::Keep);
    }
    if json_output || !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        bail!("invalid_request: noninteractive uninstall requires --delete-data or --keep-data");
    }
    prompt_uninstall_data_disposition(&mut io::stdin().lock(), ui)
}

fn prompt_uninstall_data_disposition(
    input: &mut impl io::BufRead,
    ui: &mut Ui,
) -> Result<UninstallDataDisposition> {
    render::prompt_uninstall_data_disposition(input, ui)
}

pub(crate) fn lifecycle_status_json(data_root: &Path) -> serde_json::Value {
    observe_lifecycle_status_query();
    lifecycle_status_value(status(data_root), preserved_data_marker_is_set(data_root))
}

pub(crate) fn lifecycle_status_json_for_core(
    data_root: &Path,
    active_core: Option<&ctx_history_index::VerifiedIndex>,
) -> serde_json::Value {
    observe_lifecycle_status_query();
    lifecycle_status_value(
        status_for_core(data_root, active_core),
        preserved_data_marker_is_set(data_root),
    )
}

#[cfg(test)]
thread_local! {
    static LIFECYCLE_STATUS_QUERY_COUNT: std::cell::Cell<Option<usize>> = const {
        std::cell::Cell::new(None)
    };
}

fn observe_lifecycle_status_query() {
    #[cfg(test)]
    LIFECYCLE_STATUS_QUERY_COUNT.with(|count| {
        if let Some(current) = count.get() {
            count.set(Some(current.saturating_add(1)));
        }
    });
}

#[cfg(test)]
pub(crate) fn count_lifecycle_status_queries<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    LIFECYCLE_STATUS_QUERY_COUNT.with(|count| {
        let previous = count.replace(Some(0));
        assert!(
            previous.is_none(),
            "Pro lifecycle-status query counters must not be nested"
        );
        let output = operation();
        let observed = count.replace(None).unwrap_or(0);
        (output, observed)
    })
}

pub(super) fn lifecycle_status_value(helper: ProStatus, preserved_data: bool) -> serde_json::Value {
    ctx_pro_application::lifecycle_status_value(helper, preserved_data)
}

#[allow(clippy::too_many_arguments)]
fn run_setup(
    data_root: &Path,
    service: &mut dyn ProLifecycleService,
    json_output: bool,
    defer_materialization: bool,
    trial_only: bool,
    referral_codename: Option<&str>,
    telemetry: &mut ProLifecycleTelemetryV1,
    ui: &mut Ui,
) -> Result<()> {
    let trust = service.release_trust()?;
    telemetry.reconcile = ProReconcileOutcomeV1::Failed;
    let operation = begin_pro_operation(data_root)?;
    let installation =
        ctx_pro_lifecycle::installation::reconcile_setup_installation(&operation, trust)?;
    let plan = service.setup(
        &operation,
        data_root,
        installation.installed_version(),
        trial_only,
        referral_codename,
        ui,
        !json_output,
        !json_output,
    )?;
    let replacing_existing = matches!(
        &installation,
        SetupInstallation::Current(_) | SetupInstallation::RepairRequired
    );
    telemetry.reconcile = match &installation {
        SetupInstallation::Current(_) => ProReconcileOutcomeV1::Current,
        SetupInstallation::Missing => ProReconcileOutcomeV1::Missing,
        SetupInstallation::RepairRequired => ProReconcileOutcomeV1::Failed,
    };
    validate_account_state(&plan.account_state)?;
    telemetry.access_state = ProAccessStateV1::from_safe_name(&plan.account_state);
    let artifact = setup_artifact(&installation, plan.artifact)?;
    let helper_updated = if let Some(bundle) = artifact {
        match bundle {
            SetupArtifactBundle::Release(bundle) => {
                let smoke = record_helper_smoke(
                    smoke_validated_helper(data_root, bundle.identity().clone()),
                    telemetry,
                )?;
                validate_staged_helper(&smoke)?;
                install_verified_bundle(&bundle, &operation, trust)?;
                telemetry.reconcile = if replacing_existing {
                    ProReconcileOutcomeV1::Updated
                } else {
                    ProReconcileOutcomeV1::Installed
                };
                true
            }
            #[cfg(ctx_pro_test_helper)]
            SetupArtifactBundle::TestControl(bundle) => {
                let helper = bundle.verified_path()?;
                let smoke =
                    record_helper_smoke(smoke_helper_at_path(data_root, &helper), telemetry)?;
                validate_staged_helper(&smoke)?;
                false
            }
        }
    } else {
        false
    };
    if defer_materialization {
        return pending_materialization::defer_setup(
            &operation,
            data_root,
            &plan.account_state,
            helper_updated,
            json_output,
            ui,
        );
    }
    // An empty repository-root set still materializes canonical transcript evidence.
    let mut materialization = ProMaterializationTelemetryV1::started();
    let report = materialize_in(data_root, &operation, &mut materialization);
    if materialization.helper_connection != ProHelperConnectionOutcomeV1::NotAttempted {
        telemetry.helper_connection = materialization.helper_connection;
    }
    telemetry.materialization = Some(materialization);
    let report = report.map_err(crate::pro::actionable_error)?;
    write_setup_result(
        data_root,
        &plan.account_state,
        helper_updated,
        report,
        json_output,
        ui,
    )
}

struct ManageContext<'a> {
    data_root: &'a Path,
    no_open: bool,
    json_output: bool,
    usage_storage: &'a crate::local_usage::LocalUsageStorageAuthority,
    usage_control: &'a crate::local_usage::UsageControlSnapshot,
}

fn run_manage(
    context: ManageContext<'_>,
    service: &mut dyn ProLifecycleService,
    telemetry: &mut ProLifecycleTelemetryV1,
    ui: &mut Ui,
) -> Result<()> {
    run_manage_with_opener(context, service, telemetry, ui, &open_browser)
}

fn run_manage_with_opener(
    context: ManageContext<'_>,
    service: &mut dyn ProLifecycleService,
    telemetry: &mut ProLifecycleTelemetryV1,
    ui: &mut Ui,
    opener: &dyn Fn(&str) -> Result<()>,
) -> Result<()> {
    let _operation = begin_pro_operation(context.data_root)?;
    let plan = service.manage(
        context.data_root,
        ui,
        !context.json_output,
        !context.json_output && !context.no_open,
    )?;
    validate_portal_url(&plan.portal_url)?;
    validate_access_status(
        &plan.access_state,
        plan.refresh_after_unix,
        plan.access_deadline_unix,
        plan.grace_deadline_unix,
    )?;
    telemetry.access_state = ProAccessStateV1::from_safe_name(&plan.access_state);
    let browser_opened =
        !context.json_output && !context.no_open && opener(&plan.portal_url).is_ok();
    let mut value = manage_payload(&plan, browser_opened);
    let usage_report = crate::local_usage::read_report_authorized(
        context.usage_storage,
        context.usage_control,
        false,
    );
    let conversion_action =
        crate::local_usage::pro_conversion_action(Some(plan.access_state.as_str()));
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "local_usage".to_owned(),
            serde_json::to_value(&usage_report)?,
        );
        object.insert(
            "conversion_action".to_owned(),
            conversion_action.clone().unwrap_or(serde_json::Value::Null),
        );
    }
    if context.json_output {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        let document = render_manage_human(
            ui.stdout_context(),
            &plan,
            &usage_report,
            conversion_action.as_ref(),
            browser_opened,
        );
        ui.write_stdout(&document)?;
        if !context.no_open {
            let notice = render_browser_notice(
                ui.stderr_context(),
                browser_opened,
                "ctx Pro account management",
            );
            ui.write_stderr(&notice)?;
        }
    }
    Ok(())
}

fn begin_pro_operation(data_root: &Path) -> Result<LifecycleOperation> {
    let lifecycle_operation = LifecycleOperation::begin(data_root, true)?
        .ok_or_else(|| anyhow::anyhow!("invalid_request: failed to create Pro lifecycle lock"))?;
    if local_pro_graph_key_cleanup_phase_exists(data_root)? {
        bail!(
            "key_store_unavailable: interrupted Pro deletion must be completed with `ctx pro uninstall --delete-data`"
        );
    }
    ctx_pro_lifecycle::state_markers::mark_initialized(&lifecycle_operation)?;
    Ok(lifecycle_operation)
}

#[cfg(test)]
fn with_pro_initialization<T>(data_root: &Path, body: impl FnOnce() -> Result<T>) -> Result<T> {
    let _operation = begin_pro_operation(data_root)?;
    body()
}

fn manage_payload(plan: &ProManagePlan, browser_opened: bool) -> serde_json::Value {
    json!({
        "schema_version": 1,
        "payload_type": "pro_manage",
        "portal_url": plan.portal_url,
        "browser_opened": browser_opened,
        "access_state": plan.access_state,
        "refresh_after_unix": plan.refresh_after_unix,
        "access_deadline_unix": plan.access_deadline_unix,
        "grace_deadline_unix": plan.grace_deadline_unix,
    })
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(ctx_pro_test_helper)]
    if let Some(result) = crate::pro::test_control::browser_result_if_active(url) {
        return result;
    }

    let mut command = if cfg!(target_os = "macos") {
        let mut command = Command::new("open");
        command.arg(url);
        command
    } else if cfg!(windows) {
        let mut command = Command::new("rundll32.exe");
        command.args(["url.dll,FileProtocolHandler", url]);
        command
    } else {
        let mut command = Command::new("xdg-open");
        command.arg(url);
        command
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("open Pro management URL")?;
    Ok(())
}

#[cfg(test)]
#[path = "lifecycle_commands/tests.rs"]
mod tests;
