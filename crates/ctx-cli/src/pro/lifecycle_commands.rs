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
    CoreProjectionCurrentness, MaterializedCoverage, ProOperation, ProStorageEvidence,
    RepositoryCoverage, PROTOCOL_VERSION,
};
use serde_json::json;

#[path = "lifecycle_commands/render.rs"]
mod render;
#[path = "lifecycle_commands/setup_output.rs"]
mod setup_output;
#[path = "lifecycle_commands/uninstall.rs"]
mod uninstall;

use crate::pro::artifact_delivery::SetupArtifactBundle;
use crate::pro::client::{self, status, status_for_core, ProStatus};
use crate::pro::commercial_lifecycle::CommercialLifecycleService;
use crate::pro::lifecycle::lifecycle_manifest::ReleaseTrust;
use crate::pro::local_deletion::LocalDeletionService;
use crate::pro::pending_materialization;
use crate::pro::referral::{parse_referral_codename_unchecked, ReferralCodename};
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
        ProMaterializationModeV1, ProMaterializationTelemetryV1, ProReconcileOutcomeV1,
        ProUninstallDataDispositionV1,
    },
    output::JsonOutputFormat,
    pro::stable_error_code,
    ui::Ui,
};
#[cfg(test)]
use ctx_pro_application::{validate_access_status, ProSetupRepairability};
use ctx_pro_application::{
    HelperConnectionFact, LifecycleCommandFacts, ManageAccess, MaterializationFact,
    MaterializationMode, ReconcileFact, SetupAccess, SetupAccessRequest, SetupAdmission,
    SetupCompletion, SetupStart,
};
use ctx_pro_lifecycle::operation::LifecycleOperation;
use render::{
    browser_notice as render_browser_notice, manage as render_manage_human,
    setup as render_setup_human,
};
use setup_output::write_setup_result;
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

pub(crate) type ProSetupPlan = ctx_pro_application::SetupPlan<SetupArtifactBundle>;
pub(crate) type ProManagePlan = ctx_pro_application::ManagePlan;

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

struct CliLifecycleAccess<'a> {
    service: &'a mut dyn ProLifecycleService,
    ui: &'a mut Ui,
    human_output: bool,
    browser_enabled: bool,
}

impl SetupAccess<SetupArtifactBundle> for CliLifecycleAccess<'_> {
    fn release_trust(&self) -> Result<ReleaseTrust> {
        self.service.release_trust()
    }

    fn setup(
        &mut self,
        request: SetupAccessRequest<'_>,
    ) -> Result<ctx_pro_application::SetupPlan<SetupArtifactBundle>> {
        self.service.setup(
            request.operation,
            request.data_root,
            request.installed_version,
            request.trial_only,
            request.referral_codename,
            self.ui,
            self.human_output,
            self.browser_enabled,
        )
    }
}

impl ManageAccess for CliLifecycleAccess<'_> {
    fn manage(&mut self, data_root: &Path) -> Result<ctx_pro_application::ManagePlan> {
        self.service
            .manage(data_root, self.ui, self.human_output, self.browser_enabled)
    }
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
            let execution = client::application().admit_setup::<SetupArtifactBundle>(
                data_root,
                trial_only,
                referral.as_ref().map(ReferralCodename::as_str),
            );
            let admission = lifecycle_execution_result(execution, telemetry)?;
            let admission = match admission {
                SetupAdmission::Replayed(outcome) => {
                    return write_setup_outcome(data_root, &outcome, json_output, ui);
                }
                SetupAdmission::Start(admission) => admission,
            };
            #[cfg(ctx_pro_test_helper)]
            if let Some(mut service) = crate::pro::test_control::lifecycle_service()? {
                return run_setup(
                    data_root,
                    admission,
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
                admission,
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
    lifecycle_status_value(status(data_root), preserved_data_marker_is_set(data_root))
}

pub(crate) fn lifecycle_status_json_for_core(
    data_root: &Path,
    active_core: Option<&ctx_history_index::VerifiedIndex>,
) -> serde_json::Value {
    lifecycle_status_value(
        status_for_core(data_root, active_core),
        preserved_data_marker_is_set(data_root),
    )
}

pub(super) fn lifecycle_status_value(helper: ProStatus, preserved_data: bool) -> serde_json::Value {
    ctx_pro_application::lifecycle_status_value(helper, preserved_data)
}

#[allow(clippy::too_many_arguments)]
fn run_setup(
    data_root: &Path,
    admission: SetupStart<'_>,
    service: &mut dyn ProLifecycleService,
    json_output: bool,
    defer_materialization: bool,
    trial_only: bool,
    referral_codename: Option<&str>,
    telemetry: &mut ProLifecycleTelemetryV1,
    ui: &mut Ui,
) -> Result<()> {
    let mut access = CliLifecycleAccess {
        service,
        ui,
        human_output: !json_output,
        browser_enabled: !json_output,
    };
    let execution = client::application().setup(
        admission,
        &mut access,
        defer_materialization,
        trial_only,
        referral_codename,
    );
    let outcome = lifecycle_execution_result(execution, telemetry)?;
    write_setup_outcome(data_root, &outcome, json_output, access.ui)
}

fn write_setup_outcome(
    data_root: &Path,
    outcome: &ctx_pro_application::SetupCommandOutcome,
    json_output: bool,
    ui: &mut Ui,
) -> Result<()> {
    match &outcome.completion {
        SetupCompletion::Materialized(materialized) => write_setup_result(
            data_root,
            &outcome.account_state,
            outcome.helper_updated,
            &materialized.report,
            json_output,
            ui,
        ),
        SetupCompletion::Deferred => pending_materialization::write_deferred_setup_result(
            data_root,
            &outcome.account_state,
            outcome.helper_updated,
            json_output,
            ui,
        ),
    }
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
    let mut access = CliLifecycleAccess {
        service,
        ui,
        human_output: !context.json_output,
        browser_enabled: !context.json_output && !context.no_open,
    };
    let execution = client::application().manage(context.data_root, &mut access);
    apply_lifecycle_facts(telemetry, &execution.facts);
    let outcome = execution.result?;
    let plan = &outcome.plan;
    let browser_opened =
        !context.json_output && !context.no_open && opener(&plan.portal_url).is_ok();
    let mut value = manage_payload(plan, browser_opened);
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
            access.ui.stdout_context(),
            plan,
            &usage_report,
            conversion_action.as_ref(),
            browser_opened,
        );
        access.ui.write_stdout(&document)?;
        if !context.no_open {
            let notice = render_browser_notice(
                access.ui.stderr_context(),
                browser_opened,
                "ctx Pro account management",
            );
            access.ui.write_stderr(&notice)?;
        }
    }
    Ok(())
}

fn lifecycle_execution_result<T>(
    execution: ctx_pro_application::LifecycleExecution<T>,
    telemetry: &mut ProLifecycleTelemetryV1,
) -> Result<T> {
    let materialization_attempted = execution.facts.materialization.is_some();
    apply_lifecycle_facts(telemetry, &execution.facts);
    execution.result.map_err(|error| {
        if materialization_attempted {
            crate::pro::actionable_error(error)
        } else {
            error
        }
    })
}

fn apply_lifecycle_facts(telemetry: &mut ProLifecycleTelemetryV1, facts: &LifecycleCommandFacts) {
    telemetry.reconcile = match facts.reconcile {
        ReconcileFact::NotAttempted => telemetry.reconcile,
        ReconcileFact::Missing => ProReconcileOutcomeV1::Missing,
        ReconcileFact::Current => ProReconcileOutcomeV1::Current,
        ReconcileFact::Installed => ProReconcileOutcomeV1::Installed,
        ReconcileFact::Updated => ProReconcileOutcomeV1::Updated,
        ReconcileFact::Failed => ProReconcileOutcomeV1::Failed,
    };
    if let Some(access_state) = &facts.access_state {
        telemetry.access_state = ProAccessStateV1::from_safe_name(access_state);
    }
    match &facts.helper_connection {
        HelperConnectionFact::NotAttempted => {}
        HelperConnectionFact::Connected => {
            telemetry.helper_connection = ProHelperConnectionOutcomeV1::Connected;
        }
        HelperConnectionFact::Failed { error_code } => {
            telemetry.helper_connection =
                crate::analytics::pro_helper_connection_outcome(error_code.as_deref());
        }
    }
    if let Some(fact) = &facts.materialization {
        let mut materialization = ProMaterializationTelemetryV1::started();
        match fact {
            MaterializationFact::Completed {
                mode,
                batches,
                source_count,
                replayed_batches,
            } => {
                materialization.helper_connection = ProHelperConnectionOutcomeV1::Connected;
                materialization.mode = Some(match mode {
                    MaterializationMode::NoOp => ProMaterializationModeV1::NoOp,
                    MaterializationMode::Full => ProMaterializationModeV1::Full,
                    MaterializationMode::Incremental => ProMaterializationModeV1::Incremental,
                });
                let records = if *mode == MaterializationMode::NoOp {
                    0
                } else {
                    *source_count
                };
                materialization.complete(*batches, records, records, *replayed_batches, records);
            }
            MaterializationFact::Failed { error_code } => {
                materialization.fail(error_code.as_deref());
            }
        }
        telemetry.materialization = Some(materialization);
    }
}

#[cfg(test)]
fn with_pro_initialization<T>(data_root: &Path, body: impl FnOnce() -> Result<T>) -> Result<T> {
    let operation = LifecycleOperation::begin(data_root, true)?
        .ok_or_else(|| anyhow::anyhow!("invalid_request: failed to create Pro lifecycle lock"))?;
    if ctx_pro_lifecycle::deletion::local_pro_graph_key_cleanup_phase_exists(data_root)? {
        bail!(
            "key_store_unavailable: interrupted Pro deletion must be completed with `ctx pro uninstall --delete-data`"
        );
    }
    ctx_pro_lifecycle::state_markers::mark_initialized(&operation)?;
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
