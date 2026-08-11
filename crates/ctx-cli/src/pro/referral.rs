use std::{
    convert::Infallible,
    fmt, fs,
    io::{self, IsTerminal as _},
    path::{Path, PathBuf},
};

use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use ctx_pro_application::{
    execute_referral, is_iso_country_code, retry_referral_payout, validate_referral_codename,
    ReferralAuthMode, ReferralClock, ReferralCommand as ApplicationReferralCommand,
    ReferralOutcome, ReferralPayoutResponse, ReferralRequest as ApplicationReferralRequest,
    ReferralService as ApplicationReferralService,
};
use serde::Serialize;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod render;

use super::{
    commercial_api::{ReferralCreateResult, ReferralPayoutResult, ReferralStatusResult},
    commercial_config::selected_channel,
    commercial_lifecycle::{open_browser, CommercialLifecycleService},
    lifecycle::lifecycle_manifest::ReleaseChannel,
};
use crate::{
    output::JsonOutputFormat,
    ui::{Document, RenderContext, StreamKind, Ui},
};
use render::{
    create as render_create_human, cta as render_cta_human, payout as render_payout_human,
    payout_browser_notice as render_payout_browser_notice,
    payout_country_invalid as render_payout_country_invalid,
    payout_country_prompt as render_payout_country_prompt, status as render_status_human,
};

const REFERRAL_CTA_MARKER_PREFIX: &str = ".referral-cta-v1";

#[derive(Debug, Args)]
pub(crate) struct ReferralArgs {
    #[command(subcommand)]
    command: ReferralCommand,
}

#[derive(Debug, Subcommand)]
enum ReferralCommand {
    #[command(about = "Claim or show your stable referral codename")]
    Create(ReferralCreateArgs),
    #[command(about = "Show your aggregate referral ledger and payout state")]
    Status(ReferralStatusArgs),
    #[command(about = "Set up individual referral payouts; asks for country when needed")]
    Payout(ReferralPayoutArgs),
}

#[derive(Debug, Args)]
struct ReferralCreateArgs {
    #[arg(
        value_parser = parse_referral_codename_unchecked,
        help = "Public codename used in the share command"
    )]
    codename: ReferralCodename,
    #[arg(long, value_enum, default_value_t = JsonOutputFormat::Text)]
    format: JsonOutputFormat,
}

#[derive(Debug, Args)]
struct ReferralStatusArgs {
    #[arg(long, value_enum, default_value_t = JsonOutputFormat::Text)]
    format: JsonOutputFormat,
}

#[derive(Debug, Args)]
struct ReferralPayoutArgs {
    #[arg(long, help = "Print the Stripe-hosted URL without opening a browser")]
    no_open: bool,
    #[arg(long, value_enum, default_value_t = JsonOutputFormat::Text)]
    format: JsonOutputFormat,
    #[arg(
        long,
        value_parser = parse_country_code,
        help = "Advanced override: two-letter uppercase country code for payout onboarding"
    )]
    country: Option<CountryCode>,
}

impl ReferralArgs {
    pub(crate) fn validate_invocation(&self) -> Result<()> {
        if let ReferralCommand::Create(args) = &self.command {
            args.codename.validate()?;
        }
        Ok(())
    }

    pub(crate) const fn json_output(&self) -> bool {
        match &self.command {
            ReferralCommand::Create(args) => args.format.is_json(),
            ReferralCommand::Status(args) => args.format.is_json(),
            ReferralCommand::Payout(args) => args.format.is_json(),
        }
    }

    fn retry_command(&self) -> String {
        match &self.command {
            ReferralCommand::Create(args) => {
                format!("ctx referral create {}", args.codename.as_str())
            }
            ReferralCommand::Status(_) => "ctx referral status".to_owned(),
            ReferralCommand::Payout(args) => {
                let mut command = "ctx referral payout".to_owned();
                if args.no_open {
                    command.push_str(" --no-open");
                }
                if let Some(country) = &args.country {
                    command.push_str(" --country ");
                    command.push_str(country.as_str());
                }
                command
            }
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ReferralCodename(String);

impl ReferralCodename {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_referral_codename(&self.0)
    }
}

impl fmt::Debug for ReferralCodename {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReferralCodename([REDACTED])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CountryCode(String);

impl CountryCode {
    fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
pub(crate) fn parse_referral_codename(value: &str) -> Result<ReferralCodename, String> {
    let codename = ReferralCodename(value.to_owned());
    codename.validate().map_err(|error| error.to_string())?;
    Ok(codename)
}

pub(super) fn parse_referral_codename_unchecked(
    value: &str,
) -> std::result::Result<ReferralCodename, Infallible> {
    Ok(ReferralCodename(value.to_owned()))
}

fn parse_country_code(value: &str) -> Result<CountryCode, String> {
    if !is_iso_country_code(value) {
        return Err(
            "country must be a two-letter uppercase ISO country code, for example US".to_owned(),
        );
    }
    Ok(CountryCode(value.to_owned()))
}

fn parse_country_input(value: &str) -> Result<CountryCode, &'static str> {
    let value = value.trim();
    if value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        let code = value.to_ascii_uppercase();
        return if is_iso_country_code(&code) {
            Ok(CountryCode(code))
        } else {
            Err("enter a valid ISO country name or two-letter country code")
        };
    }
    country_code_for_name(value).map(|code| CountryCode(code.to_owned()))
}

fn country_code_for_name(value: &str) -> Result<&'static str, &'static str> {
    ISO_COUNTRY_ALIASES
        .iter()
        .chain(ISO_COUNTRIES.iter())
        .find(|(name, _)| name.eq_ignore_ascii_case(value))
        .map(|(_, code)| *code)
        .ok_or("enter a valid ISO country name or two-letter country code")
}

// Keep the interactive input independent of the host locale or an optional
// system data file. The names are the readable labels used by the country
// prompt; the codes are the ISO 3166-1 alpha-2 values sent to the service.
const ISO_COUNTRIES: &[(&str, &str)] = &[
    ("Andorra", "AD"),
    ("United Arab Emirates", "AE"),
    ("Afghanistan", "AF"),
    ("Antigua & Barbuda", "AG"),
    ("Anguilla", "AI"),
    ("Albania", "AL"),
    ("Armenia", "AM"),
    ("Angola", "AO"),
    ("Antarctica", "AQ"),
    ("Argentina", "AR"),
    ("Samoa (American)", "AS"),
    ("Austria", "AT"),
    ("Australia", "AU"),
    ("Aruba", "AW"),
    ("Åland Islands", "AX"),
    ("Azerbaijan", "AZ"),
    ("Bosnia & Herzegovina", "BA"),
    ("Barbados", "BB"),
    ("Bangladesh", "BD"),
    ("Belgium", "BE"),
    ("Burkina Faso", "BF"),
    ("Bulgaria", "BG"),
    ("Bahrain", "BH"),
    ("Burundi", "BI"),
    ("Benin", "BJ"),
    ("St Barthelemy", "BL"),
    ("Bermuda", "BM"),
    ("Brunei", "BN"),
    ("Bolivia", "BO"),
    ("Caribbean NL", "BQ"),
    ("Brazil", "BR"),
    ("Bahamas", "BS"),
    ("Bhutan", "BT"),
    ("Bouvet Island", "BV"),
    ("Botswana", "BW"),
    ("Belarus", "BY"),
    ("Belize", "BZ"),
    ("Canada", "CA"),
    ("Cocos (Keeling) Islands", "CC"),
    ("Congo (Dem. Rep.)", "CD"),
    ("Central African Rep.", "CF"),
    ("Congo (Rep.)", "CG"),
    ("Switzerland", "CH"),
    ("Côte d’Ivoire", "CI"),
    ("Cook Islands", "CK"),
    ("Chile", "CL"),
    ("Cameroon", "CM"),
    ("China", "CN"),
    ("Colombia", "CO"),
    ("Costa Rica", "CR"),
    ("Cuba", "CU"),
    ("Cape Verde", "CV"),
    ("Curaçao", "CW"),
    ("Christmas Island", "CX"),
    ("Cyprus", "CY"),
    ("Czech Republic", "CZ"),
    ("Germany", "DE"),
    ("Djibouti", "DJ"),
    ("Denmark", "DK"),
    ("Dominica", "DM"),
    ("Dominican Republic", "DO"),
    ("Algeria", "DZ"),
    ("Ecuador", "EC"),
    ("Estonia", "EE"),
    ("Egypt", "EG"),
    ("Western Sahara", "EH"),
    ("Eritrea", "ER"),
    ("Spain", "ES"),
    ("Ethiopia", "ET"),
    ("Finland", "FI"),
    ("Fiji", "FJ"),
    ("Falkland Islands", "FK"),
    ("Micronesia", "FM"),
    ("Faroe Islands", "FO"),
    ("France", "FR"),
    ("Gabon", "GA"),
    ("Britain (UK)", "GB"),
    ("Grenada", "GD"),
    ("Georgia", "GE"),
    ("French Guiana", "GF"),
    ("Guernsey", "GG"),
    ("Ghana", "GH"),
    ("Gibraltar", "GI"),
    ("Greenland", "GL"),
    ("Gambia", "GM"),
    ("Guinea", "GN"),
    ("Guadeloupe", "GP"),
    ("Equatorial Guinea", "GQ"),
    ("Greece", "GR"),
    ("South Georgia & the South Sandwich Islands", "GS"),
    ("Guatemala", "GT"),
    ("Guam", "GU"),
    ("Guinea-Bissau", "GW"),
    ("Guyana", "GY"),
    ("Hong Kong", "HK"),
    ("Heard Island & McDonald Islands", "HM"),
    ("Honduras", "HN"),
    ("Croatia", "HR"),
    ("Haiti", "HT"),
    ("Hungary", "HU"),
    ("Indonesia", "ID"),
    ("Ireland", "IE"),
    ("Israel", "IL"),
    ("Isle of Man", "IM"),
    ("India", "IN"),
    ("British Indian Ocean Territory", "IO"),
    ("Iraq", "IQ"),
    ("Iran", "IR"),
    ("Iceland", "IS"),
    ("Italy", "IT"),
    ("Jersey", "JE"),
    ("Jamaica", "JM"),
    ("Jordan", "JO"),
    ("Japan", "JP"),
    ("Kenya", "KE"),
    ("Kyrgyzstan", "KG"),
    ("Cambodia", "KH"),
    ("Kiribati", "KI"),
    ("Comoros", "KM"),
    ("St Kitts & Nevis", "KN"),
    ("Korea (North)", "KP"),
    ("Korea (South)", "KR"),
    ("Kuwait", "KW"),
    ("Cayman Islands", "KY"),
    ("Kazakhstan", "KZ"),
    ("Laos", "LA"),
    ("Lebanon", "LB"),
    ("St Lucia", "LC"),
    ("Liechtenstein", "LI"),
    ("Sri Lanka", "LK"),
    ("Liberia", "LR"),
    ("Lesotho", "LS"),
    ("Lithuania", "LT"),
    ("Luxembourg", "LU"),
    ("Latvia", "LV"),
    ("Libya", "LY"),
    ("Morocco", "MA"),
    ("Monaco", "MC"),
    ("Moldova", "MD"),
    ("Montenegro", "ME"),
    ("St Martin (French)", "MF"),
    ("Madagascar", "MG"),
    ("Marshall Islands", "MH"),
    ("North Macedonia", "MK"),
    ("Mali", "ML"),
    ("Myanmar (Burma)", "MM"),
    ("Mongolia", "MN"),
    ("Macau", "MO"),
    ("Northern Mariana Islands", "MP"),
    ("Martinique", "MQ"),
    ("Mauritania", "MR"),
    ("Montserrat", "MS"),
    ("Malta", "MT"),
    ("Mauritius", "MU"),
    ("Maldives", "MV"),
    ("Malawi", "MW"),
    ("Mexico", "MX"),
    ("Malaysia", "MY"),
    ("Mozambique", "MZ"),
    ("Namibia", "NA"),
    ("New Caledonia", "NC"),
    ("Niger", "NE"),
    ("Norfolk Island", "NF"),
    ("Nigeria", "NG"),
    ("Nicaragua", "NI"),
    ("Netherlands", "NL"),
    ("Norway", "NO"),
    ("Nepal", "NP"),
    ("Nauru", "NR"),
    ("Niue", "NU"),
    ("New Zealand", "NZ"),
    ("Oman", "OM"),
    ("Panama", "PA"),
    ("Peru", "PE"),
    ("French Polynesia", "PF"),
    ("Papua New Guinea", "PG"),
    ("Philippines", "PH"),
    ("Pakistan", "PK"),
    ("Poland", "PL"),
    ("St Pierre & Miquelon", "PM"),
    ("Pitcairn", "PN"),
    ("Puerto Rico", "PR"),
    ("Palestine", "PS"),
    ("Portugal", "PT"),
    ("Palau", "PW"),
    ("Paraguay", "PY"),
    ("Qatar", "QA"),
    ("Réunion", "RE"),
    ("Romania", "RO"),
    ("Serbia", "RS"),
    ("Russia", "RU"),
    ("Rwanda", "RW"),
    ("Saudi Arabia", "SA"),
    ("Solomon Islands", "SB"),
    ("Seychelles", "SC"),
    ("Sudan", "SD"),
    ("Sweden", "SE"),
    ("Singapore", "SG"),
    ("St Helena", "SH"),
    ("Slovenia", "SI"),
    ("Svalbard & Jan Mayen", "SJ"),
    ("Slovakia", "SK"),
    ("Sierra Leone", "SL"),
    ("San Marino", "SM"),
    ("Senegal", "SN"),
    ("Somalia", "SO"),
    ("Suriname", "SR"),
    ("South Sudan", "SS"),
    ("Sao Tome & Principe", "ST"),
    ("El Salvador", "SV"),
    ("St Maarten (Dutch)", "SX"),
    ("Syria", "SY"),
    ("Eswatini (Swaziland)", "SZ"),
    ("Turks & Caicos Is", "TC"),
    ("Chad", "TD"),
    ("French S. Terr.", "TF"),
    ("Togo", "TG"),
    ("Thailand", "TH"),
    ("Tajikistan", "TJ"),
    ("Tokelau", "TK"),
    ("East Timor", "TL"),
    ("Turkmenistan", "TM"),
    ("Tunisia", "TN"),
    ("Tonga", "TO"),
    ("Turkey", "TR"),
    ("Trinidad & Tobago", "TT"),
    ("Tuvalu", "TV"),
    ("Taiwan", "TW"),
    ("Tanzania", "TZ"),
    ("Ukraine", "UA"),
    ("Uganda", "UG"),
    ("US minor outlying islands", "UM"),
    ("United States", "US"),
    ("Uruguay", "UY"),
    ("Uzbekistan", "UZ"),
    ("Vatican City", "VA"),
    ("St Vincent", "VC"),
    ("Venezuela", "VE"),
    ("Virgin Islands (UK)", "VG"),
    ("Virgin Islands (US)", "VI"),
    ("Vietnam", "VN"),
    ("Vanuatu", "VU"),
    ("Wallis & Futuna", "WF"),
    ("Samoa (western)", "WS"),
    ("Yemen", "YE"),
    ("Mayotte", "YT"),
    ("South Africa", "ZA"),
    ("Zambia", "ZM"),
    ("Zimbabwe", "ZW"),
];

const ISO_COUNTRY_ALIASES: &[(&str, &str)] = &[
    ("United States of America", "US"),
    ("United Kingdom", "GB"),
    ("UK", "GB"),
    ("USA", "US"),
    ("Czechia", "CZ"),
    ("Türkiye", "TR"),
    ("South Korea", "KR"),
    ("North Korea", "KP"),
];

pub(super) trait UiReferralService {
    fn create(
        &mut self,
        codename: &str,
        auth_mode: ReferralAuthMode,
        ui: &mut Ui,
    ) -> Result<ReferralCreateResult>;
    fn status(&mut self, auth_mode: ReferralAuthMode, ui: &mut Ui) -> Result<ReferralStatusResult>;
    fn payout(
        &mut self,
        country: Option<&str>,
        auth_mode: ReferralAuthMode,
        ui: &mut Ui,
    ) -> Result<ReferralPayoutResponse>;
}

struct ApplicationServiceAdapter<'a> {
    service: &'a mut dyn UiReferralService,
    ui: &'a mut Ui,
}

impl ApplicationReferralService for ApplicationServiceAdapter<'_> {
    fn create(
        &mut self,
        codename: &str,
        auth_mode: ReferralAuthMode,
    ) -> Result<ReferralCreateResult> {
        self.service.create(codename, auth_mode, self.ui)
    }

    fn status(&mut self, auth_mode: ReferralAuthMode) -> Result<ReferralStatusResult> {
        self.service.status(auth_mode, self.ui)
    }

    fn payout(
        &mut self,
        country: Option<&str>,
        auth_mode: ReferralAuthMode,
    ) -> Result<ReferralPayoutResponse> {
        self.service.payout(country, auth_mode, self.ui)
    }
}

struct CliReferralClock;

impl ReferralClock for CliReferralClock {
    fn unix_time(&self) -> Result<i64> {
        super::commercial_lifecycle::unix_time()
    }
}

impl UiReferralService for CommercialLifecycleService {
    fn create(
        &mut self,
        codename: &str,
        auth_mode: ReferralAuthMode,
        ui: &mut Ui,
    ) -> Result<ReferralCreateResult> {
        let access_token = self.referral_access_token(auth_mode, ui)?;
        self.api.referral_create(&access_token, codename)
    }

    fn status(&mut self, auth_mode: ReferralAuthMode, ui: &mut Ui) -> Result<ReferralStatusResult> {
        let access_token = self.referral_access_token(auth_mode, ui)?;
        self.api.referral_status(&access_token)
    }

    fn payout(
        &mut self,
        country: Option<&str>,
        auth_mode: ReferralAuthMode,
        ui: &mut Ui,
    ) -> Result<ReferralPayoutResponse> {
        let access_token = self.referral_access_token(auth_mode, ui)?;
        self.api
            .referral_payout(&access_token, country)
            .map(ReferralPayoutResponse::Unvalidated)
    }
}

pub(crate) fn run(args: ReferralArgs, data_root: PathBuf, ui: &mut Ui) -> Result<()> {
    super::commercial_config::reject_test_control_outside_test_host()?;
    #[cfg(ctx_pro_test_helper)]
    super::test_control::prepare()?;
    args.validate_invocation()?;
    let json_output = args.json_output();
    let stdin = io::stdin();
    let interactive = !json_output
        && stdin.is_terminal()
        && ui.stdout_context().is_terminal()
        && ui.stderr_context().is_terminal();
    let mut input = stdin.lock();
    #[cfg(ctx_pro_test_helper)]
    let test_control_active = super::test_control::is_active()?;
    #[cfg(ctx_pro_test_helper)]
    let _lifecycle_lock = if test_control_active {
        None
    } else {
        Some(super::client::admit_referral(
            &data_root,
            json_output,
            !json_output,
        )?)
    };
    #[cfg(not(ctx_pro_test_helper))]
    let _lifecycle_lock = super::client::admit_referral(&data_root, json_output, !json_output)?;
    #[cfg(ctx_pro_test_helper)]
    let result = if let Some(mut service) = super::test_control::referral_service()? {
        run_with_service_with_input(
            args,
            &mut service,
            &mut io::stdout().lock(),
            &mut input,
            interactive,
            ui,
            &open_browser,
        )
    } else {
        let mut service = CommercialLifecycleService::production(&data_root)?;
        run_with_service_with_input(
            args,
            &mut service,
            &mut io::stdout().lock(),
            &mut input,
            interactive,
            ui,
            &open_browser,
        )
    };
    #[cfg(not(ctx_pro_test_helper))]
    let result = {
        let mut service = CommercialLifecycleService::production(&data_root)?;
        run_with_service_with_input(
            args,
            &mut service,
            &mut io::stdout().lock(),
            &mut input,
            interactive,
            ui,
            &open_browser,
        )
    };
    #[cfg(ctx_pro_test_helper)]
    let result = super::test_control::finish(result);
    result
}

pub(crate) fn show_cta_once(data_root: &Path, eligible: bool, output: &mut Ui) -> bool {
    let Ok(channel) = selected_channel() else {
        return false;
    };
    show_cta_once_for_channel(data_root, eligible, channel, &mut UiCtaDestination(output))
}

fn show_cta_once_for_channel<D>(
    data_root: &Path,
    eligible: bool,
    channel: ReleaseChannel,
    output: &mut D,
) -> bool
where
    D: CtaDestination + ?Sized,
{
    if !eligible || !claim_cta_marker(data_root, channel) {
        return false;
    }
    if output
        .write_cta(&render_cta_human(output.cta_context()))
        .is_ok()
    {
        true
    } else {
        rollback_cta_marker(data_root, channel);
        false
    }
}

pub(crate) trait CtaDestination {
    fn cta_context(&self) -> &RenderContext;
    fn write_cta(&mut self, document: &Document) -> io::Result<()>;
}

struct UiCtaDestination<'a>(&'a mut Ui);

impl CtaDestination for UiCtaDestination<'_> {
    fn cta_context(&self) -> &RenderContext {
        self.0.stderr_context()
    }

    fn write_cta(&mut self, document: &Document) -> io::Result<()> {
        self.0.write_stderr(document)
    }
}

impl<W> CtaDestination for W
where
    W: io::Write,
{
    fn cta_context(&self) -> &RenderContext {
        static CONTEXT: std::sync::OnceLock<RenderContext> = std::sync::OnceLock::new();
        CONTEXT.get_or_init(|| {
            RenderContext::for_test(crate::ui::TestContext::pipe(StreamKind::Stderr))
        })
    }

    fn write_cta(&mut self, document: &Document) -> io::Result<()> {
        self.write_all(document.render_plain().as_bytes())
    }
}

fn cta_marker(data_root: &Path, channel: ReleaseChannel) -> PathBuf {
    data_root.join(format!(
        "{REFERRAL_CTA_MARKER_PREFIX}.{}.shown",
        channel.wire_name()
    ))
}

fn claim_cta_marker(data_root: &Path, channel: ReleaseChannel) -> bool {
    use ctx_history_core::platform_security::{
        restrict_private_file, verify_private_directory, verify_private_file,
    };

    let marker = cta_marker(data_root, channel);
    if verify_private_directory(data_root).is_err() {
        return false;
    }
    let temporary = data_root.join(format!(
        "{REFERRAL_CTA_MARKER_PREFIX}.{}.{}.tmp",
        channel.wire_name(),
        Uuid::new_v4().simple()
    ));
    let result = (|| -> std::io::Result<bool> {
        crate::identity::create_private_file(&temporary, b"shown\n")?;
        restrict_private_file(&temporary).map_err(std::io::Error::other)?;
        verify_private_file(&temporary).map_err(std::io::Error::other)?;
        fs::File::open(&temporary)?.sync_all()?;
        match fs::hard_link(&temporary, &marker) {
            Ok(()) => {
                #[cfg(unix)]
                fs::File::open(data_root)?.sync_all()?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error),
        }
    })();
    let _ = fs::remove_file(&temporary);
    result.unwrap_or(false)
}

fn rollback_cta_marker(data_root: &Path, channel: ReleaseChannel) {
    let marker = cta_marker(data_root, channel);
    if fs::remove_file(marker).is_ok() {
        #[cfg(unix)]
        let _ = fs::File::open(data_root).and_then(|directory| directory.sync_all());
    }
}

#[cfg(test)]
fn run_with_service(
    args: ReferralArgs,
    service: &mut dyn UiReferralService,
    output: &mut impl io::Write,
    ui: &mut Ui,
    opener: &impl Fn(&str) -> Result<()>,
) -> Result<()> {
    let mut input = io::Cursor::new(Vec::<u8>::new());
    run_with_service_with_input(args, service, output, &mut input, true, ui, opener)
}

fn run_with_service_with_input(
    args: ReferralArgs,
    service: &mut dyn UiReferralService,
    output: &mut impl io::Write,
    input: &mut impl io::BufRead,
    interactive: bool,
    ui: &mut Ui,
    opener: &impl Fn(&str) -> Result<()>,
) -> Result<()> {
    let json_output = args.json_output();
    let retry_command = args.retry_command();
    let result = (|| {
        args.validate_invocation()?;
        match args.command {
            ReferralCommand::Create(args) => {
                let outcome = {
                    let mut service = ApplicationServiceAdapter { service, ui };
                    execute_referral(
                        &mut service,
                        &CliReferralClock,
                        ApplicationReferralRequest {
                            command: ApplicationReferralCommand::Create {
                                codename: args.codename.as_str(),
                            },
                            machine_output: json_output,
                            interactive,
                        },
                    )?
                };
                let ReferralOutcome::Created(result) = outcome else {
                    unreachable!("create request returned a different referral outcome")
                };
                if args.format.is_json() {
                    write_json(output, &create_output(&result))
                } else {
                    let document = render_create_human(ui.stdout_context(), &result);
                    ui.write_stdout(&document)?;
                    Ok(())
                }
            }
            ReferralCommand::Status(args) => {
                let outcome = {
                    let mut service = ApplicationServiceAdapter { service, ui };
                    execute_referral(
                        &mut service,
                        &CliReferralClock,
                        ApplicationReferralRequest {
                            command: ApplicationReferralCommand::Status,
                            machine_output: json_output,
                            interactive,
                        },
                    )?
                };
                let ReferralOutcome::Status(result) = outcome else {
                    unreachable!("status request returned a different referral outcome")
                };
                if args.format.is_json() {
                    write_json(output, &status_output(&result))
                } else {
                    let document = render_status_human(ui.stdout_context(), &result);
                    ui.write_stdout(&document)?;
                    Ok(())
                }
            }
            ReferralCommand::Payout(args) => {
                let requested_country = args.country.as_ref().map(CountryCode::as_str);
                let outcome = {
                    let mut service = ApplicationServiceAdapter { service, ui };
                    execute_referral(
                        &mut service,
                        &CliReferralClock,
                        ApplicationReferralRequest {
                            command: ApplicationReferralCommand::Payout {
                                country: requested_country,
                                no_open: args.no_open,
                            },
                            machine_output: json_output,
                            interactive,
                        },
                    )?
                };
                let result = match outcome {
                    ReferralOutcome::Payout(result) => result,
                    ReferralOutcome::CountryRequired(retry) => {
                        let country = prompt_payout_country(input, ui)?;
                        let mut service = ApplicationServiceAdapter { service, ui };
                        retry_referral_payout(
                            &mut service,
                            &CliReferralClock,
                            retry,
                            country.as_str(),
                        )?
                    }
                    ReferralOutcome::Created(_) | ReferralOutcome::Status(_) => {
                        unreachable!("payout request returned a different referral outcome")
                    }
                };
                if args.format.is_json() {
                    return write_json(output, &payout_output(&result, false));
                }
                let mut browser_opened = false;
                if interactive && !args.no_open {
                    browser_opened = opener(&result.url).is_ok();
                }
                let document = render_payout_human(ui.stdout_context(), &result, browser_opened);
                ui.write_stdout(&document)?;
                if interactive && !args.no_open {
                    let notice = render_payout_browser_notice(ui.stderr_context(), browser_opened);
                    ui.write_stderr(&notice)?;
                }
                Ok(())
            }
        }
    })();
    super::human_result(result, !json_output, &retry_command, ui)
}

const REFERRAL_PAYOUT_COUNTRY_REQUIRED: &str = "referral_payout_country_required";

fn prompt_payout_country(input: &mut impl io::BufRead, ui: &mut Ui) -> Result<CountryCode> {
    ui.write_stderr(&render_payout_country_prompt(ui.stderr_context()))?;
    ui.flush()?;
    loop {
        let mut answer = String::new();
        if input.read_line(&mut answer)? == 0 {
            bail!("{REFERRAL_PAYOUT_COUNTRY_REQUIRED}: payout country selection was cancelled; supply --country <CC>");
        }
        match parse_country_input(&answer) {
            Ok(country) => return Ok(country),
            Err(_) => {
                ui.write_stderr(&render_payout_country_invalid(ui.stderr_context()))?;
                ui.flush()?;
            }
        }
    }
}

fn write_json(output: &mut impl io::Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *output, value)?;
    writeln!(output)?;
    Ok(())
}

fn share_command(codename: &str) -> String {
    format!("ctx pro --referral {codename}")
}

#[derive(Serialize)]
struct ReferralCreateOutput<'a> {
    schema_version: u16,
    payload_type: &'static str,
    codename: &'a str,
    share_command: String,
    disposition: &'a str,
}

fn create_output(result: &ReferralCreateResult) -> ReferralCreateOutput<'_> {
    ReferralCreateOutput {
        schema_version: 1,
        payload_type: "referral_create",
        codename: &result.codename,
        share_command: share_command(&result.codename),
        disposition: &result.disposition,
    }
}

#[derive(Serialize)]
struct ReferralStatusOutput<'a> {
    schema_version: u16,
    payload_type: &'static str,
    codename: &'a str,
    share_command: String,
    attributed: u64,
    subscribed: u64,
    earned_cents: u64,
    pending_cents: u64,
    manual_review_cents: u64,
    payable_cents: u64,
    processing_cents: u64,
    paid_cents: u64,
    debt_cents: u64,
    currency: &'a str,
    payout_state: &'a str,
}

fn status_output(result: &ReferralStatusResult) -> ReferralStatusOutput<'_> {
    ReferralStatusOutput {
        schema_version: 1,
        payload_type: "referral_status",
        codename: &result.codename,
        share_command: share_command(&result.codename),
        attributed: result.attributed,
        subscribed: result.subscribed,
        earned_cents: result.earned_cents,
        pending_cents: result.pending_cents,
        manual_review_cents: result.manual_review_cents,
        payable_cents: result.payable_cents,
        processing_cents: result.processing_cents,
        paid_cents: result.paid_cents,
        debt_cents: result.debt_cents,
        currency: &result.currency,
        payout_state: &result.payout_state,
    }
}

#[derive(Serialize)]
struct ReferralPayoutOutput<'a> {
    schema_version: u16,
    payload_type: &'static str,
    payout_state: &'a str,
    onboarding_url: &'a str,
    expires_at_unix: i64,
    browser_opened: bool,
}

fn payout_output(result: &ReferralPayoutResult, browser_opened: bool) -> ReferralPayoutOutput<'_> {
    ReferralPayoutOutput {
        schema_version: 1,
        payload_type: "referral_payout",
        payout_state: &result.payout_state,
        onboarding_url: &result.url,
        expires_at_unix: result.expires_at_unix,
        browser_opened,
    }
}

#[cfg(test)]
mod cta_tests;

#[cfg(test)]
#[path = "referral/ui_tests.rs"]
mod ui_tests;

#[cfg(test)]
mod tests {
    use clap::{CommandFactory as _, Parser as _};

    use super::*;
    use crate::cli::Cli;

    fn create_result() -> ReferralCreateResult {
        ReferralCreateResult {
            codename: "agent-smith".to_owned(),
            disposition: "created".to_owned(),
        }
    }

    fn status_result() -> ReferralStatusResult {
        ReferralStatusResult {
            codename: "agent-smith".to_owned(),
            attributed: 4,
            subscribed: 3,
            earned_cents: 7_000,
            pending_cents: 2_000,
            manual_review_cents: 2_000,
            payable_cents: 2_000,
            processing_cents: 1_000,
            paid_cents: 2_000,
            debt_cents: 2_000,
            currency: "usd".to_owned(),
            payout_state: "paused".to_owned(),
        }
    }

    #[test]
    fn parser_exposes_one_top_level_namespace_and_the_bare_pro_referral_form() {
        for args in [
            &["referral", "create", "agent-smith"][..],
            &["referral", "status"][..],
            &["referral", "payout", "--no-open"][..],
            &["pro", "--referral", "agent-smith"][..],
        ] {
            Cli::try_parse_from(std::iter::once("ctx").chain(args.iter().copied())).unwrap();
        }
        for args in [
            &["status", "--referral", "agent-smith"][..],
            &["search", "agents", "--referral", "agent-smith"][..],
            &["pro", "setup", "--referral", "agent-smith"][..],
            &["pro", "manage", "--referral", "agent-smith"][..],
            &["pro", "uninstall", "--referral", "agent-smith"][..],
        ] {
            assert!(
                Cli::try_parse_from(std::iter::once("ctx").chain(args.iter().copied())).is_err(),
                "{args:?}"
            );
        }
    }

    #[test]
    fn invalid_country_names_a_valid_copyable_example() {
        assert_eq!(
            parse_country_code("us").unwrap_err(),
            "country must be a two-letter uppercase ISO country code, for example US"
        );
        assert_eq!(parse_country_input("United States").unwrap().as_str(), "US");
        assert_eq!(parse_country_input("ca").unwrap().as_str(), "CA");
        assert!(parse_country_input("Atlantis").is_err());
    }

    #[test]
    fn payout_help_is_individual_only_and_has_no_entity_type_option() {
        let mut command = Cli::command();
        let payout = command
            .find_subcommand_mut("referral")
            .expect("referral subcommand")
            .find_subcommand_mut("payout")
            .expect("referral payout subcommand");
        let help = payout.render_long_help().to_string();
        assert!(help.contains("individual referral payouts"));
        assert!(help.contains("country"));
        assert!(!help.contains("--entity-type"));
        assert!(!help.contains("company"));
        assert!(
            Cli::try_parse_from(["ctx", "referral", "payout", "--entity-type", "company"]).is_err()
        );
    }

    #[test]
    fn referral_help_states_the_recurring_commission_and_direct_cap() {
        let mut command = Cli::command();
        let referral = command
            .find_subcommand_mut("referral")
            .expect("referral subcommand");
        let help = referral.render_long_help().to_string();
        let normalized = help.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(help.contains("Refer a developer. Earn $10/month toward your agent bill."));
        assert!(help.contains("Up to $120 per friend."));
        assert!(normalized.contains("first 12 distinct qualifying paid monthly invoices"));
        assert!(normalized.contains("first two commissions remain pending until invoice 2 settles"));
        assert!(
            normalized.contains("invoices 3-12 each have their own 14-day hold and reconciliation")
        );
        assert!(!help.contains("Get $20"));
        assert!(!help.contains("one-time"));
    }

    #[test]
    fn referral_create_help_describes_the_public_share_command_codename() {
        let mut command = Cli::command();
        let create = command
            .find_subcommand_mut("referral")
            .expect("referral subcommand")
            .find_subcommand_mut("create")
            .expect("referral create subcommand");
        let help = create.render_long_help().to_string();
        assert!(help.contains("Public codename used in the share command"));
        assert!(!help.contains("referral link"));
    }

    #[test]
    fn codename_and_payout_identity_inputs_are_strictly_bounded_ascii() {
        for valid in ["abc", "agent-smith", "a1b2", &"a".repeat(32)] {
            assert!(parse_referral_codename(valid).is_ok(), "{valid:?}");
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
            assert!(parse_referral_codename(invalid).is_err(), "{invalid:?}");
        }
        assert!(parse_country_code("US").is_ok());
        for invalid in ["us", "USA", "U1", "ZZ", ""] {
            assert!(parse_country_code(invalid).is_err());
        }
    }

    #[test]
    fn success_json_preserves_the_exact_machine_contract() {
        let create = create_result();
        let mut create_bytes = Vec::new();
        write_json(&mut create_bytes, &create_output(&create)).unwrap();
        assert_eq!(
            create_bytes,
            br#"{"schema_version":1,"payload_type":"referral_create","codename":"agent-smith","share_command":"ctx pro --referral agent-smith","disposition":"created"}
"#
        );
        assert_eq!(
            serde_json::to_value(create_output(&create)).unwrap(),
            serde_json::json!({
                "schema_version": 1,
                "payload_type": "referral_create",
                "codename": "agent-smith",
                "share_command": "ctx pro --referral agent-smith",
                "disposition": "created",
            })
        );

        let status = status_result();
        let mut status_bytes = Vec::new();
        write_json(&mut status_bytes, &status_output(&status)).unwrap();
        assert_eq!(
            status_bytes,
            br#"{"schema_version":1,"payload_type":"referral_status","codename":"agent-smith","share_command":"ctx pro --referral agent-smith","attributed":4,"subscribed":3,"earned_cents":7000,"pending_cents":2000,"manual_review_cents":2000,"payable_cents":2000,"processing_cents":1000,"paid_cents":2000,"debt_cents":2000,"currency":"usd","payout_state":"paused"}
"#
        );
        assert_eq!(
            serde_json::to_value(status_output(&status)).unwrap(),
            serde_json::json!({
                "schema_version": 1,
                "payload_type": "referral_status",
                "codename": "agent-smith",
                "share_command": "ctx pro --referral agent-smith",
                "attributed": 4,
                "subscribed": 3,
                "earned_cents": 7000,
                "pending_cents": 2000,
                "manual_review_cents": 2000,
                "payable_cents": 2000,
                "processing_cents": 1000,
                "paid_cents": 2000,
                "debt_cents": 2000,
                "currency": "usd",
                "payout_state": "paused",
            })
        );

        let payout = ReferralPayoutResult {
            kind: "payout_onboarding_created".to_owned(),
            payout_state: "onboarding_pending".to_owned(),
            url: "https://connect.stripe.com/setup/s/test".to_owned(),
            expires_at_unix: 1_800_000_000,
        };
        let mut payout_bytes = Vec::new();
        write_json(&mut payout_bytes, &payout_output(&payout, false)).unwrap();
        assert_eq!(
            payout_bytes,
            br#"{"schema_version":1,"payload_type":"referral_payout","payout_state":"onboarding_pending","onboarding_url":"https://connect.stripe.com/setup/s/test","expires_at_unix":1800000000,"browser_opened":false}
"#
        );
    }

    #[test]
    fn referral_commands_emit_neither_analytics_nor_local_usage() {
        for args in [
            &["referral", "create", "agent-smith"][..],
            &["referral", "status"][..],
            &["referral", "payout", "--format=json"][..],
        ] {
            let cli =
                Cli::try_parse_from(std::iter::once("ctx").chain(args.iter().copied())).unwrap();
            assert!(crate::analytics::ClientOperationDraft::from_descriptor(
                crate::dispatch::command_operation_descriptor(&cli.command),
                false
            )
            .is_none());
            assert!(crate::local_usage::CliUsage::from_descriptor(
                &crate::dispatch::command_operation_descriptor(&cli.command)
            )
            .completed(true, std::time::Duration::ZERO)
            .is_none());
        }
    }

    #[test]
    fn redacted_codename_debug_never_exposes_the_value() {
        let value = parse_referral_codename("secret-agent").unwrap();
        let debug = format!("{value:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret-agent"));
    }

    #[test]
    fn interactive_referral_prepares_the_private_pro_lifecycle_root() {
        let root = tempfile::tempdir().unwrap();
        let _admission = super::super::client::admit_referral(root.path(), false, true).unwrap();

        ctx_history_core::platform_security::verify_private_directory(
            &ctx_pro_host_protocol::ProFilesystemLayout::new(root.path()).pro_root(),
        )
        .unwrap();
    }
}
