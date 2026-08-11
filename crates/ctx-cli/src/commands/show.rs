use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::analytics::ShowTelemetry;
use crate::local_usage::CliUsage;
use crate::output::OutputFormat;
use crate::provider_args::ProviderArg;
use crate::transcript::TranscriptMode;
use crate::ui::Ui;
use crate::{parse_event_window_limit, parse_provider_arg, ShowArgs};

#[derive(Debug, Args)]
pub(crate) struct ShowSessionArgs {
    #[arg(help = "ctx session id or unambiguous id prefix")]
    pub(crate) id: Option<String>,
    #[arg(long, value_parser = parse_provider_arg, hide_possible_values = true)]
    pub(crate) provider: Option<ProviderArg>,
    #[arg(long = "provider-session")]
    pub(crate) provider_session: Option<String>,
    #[arg(long, value_enum, default_value_t = TranscriptMode::Lite)]
    pub(crate) mode: TranscriptMode,
    #[arg(long, help = "Return at most this many selected transcript events")]
    pub(crate) max_events: Option<usize>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) format: OutputFormat,
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct ShowEventArgs {
    #[arg(help = "ctx event id or unambiguous id prefix")]
    pub(crate) id: String,
    #[arg(
        long,
        default_value_t = 0,
        value_parser = parse_event_window_limit,
        help = "Number of preceding events to include (0..50)"
    )]
    pub(crate) before: usize,
    #[arg(
        long,
        default_value_t = 0,
        value_parser = parse_event_window_limit,
        help = "Number of following events to include (0..50)"
    )]
    pub(crate) after: usize,
    #[arg(
        long,
        value_parser = parse_event_window_limit,
        help = "Use this many events on both sides of the selected event (0..50)"
    )]
    pub(crate) window: Option<usize>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) format: OutputFormat,
}

pub(crate) fn run_show(
    args: ShowArgs,
    data_root: PathBuf,
    telemetry: &mut ShowTelemetry,
    local_usage: &mut CliUsage,
    ui: &mut Ui,
) -> Result<()> {
    let target = match args.target {
        crate::ShowTarget::Session(args) => {
            ctx_history_cli::ShowTarget::Session(ctx_history_cli::ShowSessionArgs {
                id: args.id,
                provider: args.provider.map(history_provider),
                provider_session: args.provider_session,
                mode: match args.mode {
                    TranscriptMode::Full => ctx_history_cli::TranscriptMode::Full,
                    TranscriptMode::Lite => ctx_history_cli::TranscriptMode::Lite,
                    TranscriptMode::Log => ctx_history_cli::TranscriptMode::Log,
                },
                max_events: args.max_events,
                format: history_output_format(args.format),
                out: args.out,
            })
        }
        crate::ShowTarget::Event(args) => {
            ctx_history_cli::ShowTarget::Event(ctx_history_cli::ShowEventArgs {
                id: args.id,
                before: args.before,
                after: args.after,
                window: args.window,
                format: history_output_format(args.format),
            })
        }
    };
    ctx_history_cli::run_show(
        ctx_history_cli::ShowArgs { target },
        data_root,
        telemetry,
        local_usage,
        ui,
    )
}

fn history_provider(provider: ProviderArg) -> ctx_history_cli::ProviderArg {
    ctx_history_cli::ProviderArg(ctx_history_cli::HistoryProvider::from(
        provider.capture_provider(),
    ))
}

fn history_output_format(format: OutputFormat) -> ctx_history_cli::OutputFormat {
    match format {
        OutputFormat::Text => ctx_history_cli::OutputFormat::Text,
        OutputFormat::Json => ctx_history_cli::OutputFormat::Json,
        OutputFormat::Jsonl => ctx_history_cli::OutputFormat::Jsonl,
        OutputFormat::Markdown => ctx_history_cli::OutputFormat::Markdown,
    }
}
