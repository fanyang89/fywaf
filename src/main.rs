mod config;
mod engine;
mod import_crs;
mod proxy;
mod secrule_parser;
mod snapshot;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Args as ClapArgs, Parser, Subcommand};
use config::AppConfig;
use engine::WafEngine;
use import_crs::ImportCrsOptions;
use snapshot::EngineSnapshot;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "fywaf")]
#[command(about = "A minimal open-source HTTP reverse-proxy WAF")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Run(RunArgs),
    Convert(ConvertArgs),
}

#[derive(ClapArgs, Debug)]
struct RunArgs {
    #[arg(long, short, default_value = "examples/config.yml")]
    config: PathBuf,
}

#[derive(ClapArgs, Debug)]
struct ConvertArgs {
    #[arg(long, short)]
    rules_dir: PathBuf,
    #[arg(long, short, default_value = "examples/crs.import.yml")]
    out: PathBuf,
    #[arg(long, default_value = "crs-imported")]
    profile_id: String,
    #[arg(long, default_value = "allow")]
    default_action: String,
    #[arg(long, default_value = "examples/crs.import.report.txt")]
    report_out: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(run_args) => run_waf(run_args).await,
        Commands::Convert(convert_args) => run_convert(convert_args),
    }
}

async fn run_waf(args: RunArgs) -> anyhow::Result<()> {
    init_logging();

    let app_config = AppConfig::from_path(&args.config)
        .with_context(|| format!("failed to load config file {}", args.config.display()))?;
    app_config.validate()?;

    let engine = Arc::new(WafEngine::from_config(&app_config)?);
    let snapshot_path = app_config.engine.snapshot_path.clone();
    info!(
        sites = app_config.sites.len(),
        profiles = app_config.profiles.len(),
        snapshot_version = EngineSnapshot::version(),
        snapshot_path = snapshot_path.as_deref().unwrap_or("-"),
        "starting fywaf",
    );

    proxy::run(app_config, engine).await
}

fn run_convert(args: ConvertArgs) -> anyhow::Result<()> {
    import_crs::run(ImportCrsOptions {
        rules_dir: args.rules_dir,
        out: args.out,
        profile_id: args.profile_id,
        default_action: args.default_action,
        report_out: args.report_out,
    })
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .compact()
        .init();
}
