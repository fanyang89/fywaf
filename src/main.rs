mod config;
mod engine;
mod proxy;
mod wasm;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Args as ClapArgs, Parser, Subcommand};
use config::AppConfig;
use engine::WafEngine;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "fywaf")]
#[command(about = "A minimal open-source HTTP reverse-proxy WAF with WASM rules")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Run(RunArgs),
}

#[derive(ClapArgs, Debug)]
struct RunArgs {
    #[arg(long, short, default_value = "examples/config.yml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(args) => run_waf(args).await,
    }
}

async fn run_waf(args: RunArgs) -> anyhow::Result<()> {
    init_logging();

    let app_config = AppConfig::from_path(&args.config)
        .with_context(|| format!("failed to load config file {}", args.config.display()))?;
    app_config.validate()?;

    let base_path = args.config.parent().unwrap_or(std::path::Path::new("."));
    let engine = Arc::new(WafEngine::from_config(&app_config, base_path)?);

    info!(
        sites = app_config.sites.len(),
        profiles = app_config.profiles.len(),
        "starting fywaf with wasm engine",
    );

    proxy::run(app_config, engine).await
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .compact()
        .init();
}
