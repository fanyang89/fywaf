mod config;
mod engine;
mod proxy;
mod snapshot;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use config::AppConfig;
use engine::WafEngine;
use snapshot::EngineSnapshot;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "fywaf")]
#[command(about = "A minimal open-source HTTP reverse-proxy WAF")]
struct Args {
    #[arg(long, short, default_value = "examples/config.yml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();

    let args = Args::parse();
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

fn init_logging() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .compact()
        .init();
}
