#[path = "../config.rs"]
mod config;
#[path = "../snapshot.rs"]
mod snapshot;

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use config::AppConfig;
use snapshot::EngineSnapshot;

#[derive(Parser, Debug)]
#[command(name = "fywaf-build")]
#[command(about = "Build an engine snapshot from fywaf YAML config")]
struct Args {
    #[arg(long, short, default_value = "examples/config.yml")]
    config: PathBuf,
    #[arg(long, short, default_value = "examples/rules.snapshot.bin")]
    out: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if !args.out.to_string_lossy().ends_with(".bin") {
        anyhow::bail!("--out must be a .bin snapshot path");
    }

    let app_config = AppConfig::from_path(&args.config)
        .with_context(|| format!("failed to load config file {}", args.config.display()))?;
    app_config.validate()?;

    let snapshot = EngineSnapshot::from_app_config(&app_config);
    snapshot.write_to_path(&args.out)?;
    println!("snapshot written to {}", args.out.display());
    Ok(())
}
