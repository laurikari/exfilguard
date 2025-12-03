use anyhow::Result;
use clap::Parser;

use exfilguard::{cli::Cli, logging, run, settings::Settings};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let settings = Settings::load(&cli)?;
    logging::init_logger(settings.log)?;
    run(settings).await
}
