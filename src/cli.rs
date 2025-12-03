use std::path::PathBuf;

use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Parser)]
#[command(name = "exfilguard", about = "ExfilGuard egress policy proxy")]
pub struct Cli {
    /// Path to the runtime configuration file (defaults to ./exfilguard.toml if present).
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Text,
}
