use std::path::PathBuf;

use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Parser)]
#[command(name = "exfilguard", about = "ExfilGuard egress policy proxy")]
pub struct Cli {
    /// Path to the runtime configuration file (defaults to ./exfilguard.toml if present).
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum Command {
    /// Generate a password hash for a client.
    PasswordHash {
        #[arg(long, value_enum, default_value = "argon2id")]
        algorithm: crate::authentication::PasswordAlgorithm,
        /// Read one password line from standard input.
        #[arg(long)]
        stdin: bool,
    },
}

impl Command {
    pub fn run(&self) -> anyhow::Result<()> {
        use anyhow::{Context, ensure};
        use std::io::{Read, Write};
        use zeroize::Zeroizing;
        match self {
            Self::PasswordHash { algorithm, stdin } => {
                let password = if *stdin {
                    let mut bytes = Zeroizing::new(Vec::new());
                    std::io::stdin().lock().take(1027).read_to_end(&mut bytes)?;
                    ensure!(bytes.len() <= 1026, "password input is too long");
                    if bytes.last() == Some(&b'\n') {
                        bytes.pop();
                        if bytes.last() == Some(&b'\r') {
                            bytes.pop();
                        }
                    }
                    let text = std::str::from_utf8(&bytes).context("password must be UTF-8")?;
                    ensure!(!text.contains(['\r', '\n']), "expected one password line");
                    Zeroizing::new(text.to_owned())
                } else {
                    let password = Zeroizing::new(rpassword::prompt_password("Password: ")?);
                    let confirmation =
                        Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
                    ensure!(*password == *confirmation, "passwords do not match");
                    password
                };
                let hash = crate::authentication::generate_hash(&password, *algorithm)?;
                writeln!(std::io::stdout().lock(), "{hash}")?;
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Text,
}
