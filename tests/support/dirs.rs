use std::path::{Path, PathBuf};

use anyhow::Result;
use tempfile::TempDir;

pub struct TestDirs {
    _temp: TempDir,
    pub ca_dir: PathBuf,
    pub config_dir: PathBuf,
    pub clients_path: PathBuf,
    pub policies_path: PathBuf,
    pub cache_dir: Option<PathBuf>,
}

impl TestDirs {
    pub fn new() -> Result<Self> {
        let temp = TempDir::new()?;
        let workspace = temp.path();
        let ca_dir = workspace.join("ca");
        let config_dir = workspace.join("config");
        std::fs::create_dir_all(&ca_dir)?;
        std::fs::create_dir_all(&config_dir)?;

        let clients_path = config_dir.join("clients.toml");
        let policies_path = config_dir.join("policies.toml");

        Ok(Self {
            _temp: temp,
            ca_dir,
            config_dir,
            clients_path,
            policies_path,
            cache_dir: None,
        })
    }

    pub fn enable_cache_dir(&mut self) -> Result<&Path> {
        if self.cache_dir.is_none() {
            let cache_dir = self
                .config_dir
                .parent()
                .unwrap_or(Path::new("."))
                .join("http_cache");
            std::fs::create_dir_all(&cache_dir)?;
            self.cache_dir = Some(cache_dir);
        }
        Ok(self.cache_dir.as_deref().expect("cache_dir set"))
    }
}

pub fn write_clients_and_policies(dirs: &TestDirs, clients: &str, policies: &str) -> Result<()> {
    std::fs::write(&dirs.clients_path, clients)?;
    std::fs::write(&dirs.policies_path, policies)?;
    Ok(())
}
