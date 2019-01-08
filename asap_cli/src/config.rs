use asap::claims::{Aud, ExtraClaims};
use directories::ProjectDirs;
use pem;
use serde_json;
use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use errors::Result;
use opt::Opt;

pub const CONFIG_BASENAME: &'static str = ".asap-config";

#[derive(Debug, Fail)]
pub enum ConfigError {
    #[fail(display = "failed to parse config from {}: {}", _0, _1)]
    CustomConfig(String, String),

    #[fail(display = "failed to find configuration files: {}", _0)]
    NotFound(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub audience: Aud,
    pub issuer: String,
    pub key_id: String,
    pub private_key: Vec<u8>,
    pub extra_claims: Option<ExtraClaims>,
}

impl Config {
    /// Loads config from the given file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Config> {
        Ok(serde_json::from_reader(File::open(path)?)?)
    }

    /// Creates a config from the options passed to the binary.
    pub fn from_opt(opt: &Opt) -> Result<Config> {
        // Load config either from pass or the default locations.
        let mut config = if let Some(ref path) = opt.config_path.as_ref() {
            Config::from_file(path).map_err(|err| {
                ConfigError::CustomConfig(path.display().to_string(), err.to_string())
            })?
        } else {
            Config::from_dirs().map_err(|e| ConfigError::NotFound(e.to_string()))?
        };

        // Custom claims supplied on the command line.
        if let Some(ref audience) = opt.audience {
            let aud: Aud =
                serde_json::from_str(&audience).expect("failed to parse custom audience");
            config.audience = aud;
        }
        if let Some(issuer) = opt.issuer.as_ref() {
            config.issuer = issuer.to_string();
        }
        if let Some(key_id) = opt.key_id.as_ref() {
            config.key_id = key_id.to_string();
        }
        if let Some(ref path) = opt.private_key {
            config.private_key = pem_from_file(path);
        }
        if let Some(ref json) = opt.extra_claims_json {
            let extra_claims =
                serde_json::from_str(json).expect("failed to pass extra_claims json");
            config.extra_claims = Some(extra_claims);
        }

        Ok(config)
    }

    /// Attempts to load the default config.
    ///
    /// First, the `pwd` directory is searched for `.asap-config`, and if not
    /// found, then the user's config directory is searched.
    fn from_dirs() -> Result<Config> {
        Config::from_file(env::current_dir()?.join(CONFIG_BASENAME))
            .or_else(|_| Config::from_file(default_config_path()?))
    }
}

pub fn default_config_path() -> Result<PathBuf> {
    if let Some(dirs) = ProjectDirs::from("com", "atlassian", "asap") {
        Ok(dirs.config_dir().join(CONFIG_BASENAME))
    } else {
        Err(format_err!("failed to find config directory"))
    }
}

/// Loads a PEM file and convert it to DER.
pub fn pem_from_file<P: AsRef<Path>>(path: P) -> Vec<u8> {
    let file = fs::read(path).expect("failed to read pem file");
    let dem_key = pem::parse(file).expect("failed to parse pem file");
    dem_key.contents
}
