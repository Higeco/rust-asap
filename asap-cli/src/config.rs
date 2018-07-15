use asap::claims::Aud;
use pem;
use serde_json::{self, Value};
use std::env;
use std::fs::{self, File};
use std::path::Path;

use errors::Result;
use opt::Opt;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub audience: Aud,
    pub issuer: String,
    pub key_id: String,
    pub private_key: Vec<u8>,
    pub extra_claims: Option<Value>,
}

impl Config {
    /// Loads config from the given file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Config> {
        Ok(serde_json::from_reader(File::open(path)?)?)
    }

    /// Creates a config from the options passed to the binary.
    pub fn from_opt(opt: &Opt) -> Config {
        // Load config either from pass or the default locations.
        let mut config = if opt.config_path.is_some() {
            Config::from_file(opt.config_path.as_ref().unwrap())
                .expect("failed to parse config from file")
        } else {
            Config::default()
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

        config
    }
}

impl Default for Config {
    /// Loads the default config.
    ///
    /// First, the `pwd` directory is searched (`~/.asap-config`), and if not
    /// found, then the user's home directory is searched. If no config is found
    /// then an empty config is used.
    fn default() -> Config {
        let path = env::current_dir()
            .expect("failed to find current directory")
            .join(".asap-config");

        Config::from_file(path).unwrap_or_else(|_| {
            let path = env::home_dir()
                .expect("failed to find home directory")
                .join(".asap-config");

            Config::from_file(path).unwrap_or_else(|_| {
                eprintln!("No ASAP configuration found! Have you run `asap init`?");
                ::std::process::exit(1);
            })
        })
    }
}

/// Loads a PEM file and convert it to DER.
pub fn pem_from_file<P: AsRef<Path>>(path: P) -> Vec<u8> {
    let file = fs::read(path).expect("failed to read pem file");
    let dem_key = pem::parse(file).expect("failed to parse pem file");
    dem_key.contents
}
