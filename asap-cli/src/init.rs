use asap::claims::Aud;
use config::{self, Config};
use serde_json;
use std::env;
use std::fs::{create_dir_all, File};
use std::io::{self, stdout, Write};
use std::path::PathBuf;

use config::{default_config_path, CONFIG_BASENAME};
use errors::Result;

// Prompt the user to create an `.asap-config` file.
pub fn run() -> Result<()> {
    let issuer = read_line("issuer: ");
    let key_id = read_line("key_id: ");
    let private_key = config::pem_from_file(read_line("private_key (path to pem file): "));
    let audience = parse_audience(read_line(
        "intended audience (comma separated for multiple): ",
    ));

    let extra_claims = read_line("extra claims (as JSON string, leave blank for none): ");
    let extra_claims = if extra_claims.len() > 0 {
        serde_json::from_str(&extra_claims).expect("failed to pass extra_claims json")
    } else {
        None
    };

    // Save the config in the default config path, and fallback to the current
    // directory if getting that directory that fails.
    let default_path = default_config_path().unwrap_or(env::current_dir()?.join(CONFIG_BASENAME));

    let output_path = read_line(&format!(
        "output path (default {}): ",
        default_path.display()
    ));
    let output_path = if output_path.len() > 0 {
        PathBuf::from(&output_path)
    } else {
        default_path
    };

    if let Some(parent_path) = output_path.clone().parent() {
        create_dir_all(parent_path)?;
        Ok(serde_json::to_writer(
            File::create(output_path)?,
            &Config {
                audience,
                issuer,
                key_id,
                private_key,
                extra_claims,
            },
        )?)
    } else {
        Err(format_err!(
            "failed to create parent directory {}",
            output_path.display()
        ))
    }
}

// Prompt the user for input.
fn read_line(prompt: &str) -> String {
    print!("{}", prompt);
    stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("failed to read stdin");

    // Remove trailing newline.
    input.pop();
    input
}

// Parse audience from input.
// > "aud"       = Aud::One("aud")
// > "aud1,aud2" = Aud::Many(vec!["aud1", "aud2"])
fn parse_audience(input: String) -> Aud {
    if input.contains(",") {
        Aud::from_vec(input.split(',').collect())
    } else {
        Aud::from_str(format!("\"{}\"", input))
    }
}
