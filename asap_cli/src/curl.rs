use std::process::Command;

use config::Config;
use errors::Result;
use token;

// Simply inject an authorisation header into curl and pass along all other
// arguments passed to the binary.
pub fn run(config: &Config, args: Vec<String>) -> Result<()> {
    let header = format!("Authorization: Bearer {}", token::create_token(config));
    Command::new("curl")
        .args(&["-H", &header])
        .args(&args)
        .spawn()
        .expect("failed to spawn curl")
        .wait()
        .expect("failed to wait on curl");

    Ok(())
}
