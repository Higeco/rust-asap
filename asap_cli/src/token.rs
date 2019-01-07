use asap::generator::Generator;
use serde_json::Value;

use config::Config;
use errors::Result;

// Print a generated ASAP token.
pub fn run(config: &Config, full_header: bool, auth_header: bool) -> Result<()> {
    let token = create_token(config);

    if full_header {
        println!("Authorization: Bearer {}", token);
    } else if auth_header {
        println!("Authorization: {}", token);
    } else {
        println!("{}", token);
    }

    Ok(())
}

// Creates a token using the given config.
pub fn create_token(config: &Config) -> String {
    let iss = config.issuer.clone();
    let kid = config.key_id.clone();
    let pkey = config.private_key.clone();
    let mut generator = Generator::new(iss, kid, pkey);

    let aud = config.audience.clone();
    let extra_claims = config.extra_claims.clone();
    if let Ok(token) = generator.token::<Value>(aud, extra_claims) {
        token
    } else {
        panic!("failed to generate token\n{:?}", config)
    }
}
