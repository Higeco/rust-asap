use super::generator::Generator;
use super::validator::{Validator, ValidatorOptions};

use jwt;
use reqwest;
use std::time::Duration;
use serde::de::DeserializeOwned;

// A private key to use to sign the tokens.
const PRIVATE_KEY_01: &[u8] = include_bytes!("../support/keys/01-private.der");
const PRIVATE_KEY_02: &[u8] = include_bytes!("../support/keys/02-private.der");
// The path of the public key in the keyserver.
const KID_01: &'static str = "01-public.der";
const KID_02: &'static str = "02-public.der";
// The URL of our test keyserver.
const KS_URL: &'static str = "http://localhost:8000/";

// A simple `Claims` struct. At the least this must include the `iss`, `sub` and
// `aud` fields, but you can add extra claims to it as well.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
}

/**
 * Implement the `Default` trait for commonly used structs in order to reduce
 * the boilerplate required for the tests.
 */

impl Default for Claims {
    fn default() -> Claims {
        Claims {
            iss: String::from("iss"),
            sub: String::from("sub"),
            aud: String::from("aud")
        }
    }
}

impl Default for ValidatorOptions {
    fn default() -> ValidatorOptions {
        ValidatorOptions {
            aud: ValidatorOptions::audience(&"aud"),
            iss: Some(String::from("iss")),
            sub: Some(String::from("sub")),
            keyserver_url: String::from(KS_URL),
            fallback_keyserver_url: String::from(KS_URL),
            cache_duration: None
        }
    }
}

impl<'a> Default for Generator<'a> {
    fn default() -> Generator<'a> {
        Generator {
            kid: String::from(KID_01),
            private_key: PRIVATE_KEY_01
        }
    }
}

/**
 * Helpers for generating and validating tokens.
 */

// Given the generator and claims, return a token.
// Panic on any error.
fn gen_token(generator: &Generator, claims: &Claims) -> String {
    match generator.generate(claims) {
        Ok(token) => token,
        Err(e) => {
            println!("Error generating token: {}", e);
            panic!(e);
        }
    }
}

// Given the validator and token, return the decoded token.
// Panic on any error.
fn val_token<T: DeserializeOwned>(validator: &mut Validator, token: String) -> jwt::TokenData<T> {
    match validator.validate(token) {
        Ok(token_data) => token_data,
        Err(e) => {
            println!("Error validating token: {}", e);
            panic!(e);
        }
    }
}

/**
 * Helpers for interfacing with our test keyserver.
 */

fn ks_reset() {
    let _ = reqwest::get(&format!("{}reset", KS_URL));
}

fn ks_count() -> String {
    reqwest::get(&format!("{}count", KS_URL)).unwrap().text().unwrap()
}

/**
 * Tests.
 *
 * Since these rely on hit counts on our test keyserver, these tests must be
 * run serially (otherwise the counts will interfere with each other).
 *
 * TODO: Surely, there's a better way to do this/run them in parallel.
 */

#[test]
fn keyserver_works() {
    // Count should start at 0.
    ks_reset();
    assert_eq!(ks_count(), "0");

    // Make 100 requests.
    for _ in 0..100 {
        let _ = reqwest::get(&format!("{}{}", KS_URL, KID_01));
    }
    assert_eq!(ks_count(), "100");

    // Count should reset back to 0.
    ks_reset();
    assert_eq!(ks_count(), "0");
}

#[test]
fn it_works() {
    let claims = Claims::default();
    let validator_options = ValidatorOptions::default();

    let generator = Generator::default();
    let mut validator = Validator::new(validator_options);

    let token_data = val_token(&mut validator, gen_token(&generator, &claims));
    assert_eq!(claims, token_data.claims);
}

#[test]
fn it_fails_with_wrong_public_key() {
    let claims = Claims::default();
    let validator_options = ValidatorOptions::default();

    let mut generator = Generator::default();
    // Give the wrong `kid` for the `private_key` used.
    generator.kid = String::from(KID_02);
    let mut validator = Validator::new(validator_options);

    match validator.validate::<Claims>(gen_token(&generator, &claims)) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Invalid signature")
    }
}

#[test]
fn it_fails_with_wrong_private_key() {
    let claims = Claims::default();
    let validator_options = ValidatorOptions::default();

    let mut generator = Generator::default();
    // Give the wrong `private_key` for the `kid` used.
    generator.private_key = PRIVATE_KEY_02;
    let mut validator = Validator::new(validator_options);

    match validator.validate::<Claims>(gen_token(&generator, &claims)) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Invalid signature")
    }
}

#[test]
fn it_fails_with_no_public_key() {
    let claims = Claims::default();
    let validator_options = ValidatorOptions::default();

    let mut generator = Generator::default();
    // Give the wrong `kid` for the private key used.
    generator.kid = String::from("not-a-kid");
    let mut validator = Validator::new(validator_options);

    match validator.validate::<Claims>(gen_token(&generator, &claims)) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Failed to retrieve public key from keyserver")
    }
}

#[test]
fn it_fails_with_incorrect_audience() {
    let claims = Claims::default();
    let mut validator_options = ValidatorOptions::default();
    // A different audience to the token's audience.
    validator_options.aud = ValidatorOptions::audience(&"someone-else");

    let generator = Generator::default();
    let mut validator = Validator::new(validator_options);

    match validator.validate::<Claims>(gen_token(&generator, &claims)) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Invalid Audience")
    }
}

#[test]
fn it_uses_the_fallback_keyserver() {
    let claims = Claims::default();
    let mut validator_options = ValidatorOptions::default();
    // Ensure the first keyserver fails.
    validator_options.keyserver_url = String::from("http://not-a-real-server:1234/");

    let generator = Generator::default();
    let mut validator = Validator::new(validator_options);

    let token_data = val_token(&mut validator, gen_token(&generator, &claims));
    assert_eq!(claims, token_data.claims);
}

#[test]
fn it_fetches_key_from_cache() {
    // Reset keyserver count to 0.
    ks_reset();

    let claims = Claims::default();
    let validator_options = ValidatorOptions::default();

    let generator = Generator::default();
    let mut validator = Validator::new(validator_options);

    // Requesting the same `kid_01` twice should only result in 1 request.
    let _ = val_token::<Claims>(&mut validator, gen_token(&generator, &claims));
    assert_eq!(ks_count(), "1");
    let _ = val_token::<Claims>(&mut validator, gen_token(&generator, &claims));
    assert_eq!(ks_count(), "1");
}

#[test]
fn it_does_not_fetch_expired_key_from_cache() {
    // Reset keyserver count to 0.
    ks_reset();

    let claims = Claims::default();
    let mut validator_options = ValidatorOptions::default();
    // Make all tokens expire immediately.
    validator_options.cache_duration = Some(Duration::from_nanos(0));

    let generator = Generator::default();
    let mut validator = Validator::new(validator_options);

    // The expired `kid_01` should be requested again = 2 requests.
    let _ = val_token::<Claims>(&mut validator, gen_token(&generator, &claims));
    assert_eq!(ks_count(), "1");
    let _ = val_token::<Claims>(&mut validator, gen_token(&generator, &claims));
    assert_eq!(ks_count(), "2");
}
