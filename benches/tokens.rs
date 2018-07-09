#![feature(test)]
extern crate asap;
extern crate chrono;
extern crate test;
extern crate jsonwebtoken as jwt;
extern crate serde;
#[macro_use]
extern crate serde_derive;

use asap::generator::Generator;
use asap::validator::{Validator, ValidatorOptions};
use chrono::Utc;
use test::Bencher;


// A private key to use to sign the tokens.
const PRIVATE_KEY_01: &[u8] = include_bytes!("../support/keys/service01/1530402390-private.der");
// The path of the public key in the keyserver.
const KID_01: &'static str = "service01/1530402390-public.der";
// The URL of our test keyserver.
const KS_URL: &'static str = "http://localhost:8000/";


// A simple `Claims` struct. At the least this must include the `iss`, `exp`,
// `iat`, `aud` and `jti` fields, but you can add extra claims to it as well.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Claims {
    iss: String,
    exp: i64,
    iat: i64,
    aud: String,
    jti: String
}

impl Default for Claims {
    fn default() -> Claims {
        let now = Utc::now().timestamp();
        Claims {
            iss: String::from("service01"),
            exp: now + 3000,
            iat: now,
            aud: String::from("resource_server_audience"),
            jti: String::from("foobar")
        }
    }
}

fn default_validator_options() -> ValidatorOptions {
    ValidatorOptions {
        leeway: None,
        max_lifespan: None,
        resource_server_audience: String::from("resource_server_audience"),
        keyserver_url: String::from(KS_URL),
        fallback_keyserver_url: String::from(KS_URL),
        validate_kid: true,
        validate_jti: false,
        cache_duration: None
    }
}

fn default_generator() -> Generator {
    Generator::new(KID_01.to_string(), PRIVATE_KEY_01.to_vec())
}


#[bench]
fn speed_of_generating_tokens(b: &mut Bencher) {
    let claims = Claims::default();
    let generator = default_generator();
    b.iter(|| generator.token(&claims).unwrap());
}

#[bench]
fn speed_of_generating_tokens_with_validation(b: &mut Bencher) {
    let claims = Claims::default();
    let mut generator = default_generator();
    generator.validate_claims = true;
    b.iter(|| generator.token(&claims).unwrap());
}

#[bench]
fn speed_of_validating_tokens(b: &mut Bencher) {
    let claims = Claims::default();
    let generator = default_generator();
    let token = generator.token(&claims).unwrap();

    let mut validator = Validator::new(default_validator_options());

    // Validate once to cache the public key:
    validator.decode::<Claims>(&token, &vec!["service01"]).unwrap();
    b.iter(|| validator.decode::<Claims>(&token, &vec!["service01"]).unwrap());
}

#[bench]
fn speed_of_validating_tokens_without_asap(b: &mut Bencher) {
    let claims = Claims::default();
    let generator = default_generator();
    let token = generator.token(&claims).unwrap();

    let jwt_validator = jwt::Validation {
        leeway: 0,
        validate_exp: false,
        validate_iat: false,
        validate_nbf: false,
        iss: None,
        sub: None,
        aud: None,
        algorithms: vec![jwt::Algorithm::RS256],
    };

    let public_key: &[u8] = include_bytes!("../support/keys/service01/1530402390-public.der");
    b.iter(|| jwt::decode::<Claims>(&token, &public_key, &jwt_validator).unwrap());
}

#[bench]
fn speed_of_dangerous_unsafe_decode(b: &mut Bencher) {
    let claims = Claims::default();
    let generator = default_generator();
    let token = generator.token(&claims).unwrap();

    let mut validator = Validator::new(default_validator_options());
    b.iter(|| validator.dangerous_unsafe_decode::<Claims>(&token).unwrap());
}
