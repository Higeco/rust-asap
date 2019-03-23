extern crate asap;
#[macro_use]
extern crate bencher;
extern crate asap_deps_keyserver as keyserver;
extern crate chrono;
extern crate jsonwebtoken as jwt;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;

use asap::claims::Aud;
use asap::generator::Generator;
use asap::validator::Validator;
use bencher::Bencher;
use keyserver::Keyserver;
use std::collections::HashMap;

// A private key to use to sign the tokens.
const PRIVATE_KEY_01: &[u8] = include_bytes!("../support/keys/service01/1530402390-private.der");
// The path of the public key in the keyserver.
const KID_01: &str = "service01/1530402390-public.der";
// The issuer of the token.
const ISS_01: &str = "service01";

fn default_generator() -> Generator {
    Generator::new(
        ISS_01.to_string(),
        KID_01.to_string(),
        PRIVATE_KEY_01.to_vec(),
    )
}

fn default_aud() -> Aud {
    Aud::One(ISS_01.to_string())
}

fn speed_of_generating_tokens(b: &mut Bencher) {
    let generator = default_generator();
    b.iter(|| generator.token(default_aud(), None).unwrap());
}

fn speed_of_generating_tokens_with_caching_enabled(b: &mut Bencher) {
    let generator = default_generator();
    generator.enable_token_caching(10, ::std::time::Duration::from_millis(1000));

    b.iter(|| generator.token(default_aud(), None).unwrap());
}

fn speed_of_generating_tokens_with_extra_claims(b: &mut Bencher) {
    let mut extra_claims = HashMap::new();
    extra_claims.insert("foo".to_string(), json!("foo"));
    extra_claims.insert("bar".to_string(), json!(1234));
    extra_claims.insert("baz".to_string(), json!(["baz", "bop"]));

    let generator = default_generator();
    b.iter(|| {
        generator
            .token(default_aud(), Some(extra_claims.clone()))
            .unwrap()
    });
}

fn speed_of_generating_tokens_with_extra_claims_with_caching_enabled(b: &mut Bencher) {
    let mut extra_claims = HashMap::new();
    extra_claims.insert("foo".to_string(), json!("foo"));
    extra_claims.insert("bar".to_string(), json!(1234));
    extra_claims.insert("baz".to_string(), json!(["baz", "bop"]));

    let generator = default_generator();
    generator.enable_token_caching(10, ::std::time::Duration::from_millis(1000));

    b.iter(|| {
        generator
            .token(default_aud(), Some(extra_claims.clone()))
            .unwrap()
    });
}

fn speed_of_validating_tokens(b: &mut Bencher) {
    let generator = default_generator();
    let token = generator.token(default_aud(), None).unwrap();

    let keyserver = Keyserver::start();
    let mut validator = Validator::builder(keyserver.url().to_string(), ISS_01.to_string()).build();

    // Validate once to cache the public key:
    validator.decode(&token, &vec![ISS_01]).unwrap();
    b.iter(|| validator.decode(&token, &vec![ISS_01]).unwrap());
}

fn speed_of_validating_tokens_without_asap(b: &mut Bencher) {
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Claims {
        iss: String,
        exp: i64,
        iat: i64,
        aud: String,
        jti: String,
    }

    let generator = default_generator();
    let token = generator.token(default_aud(), None).unwrap();

    let jwt_validator = jwt::Validation {
        leeway: 0,
        validate_exp: false,
        validate_nbf: false,
        iss: None,
        sub: None,
        aud: None,
        algorithms: vec![jwt::Algorithm::RS256],
    };

    let public_key: &[u8] = include_bytes!("../support/keys/service01/1530402390-public.der");
    b.iter(|| jwt::decode::<Claims>(&token, &public_key, &jwt_validator).unwrap());
}

fn speed_of_dangerous_unsafe_decode(b: &mut Bencher) {
    let generator = default_generator();
    let token = generator.token(default_aud(), None).unwrap();

    let mut validator = Validator::builder("unused".to_string(), ISS_01.to_string()).build();
    b.iter(|| validator.dangerous_unsafe_decode(&token).unwrap());
}

benchmark_group!(
    generate,
    speed_of_generating_tokens,
    speed_of_generating_tokens_with_caching_enabled,
    speed_of_generating_tokens_with_extra_claims,
    speed_of_generating_tokens_with_extra_claims_with_caching_enabled
);
benchmark_group!(
    validate,
    speed_of_validating_tokens,
    speed_of_validating_tokens_without_asap,
    speed_of_dangerous_unsafe_decode
);
benchmark_main!(generate, validate);
