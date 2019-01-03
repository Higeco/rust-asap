extern crate asap;
extern crate chrono;
extern crate jsonwebtoken as jwt;
extern crate asap_deps_keyserver as keyserver;
extern crate reqwest;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

use chrono::Utc;
use jwt::TokenData;
use keyserver::Keyserver;
use std::env;
use std::thread;
use std::time::Duration;

use asap::claims::{Aud, Claims, DefaultClaims, DEFAULT_TOKEN_LIFESPAN};
use asap::generator::Generator;
use asap::validator::{Validator, ValidatorBuilder};

// A private key to use to sign the tokens.
const PRIVATE_KEY_01: &[u8] = include_bytes!("../support/keys/service01/1530402390-private.der");
// The issuer of the service generating the token.
const ISS_01: &'static str = "service01";
const ISS_02: &'static str = "service02";
// The path of the public key in the keyserver.
const KID_01: &'static str = "service01/1530402390-public.der";
const KID_02: &'static str = "service02/1530402393-public.der";

// Sample struct for extra claims.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct ExtraClaims {
    foo: String,
    bar: i64,
    baz: Vec<String>
}

impl ExtraClaims {
    pub fn new() -> ExtraClaims {
        let foo = "foo".to_string();
        let bar = 1234;
        let baz = vec!["baz".to_string(), "bop".to_string()];
        ExtraClaims { foo, bar, baz }
    }
}

fn get_validator_builder(keyserver_url: &str) -> ValidatorBuilder {
    let resource_server_audience = String::from(ISS_01);
    Validator::builder(vec![String::from(keyserver_url)], resource_server_audience)
}


fn default_aud() -> Aud {
    Aud::One(ISS_01.to_string())
}

fn default_generator() -> Generator {
    Generator::new(
        ISS_01.to_string(),
        KID_01.to_string(),
        PRIVATE_KEY_01.to_vec()
    )
}

fn validate_claims(token_data: TokenData<Claims<ExtraClaims>>, expected_aud: Aud, extra_claims: Option<ExtraClaims>) {
    let now = Utc::now().timestamp();
    assert_eq!(token_data.claims.aud, expected_aud);
    assert_eq!(&token_data.claims.iss, ISS_01);
    assert_eq!(token_data.claims.jti.len(), 20);
    assert_eq!(token_data.claims.exp - token_data.claims.iat, DEFAULT_TOKEN_LIFESPAN);
    assert!(token_data.claims.iat > now - 2 && token_data.claims.iat < now + 2);
    assert_eq!(token_data.claims.extra_claims, extra_claims);
}





/**
 * Tests.
 *
 * Each test that needs a keyserver starts up a new one on an available port.
 * That means they can be run in parallel.
 */

#[test]
fn keyserver_works() {
    // Count should start at 0.
    let keyserver = Keyserver::start();
    assert_eq!(keyserver.count(), "0");

    // Make 100 requests.
    for _ in 0..100 {
        reqwest::get(&format!("{}{}", keyserver.url(), KID_01)).unwrap();
    }
    assert_eq!(keyserver.count(), "100");
}

#[test]
fn it_works() {
    let keyserver = Keyserver::start();
    let mut generator = default_generator();
    let mut validator = get_validator_builder(keyserver.url()).build();

    // Test with no extra claims.
    let token = generator.token::<ExtraClaims>(default_aud(), None).unwrap();
    let token_data = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();
    validate_claims(token_data, default_aud(), None);

    // Test with extra claims.
    let token = generator.token(default_aud(), Some(ExtraClaims::new())).unwrap();
    let token_data = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();
    validate_claims(token_data, default_aud(), Some(ExtraClaims::new()));
}

#[test]
fn instantiates_from_environment() {
    let keyserver = Keyserver::start();

    // Setup environment for the validator.
    env::set_var("ASAP_SERVER_AUDIENCE", ISS_01);
    env::set_var("ASAP_KEYSERVER_URL", keyserver.url());
    env::set_var("ASAP_FALLBACK_KEYSERVER_URL", keyserver.url());
    // Setup environment for the generator.
    env::set_var("ASAP_KEY_ID", KID_01);
    env::set_var("ASAP_ISSUER", ISS_01);
    env::set_var("ASAP_PRIVATE_KEY", include_str!("../support/keys/service01/1530402390-private.pem"));

    let mut generator = Generator::from_env().unwrap();
    let mut validator = Validator::from_env().unwrap().build();
    let token = generator.token(default_aud(), Some(ExtraClaims::new())).unwrap();
    let token_data = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();
    validate_claims(token_data, default_aud(), Some(ExtraClaims::new()));

    // Tear down environment.
    env::remove_var("ASAP_SERVER_AUDIENCE");
    env::remove_var("ASAP_KEYSERVER_URL");
    env::remove_var("ASAP_FALLBACK_KEYSERVER_URL");
    env::remove_var("ASAP_KEY_ID");
    env::remove_var("ASAP_ISSUER");
    env::remove_var("ASAP_PRIVATE_KEY");
}

#[test]
fn validates_nbf_is_after_current_time() {
    let keyserver = Keyserver::start();

    let now = Utc::now().timestamp();
    let mut generator = default_generator();
    let mut validator = get_validator_builder(keyserver.url()).build();

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct ExtraClaims { nbf: i64 }
    let extra_claims = ExtraClaims { nbf: now + 30 };

    // Validation should fail since `nbf` is after current time.
    let token = generator.token(default_aud(), Some(extra_claims)).unwrap();
    match validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert!(format!("{}", e).starts_with("Immature jwt signature"))
    }

    // Validation should succeed since `nbf` is before current time.
    let extra_claims = ExtraClaims { nbf: now - 30 };
    let token = generator.token(default_aud(), Some(extra_claims)).unwrap();
    let _ = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();
}

#[test]
fn validates_exp_is_before_current_time() {
    let keyserver = Keyserver::start();
    let mut generator = default_generator();
    let mut validator = get_validator_builder(keyserver.url()).build();

    // Generate a token which expires in one second, then wait two before validating.
    generator.set_max_lifespan(1);
    let token = generator.token::<DefaultClaims>(default_aud(), None).unwrap();
    thread::sleep(Duration::from_secs(2));

    // Validation should fail since `exp` is before current time.
    match validator.decode::<DefaultClaims>(&token, &vec![ISS_01]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert!(format!("{}", e).starts_with("Expired jwt signature"))
    }
}

#[test]
fn validates_if_max_lifespan_is_exceeded() {
    let keyserver = Keyserver::start();
    let mut generator = default_generator();
    let mut validator = get_validator_builder(keyserver.url()).build();

    // Validation should succeed since `max_lifespan` is below default hard limit.
    let token = generator.token::<DefaultClaims>(default_aud(), None).unwrap();
    let _ = validator.decode::<DefaultClaims>(&token, &vec![ISS_01]).unwrap();

    // Validation should fail since `max_lifespan` is above hard limit.
    generator.set_max_lifespan(3601);
    let token = generator.token::<DefaultClaims>(default_aud(), None).unwrap();
    match validator.decode::<DefaultClaims>(&token, &vec![ISS_01]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Token contained a lifespan greater than the \
            `max_lifespan` (hard limit of 3600 seconds)")
    }
}

#[test]
fn validates_if_custom_max_lifespan_is_exceeded() {
    let keyserver = Keyserver::start();
    let mut generator = default_generator();
    let mut validator = get_validator_builder(keyserver.url())
        .max_lifespan(60)
        .build();

    // Validation should succeed since `max_lifespan` is below custom limit.
    generator.set_max_lifespan(30);
    let token = generator.token::<DefaultClaims>(default_aud(), None).unwrap();
    let _ = validator.decode::<DefaultClaims>(&token, &vec![ISS_01]).unwrap();

    // Validation should fail since `max_lifespan` is above custom limit.
    generator.set_max_lifespan(120);
    let token = generator.token::<DefaultClaims>(default_aud(), None).unwrap();
    match validator.decode::<DefaultClaims>(&token, &vec![ISS_01]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Token contained a lifespan greater than the \
            `max_lifespan` (hard limit of 3600 seconds)")
    }
}

#[test]
fn validates_if_encounters_unrecognized_audience() {
    let keyserver = Keyserver::start();
    let mut generator = default_generator();
    let mut validator = get_validator_builder(keyserver.url()).build();

    // Should succeed since `Claims::default().aud = ISS_01`.
    let token = generator.token::<DefaultClaims>(default_aud(), None).unwrap();
    let _ = validator.decode::<DefaultClaims>(&token, &vec![ISS_01]).unwrap();

    // Should fail since audience does not match resource server's audience.
    let aud = Aud::One("not-whitelisted".to_string());
    let token = generator.token::<DefaultClaims>(aud, None).unwrap();
    match validator.decode::<DefaultClaims>(&token, &vec![ISS_01]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Resource server audience not found in `aud` claims of \
            token [\"not-whitelisted\"]")
    }
}

#[test]
fn works_with_aud_as_vec() {
    let keyserver = Keyserver::start();
    let mut generator = default_generator();
    let mut validator = get_validator_builder(keyserver.url()).build();

    // Should succeed since claims vec contains `ISS_01`.
    let aud = Aud::Many(vec!["foo".to_string(), ISS_01.to_string()]);
    let token = generator.token::<DefaultClaims>(aud, None).unwrap();
    let _ = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();

    // Should fail since audience does not contain `ISS_01`.
    let aud = Aud::Many(vec!["foo".to_string(), "bar".to_string()]);
    let token = generator.token::<DefaultClaims>(aud, None).unwrap();
    match validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Resource server audience not found in `aud` claims of \
            token [\"foo\", \"bar\"]")
    }
}

#[test]
fn works_with_aud_as_string() {
    let keyserver = Keyserver::start();
    let mut generator = default_generator();
    let mut validator = get_validator_builder(keyserver.url()).build();

    // Should succeed since whitelisted_issuers contains `ISS_01`.
    let token = generator.token::<Claims<ExtraClaims>>(default_aud(), None).unwrap();
    let _ = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();

    // Should fail since whitelisted_issuers doesn't contain `ISS_01`.
    let token = generator.token::<Claims<ExtraClaims>>(default_aud(), None).unwrap();
    match validator.decode::<Claims<ExtraClaims>>(&token, &vec!["foobar"]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Unknown or unauthorized subject \"service01\". The `sub` \
            claim (or `iss`) must exist in `whitelisted_issuers` [\"foobar\"]")
    }
}

#[test]
fn iss_is_assumed_if_sub_is_undefined() {
    let keyserver = Keyserver::start();

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct ExtraClaims { sub: String }
    let extra_claims = ExtraClaims { sub: ISS_02.to_string() };

    let mut generator = default_generator();
    let mut validator = get_validator_builder(keyserver.url()).build();

    let token_with_sub = generator.token(default_aud(), Some(extra_claims)).unwrap();
    let token_no_sub = generator.token::<Claims<ExtraClaims>>(default_aud(), None).unwrap();

    // Look for tokens with the following subjects only.
    let whitelisted_issuers = vec![ISS_02];

    // Validation should succeed with `sub` defined (`ISS_02`).
    let _ = validator.decode::<Claims<ExtraClaims>>(&token_with_sub, &whitelisted_issuers).unwrap();

    // Validation should fail without it (since `iss` is assumed).
    match validator.decode::<Claims<ExtraClaims>>(&token_no_sub, &whitelisted_issuers) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Unknown or unauthorized subject \"service01\". \
            The `sub` claim (or `iss`) must exist in `whitelisted_issuers` [\"service02\"]")
    }
}

#[test]
fn validates_kid_is_owned_by_isser() {
    let keyserver = Keyserver::start();
    let mut validator = get_validator_builder(keyserver.url()).build();

    // Default implementations should pass because:
    // - `default_generator()` has `iss = "service01"` and `kid = "service01/..."`
    let mut generator = default_generator();
    let token = generator.token::<Claims<ExtraClaims>>(default_aud(), None).unwrap();
    let _ = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();

    // This should fail since now `kid` does not start with `$iss/`.
    let mut generator = Generator::new(ISS_02.to_string(), KID_01.to_string(), PRIVATE_KEY_01.to_vec());
    let token = generator.token::<DefaultClaims>(default_aud(), None).unwrap();
    match validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "JWT header did not contain a valid `kid` claim. \
            As per ASAP spec, the `kid` claim must start with \"$iss/\" where $iss is the issuer \
            (kid: \"service01/1530402390-public.der\", iss: \"service02\")")
    }
}

#[test]
fn it_rejects_duplicate_jti_claims() {
    let keyserver = Keyserver::start();
    let mut generator = default_generator();

    // Enable duplicate `jti` detection:
    let mut validator = get_validator_builder(keyserver.url())
        .validate_jti(true)
        .build();

    let token = generator.token::<Claims<ExtraClaims>>(default_aud(), None).unwrap();

    // First token (first `jti` seen) should be successful.
    let _ = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();

    // Reusing the same token should fail (same `jti`).
    match validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert!(format!("{}", e).starts_with("Duplicate `jti` encountered: "))
    }

    // A new token (different `jti`) should be successful.
    let token = generator.token::<Claims<ExtraClaims>>(default_aud(), None).unwrap();
    let _ = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();
}

#[test]
fn it_fails_with_wrong_public_key() {
    let keyserver = Keyserver::start();
    // Give the wrong `kid` for the `private_key` used.
    let mut generator = Generator::new(ISS_01.to_string(), KID_02.to_string(), PRIVATE_KEY_01.to_vec());
    let mut validator = get_validator_builder(keyserver.url()).build();

    let token = generator.token::<Claims<ExtraClaims>>(default_aud(), None).unwrap();
    match validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Invalid signature")
    }
}

#[test]
fn it_fails_with_no_public_key() {
    let keyserver = Keyserver::start();
    let mut generator = Generator::new(ISS_01.to_string(), "not-a-kid".to_string(), PRIVATE_KEY_01.to_vec());
    let mut validator = get_validator_builder(keyserver.url()).build();

    let token = generator.token::<Claims<ExtraClaims>>(default_aud(), None).unwrap();
    match validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Failed to retrieve public key from keyserver: \"Failed to fetch a key from any keyserver\"")
    }
}

#[test]
fn it_uses_the_fallback_keyserver() {
    let keyserver = Keyserver::start();
    let mut generator = default_generator();

    // Ensure the first keyserver fails.
    let keyserver_urls = vec![
        "http://not-a-real-server:1234/".to_string(),
        keyserver.url().to_string()
    ];
    let mut validator = Validator::builder(keyserver_urls, ISS_01.to_string())
        .build();

    let token = generator.token::<Claims<ExtraClaims>>(default_aud(), None).unwrap();
    let token_data = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();
    validate_claims(token_data, default_aud(), None);
}

#[test]
fn it_fetches_key_from_cache() {
    let server = Keyserver::start();

    let mut generator = default_generator();
    let mut validator = get_validator_builder(server.url()).build();
    let token = generator.token::<Claims<ExtraClaims>>(default_aud(), None).unwrap();

    // Requesting the same `kid_01` twice should only result in 1 request.
    let _ = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();
    assert_eq!(server.count(), "1");
    let _ = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();
    assert_eq!(server.count(), "1");
}

#[test]
fn it_does_not_fetch_expired_key_from_cache() {
    let server = Keyserver::start();

    let mut generator = default_generator();
    let token = generator.token::<Claims<ExtraClaims>>(default_aud(), None).unwrap();

    // Make all tokens expire immediately.
    let mut validator = get_validator_builder(server.url())
        .cache_duration(Duration::from_nanos(0))
        .build();

    // The expired `kid_01` should be requested again = 2 requests.
    let _ = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();
    assert_eq!(server.count(), "1");
    let _ = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();
    assert_eq!(server.count(), "2");
}
