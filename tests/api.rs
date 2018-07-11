extern crate asap;
extern crate chrono;
extern crate jsonwebtoken as jwt;
extern crate reqwest;
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;

use jwt::TokenData;
use serde::de::DeserializeOwned;
use serde_json::map::Map;
use serde_json::value::{from_value, Value};
use serde_json::{to_string, from_str};
use std::env;
use std::thread;
use std::time::Duration;
use chrono::Utc;

use asap::claims::{Aud, DefaultClaims, Claims, DEFAULT_TOKEN_LIFESPAN};
use asap::generator::{Generator};
use asap::validator::{Validator, ValidatorBuilder};

// A private key to use to sign the tokens.
const PRIVATE_KEY_01: &[u8] = include_bytes!("../support/keys/service01/1530402390-private.der");
// The issuer of the service generating the token.
const ISS_01: &'static str = "service01";
const ISS_02: &'static str = "service02";
// The path of the public key in the keyserver.
const KID_01: &'static str = "service01/1530402390-public.der";
const KID_02: &'static str = "service02/1530402393-public.der";
// The URL of our test keyserver.
const KS_URL: &'static str = "http://localhost:8000/";

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

fn get_validator_builder() -> ValidatorBuilder {
    let resource_server_audience = String::from(ISS_01);
    Validator::builder(String::from(KS_URL), resource_server_audience)
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

fn extract_claim<T: DeserializeOwned>(map: &Map<String, Value>, key: &str) -> T {
    from_value::<T>(map.get(key).unwrap().clone()).unwrap()
}

fn validate_claims(token_data: TokenData<Claims<ExtraClaims>>, expected_aud: Aud, extra_claims: Option<ExtraClaims>) {
    assert_eq!(token_data.claims.extra_claims, extra_claims);

    let claims_as_map: Map<_, _> = from_str(&to_string(&token_data.claims).unwrap()).unwrap();
    let aud = extract_claim::<Aud>(&claims_as_map, "aud");
    let iss = extract_claim::<String>(&claims_as_map, "iss");
    let jti = extract_claim::<String>(&claims_as_map, "jti");
    let iat = extract_claim::<i64>(&claims_as_map, "iat");
    let exp = extract_claim::<i64>(&claims_as_map, "exp");
    let now = Utc::now().timestamp();

    assert_eq!(aud, expected_aud);
    assert_eq!(&iss, ISS_01);
    assert_eq!(jti.len(), 20);
    assert_eq!(exp - iat, DEFAULT_TOKEN_LIFESPAN);
    assert!(iat > now - 2 && iat < now + 2);
}

/**
 * Helpers for interfacing with our test keyserver.
 */

fn ks_reset() {
    reqwest::get(&format!("{}reset", KS_URL)).unwrap();
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
        reqwest::get(&format!("{}{}", KS_URL, KID_01)).unwrap();
    }
    assert_eq!(ks_count(), "100");

    // Count should reset back to 0.
    ks_reset();
    assert_eq!(ks_count(), "0");
}

#[test]
fn it_works() {
    let mut generator = default_generator();
    let mut validator = get_validator_builder().build();

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
    // Setup environment for the validator.
    env::set_var("ASAP_SERVER_AUDIENCE", ISS_01);
    env::set_var("ASAP_KEYSERVER_URL", KS_URL);
    env::set_var("ASAP_FALLBACK_KEYSERVER_URL", KS_URL);
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
    let now = Utc::now().timestamp();
    let mut generator = default_generator();
    let mut validator = get_validator_builder().build();

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
    let mut generator = default_generator();
    let mut validator = get_validator_builder().build();

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
    let mut generator = default_generator();
    let mut validator = get_validator_builder().build();

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
    let mut generator = default_generator();
    let mut validator = get_validator_builder()
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
    let mut generator = default_generator();
    let mut validator = get_validator_builder().build();

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
    let mut generator = default_generator();
    let mut validator = get_validator_builder().build();

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
    let mut generator = default_generator();
    let mut validator = get_validator_builder().build();

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
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct ExtraClaims { sub: String }
    let extra_claims = ExtraClaims { sub: ISS_02.to_string() };

    let mut generator = default_generator();
    let mut validator = get_validator_builder().build();

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
    let mut validator = get_validator_builder().build();

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
    let mut generator = default_generator();

    // Enable duplicate `jti` detection:
    let mut validator = get_validator_builder()
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
    // Give the wrong `kid` for the `private_key` used.
    let mut generator = Generator::new(ISS_01.to_string(), KID_02.to_string(), PRIVATE_KEY_01.to_vec());
    let mut validator = get_validator_builder().build();

    let token = generator.token::<Claims<ExtraClaims>>(default_aud(), None).unwrap();
    match validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Invalid signature")
    }
}

#[test]
fn it_fails_with_no_public_key() {
    let mut generator = Generator::new(ISS_01.to_string(), "not-a-kid".to_string(), PRIVATE_KEY_01.to_vec());
    let mut validator = get_validator_builder().build();

    let token = generator.token::<Claims<ExtraClaims>>(default_aud(), None).unwrap();
    match validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Failed to retrieve public key from keyserver: NotFound")
    }
}

#[test]
fn it_uses_the_fallback_keyserver() {
    let mut generator = default_generator();

    // Ensure the first keyserver fails.
    let keyserver = "http://not-a-real-server:1234/".to_string();
    let mut validator = Validator::builder(keyserver, ISS_01.to_string())
        .fallback_keyserver(KS_URL.to_string())
        .build();

    let token = generator.token::<Claims<ExtraClaims>>(default_aud(), None).unwrap();
    let token_data = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();
    validate_claims(token_data, default_aud(), None);
}

#[test]
fn it_fetches_key_from_cache() {
    // Reset keyserver count to 0.
    ks_reset();

    let mut generator = default_generator();
    let mut validator = get_validator_builder().build();
    let token = generator.token::<Claims<ExtraClaims>>(default_aud(), None).unwrap();

    // Requesting the same `kid_01` twice should only result in 1 request.
    let _ = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();
    assert_eq!(ks_count(), "1");
    let _ = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();
    assert_eq!(ks_count(), "1");
}

#[test]
fn it_does_not_fetch_expired_key_from_cache() {
    // Reset keyserver count to 0.
    ks_reset();

    let mut generator = default_generator();
    let token = generator.token::<Claims<ExtraClaims>>(default_aud(), None).unwrap();

    // Make all tokens expire immediately.
    let mut validator = get_validator_builder()
        .cache_duration(Duration::from_nanos(0))
        .build();

    // The expired `kid_01` should be requested again = 2 requests.
    let _ = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();
    assert_eq!(ks_count(), "1");
    let _ = validator.decode::<Claims<ExtraClaims>>(&token, &vec![ISS_01]).unwrap();
    assert_eq!(ks_count(), "2");
}
