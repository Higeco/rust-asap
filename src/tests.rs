use jwt;
use reqwest;
use std::env;
use std::time::Duration;
use test::Bencher;
use serde::ser::Serialize;
use serde::de::DeserializeOwned;
use chrono::Utc;

use super::generator::Generator;
use super::validator::{Validator, ValidatorOptions};

// A private key to use to sign the tokens.
const PRIVATE_KEY_01: &[u8] = include_bytes!("../support/keys/service01/1530402390-private.der");
const PRIVATE_KEY_02: &[u8] = include_bytes!("../support/keys/service02/1530402393-private.der");
// The path of the public key in the keyserver.
const KID_01: &'static str = "service01/1530402390-public.der";
const KID_02: &'static str = "service02/1530402393-public.der";
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

/**
 * Implement the `Default` trait for commonly used structs in order to reduce
 * the boilerplate required for the tests.
 */

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

impl Default for ValidatorOptions {
    fn default() -> ValidatorOptions {
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
}

impl Default for Generator {
    fn default() -> Generator {
        Generator::new(KID_01.to_string(), PRIVATE_KEY_01.to_vec())
    }
}

/**
 * Helpers for generating and validating tokens.
 */

// Given the generator and claims, return a token.
// Panic on any error.
fn gen_token(generator: &Generator, claims: &Claims) -> String {
    match generator.token(claims) {
        Ok(token) => token,
        Err(e) => {
            eprintln!("Error generating token: {}", e);
            panic!(e);
        }
    }
}

// Given the validator and token, return the decoded token.
// Panic on any error.
fn val_token<T: Serialize + DeserializeOwned>(validator: &mut Validator, token: &str, authorized_subjects: &Vec<&str>) -> jwt::TokenData<T> {
    match validator.decode(token, authorized_subjects) {
        Ok(token_data) => token_data,
        Err(e) => {
            eprintln!("Error validating token: {}", e);
            panic!(e);
        }
    }
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

// TODO: already done by `jsonwebtoken` but need to have tests:
//  --> Resource servers MUST reject tokens signed with an unsupported algorithm
//  --> Unsigned access tokens MUST be rejected

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
    let claims = Claims::default();
    let generator = Generator::default();
    let mut validator = Validator::new(ValidatorOptions::default());

    let token_data = val_token(&mut validator, &gen_token(&generator, &claims), &vec!["service01"]);
    assert_eq!(claims, token_data.claims);
}

#[test]
fn instantiates_from_environment() {
    let claims = Claims::default();

    // Setup environment for the validator.
    env::set_var("ASAP_SERVER_AUDIENCE", "resource_server_audience");
    env::set_var("ASAP_KEYSERVER_URL", KS_URL);
    env::set_var("ASAP_FALLBACK_KEYSERVER_URL", KS_URL);
    // Setup environment for the generator.
    env::set_var("ASAP_KEY_ID", KID_01);
    env::set_var("ASAP_PRIVATE_KEY", include_str!("../support/keys/service01/1530402390-private.pem"));

    let generator = Generator::from_env();
    let mut validator = Validator::from_env();
    val_token::<Claims>(&mut validator, &generator.token(&claims).unwrap(), &vec!["service01"]);

    // Tear down environment.
    env::remove_var("ASAP_SERVER_AUDIENCE");
    env::remove_var("ASAP_KEYSERVER_URL");
    env::remove_var("ASAP_FALLBACK_KEYSERVER_URL");
    env::remove_var("ASAP_KEY_ID");
    env::remove_var("ASAP_PRIVATE_KEY");
}

#[test]
fn generator_checks_claims_are_valid() {
    let mut generator = Generator::default();
    generator.validate_claims = true;

    // Default claims struct.
    let c = Claims::default();

    // Helper to easily re-use a `String`.
    let o = |s: &str| s.to_owned();

    // Should pass with default Claims struct.
    assert!(generator.token(&c).is_ok());

    // Should fail if `iss` claim doesn't match the start of the `kid`:
    let bad_iss = Claims { iss: String::from("foo"), iat: c.iat, exp: c.exp, aud: o(&c.aud), jti: o(&c.jti) };
    assert!(generator.token(&bad_iss).is_err());
    assert!(generator.validate_claims(&bad_iss).is_err());

    // Should fail without an `iss` claim:
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct ClaimsNoIss { iat: i64, exp: i64, aud: String, jti: String }
    let no_iss = ClaimsNoIss { iat: c.iat, exp: c.exp, aud: o(&c.aud), jti: o(&c.jti) };
    assert!(generator.token(&no_iss).is_err());
    assert!(generator.validate_claims(&no_iss).is_err());

    // Should fail without an `exp` claim:
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct ClaimsNoExp { iat: i64, iss: String, aud: String, jti: String }
    let no_exp = ClaimsNoExp { iat: c.iat, iss: o(&c.iss), aud: o(&c.aud), jti: o(&c.jti) };
    assert!(generator.token(&no_exp).is_err());
    assert!(generator.validate_claims(&no_exp).is_err());

    // Should fail without an `iat` claim:
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct ClaimsNoIat { exp: i64, iss: String, aud: String, jti: String }
    let no_iat = ClaimsNoIat { exp: c.exp, iss: o(&c.iss), aud: o(&c.aud), jti: o(&c.jti) };
    assert!(generator.token(&no_iat).is_err());
    assert!(generator.validate_claims(&no_iat).is_err());

    // Should fail without an `jti` claim:
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct ClaimsNoJti { iat: i64, exp: i64, iss: String, aud: String }
    let no_jti = ClaimsNoJti { iat: c.iat, exp: c.exp, iss: o(&c.iss), aud: o(&c.aud) };
    assert!(generator.token(&no_jti).is_err());
    assert!(generator.validate_claims(&no_jti).is_err());

    // Should fail without an `aud` claim:
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct ClaimsNoAud { iat: i64, exp: i64, iss: String, jti: String }
    let no_aud = ClaimsNoAud { iat: c.iat, exp: c.exp, iss: o(&c.iss), jti: o(&c.jti) };
    assert!(generator.token(&no_aud).is_err());
    assert!(generator.validate_claims(&no_aud).is_err());

    // Should fail if `exp` - `iat` is greater than one hour:
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct ClaimsBadLifespan { iat: i64, exp: i64, iss: String, aud: String, jti: String }
    let bad_lifespan = ClaimsBadLifespan { iat: c.iat, exp: c.iat + 3601, iss: o(&c.iss), aud: o(&c.aud), jti: o(&c.jti) };
    assert!(generator.token(&bad_lifespan).is_err());
    assert!(generator.validate_claims(&bad_lifespan).is_err());
}

#[test]
fn validates_nbf_is_after_current_time() {
    let now = Utc::now().timestamp();
    let generator = Generator::default();
    let mut validator = Validator::new(ValidatorOptions::default());

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct ClaimsWithNbf {
        iss: String,
        nbf: i64,
        exp: i64,
        iat: i64,
        aud: String,
        jti: String
    }

    let mut claims_with_nbf = ClaimsWithNbf {
        nbf: 0, // unset now, is explicitly set below
        iat: now,
        exp: now + 60,
        iss: String::from("service01"),
        aud: String::from("resource_server_audience"),
        jti: String::from("foobar")
    };

    // Validation should fail since `nbf` is after current time.
    claims_with_nbf.nbf = now + 30;
    match validator.decode::<ClaimsWithNbf>(&generator.token(&claims_with_nbf).unwrap(), &vec!["service01"]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert!(format!("{}", e).starts_with("Immature jwt signature"))
    }

    // Validation should succeed since `nbf` is before current time.
    claims_with_nbf.nbf = now - 30;
    val_token::<ClaimsWithNbf>(&mut validator, &generator.token(&claims_with_nbf).unwrap(), &vec!["service01"]);
}

#[test]
fn validates_unset_nbf_is_after_current_time() {
    let now = Utc::now().timestamp();
    let generator = Generator::default();
    let mut validator = Validator::new(ValidatorOptions::default());

    // The `nbf` claim will default to `iat`.
    let mut claims = Claims::default();

    // Validation should fail since `nbf` (defaulting to `iat`) is after current time.
    claims.iat = now + 30;
    match validator.decode::<Claims>(&generator.token(&claims).unwrap(), &vec!["service01"]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert!(format!("{}", e).starts_with("Immature jwt signature"))
    }

    // Validation should succeed since `nbf` (defaulting to `iat`) is before current time.
    claims.iat = now - 30;
    val_token::<Claims>(&mut validator, &generator.token(&claims).unwrap(), &vec!["service01"]);
}

#[test]
fn validates_exp_is_before_current_time() {
    let now = Utc::now().timestamp();
    let mut claims = Claims::default();

    let generator = Generator::default();
    let mut validator = Validator::new(ValidatorOptions::default());

    // Validation should fail since `exp` is before current time.
    claims.exp = now - 30;
    match validator.decode::<Claims>(&generator.token(&claims).unwrap(), &vec!["service01"]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert!(format!("{}", e).starts_with("Expired jwt signature"))
    }

    // Validation should fail since `exp` is after current time.
    claims.exp = now + 30;
    val_token::<Claims>(&mut validator, &generator.token(&claims).unwrap(), &vec!["service01"]);
}

#[test]
fn validates_if_max_lifespan_is_exceeded() {
    let now = Utc::now().timestamp();
    let generator = Generator::default();
    let mut claims = Claims::default();

    let mut validator_options = ValidatorOptions::default();
    validator_options.max_lifespan = Some(9_999_999_999); // Should clamp to hard limit
    let mut validator = Validator::new(validator_options);

    // Validation should succeed since `max_lifespan` is below hard limit.
    claims.iat = now;
    claims.exp = now + 60;
    val_token::<Claims>(&mut validator, &generator.token(&claims).unwrap(), &vec!["service01"]);

    // Validation should fail since `max_lifespan` is above hard limit.
    claims.iat = now;
    claims.exp = now + 3601;
    match validator.decode::<Claims>(&generator.token(&claims).unwrap(), &vec!["service01"]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Token contained a lifespan greater than the \
            `max_lifespan` (hard limit of 3600 seconds)")
    }
}

#[test]
fn validates_if_custom_max_lifespan_is_exceeded() {
    let now = Utc::now().timestamp();
    let generator = Generator::default();
    let mut claims = Claims::default();

    let mut validator_options = ValidatorOptions::default();
    validator_options.max_lifespan = Some(60);
    let mut validator = Validator::new(validator_options);

    // Validation should succeed since `max_lifespan` is below custom limit.
    claims.iat = now;
    claims.exp = now + 30;
    val_token::<Claims>(&mut validator, &generator.token(&claims).unwrap(), &vec!["service01"]);

    // Validation should fail since `max_lifespan` is above custom limit.
    claims.iat = now;
    claims.exp = now + 120;
    match validator.decode::<Claims>(&generator.token(&claims).unwrap(), &vec!["service01"]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Token contained a lifespan greater than the \
            `max_lifespan` (hard limit of 3600 seconds)")
    }
}

#[test]
fn validates_if_encounters_unrecognized_audience() {
    let generator = Generator::default();
    let mut validator = Validator::new(ValidatorOptions::default());
    let mut claims = Claims::default();

    // Should succeed since `Claims::default().aud = "resource_server_audience"`.
    val_token::<Claims>(&mut validator, &gen_token(&generator, &claims), &vec!["service01"]);

    // Should fail since audience does not match resource server's audience.
    claims.aud = String::from("some-other-audience");
    match validator.decode::<Claims>(&gen_token(&generator, &claims), &vec!["service01"]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Resource server audience not found in `aud` claims of \
            token [\"some-other-audience\"]")
    }
}

#[test]
fn validates_if_encounters_unrecognized_audience_as_vec() {
    let now = Utc::now().timestamp();
    let generator = Generator::default();
    let mut validator = Validator::new(ValidatorOptions::default());

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct ClaimsWithAUDAsVec {
        aud: Vec<String>,
        iss: String,
        exp: i64,
        iat: i64,
        jti: String
    }

    let mut claims = ClaimsWithAUDAsVec {
        iss: String::from("service01"),
        exp: now + 60,
        iat: now,
        aud: vec![], // explicitly set later
        jti: String::from("foobar")
    };

    // Should succeed since claims vec contains `"resource_server_audience"`.
    claims.aud = vec![String::from("foo"), String::from("resource_server_audience")];
    let token = generator.token(&claims).unwrap();
    val_token::<ClaimsWithAUDAsVec>(&mut validator, &token, &vec!["service01"]);

    // Should fail since audience does not contain resource server's audience.
    claims.aud = vec![String::from("foo"), String::from("bar")];
    let token = generator.token(&claims).unwrap();
    match validator.decode::<ClaimsWithAUDAsVec>(&token, &vec!["service01"]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Resource server audience not found in `aud` claims of \
            token [\"foo\", \"bar\"]")
    }
}

#[test]
fn validates_if_encounters_unauthorized_subject() {
    let generator = Generator::default();
    let mut validator = Validator::new(ValidatorOptions::default());
    let mut claims = Claims::default();

    // Should succeed since `Claims::default().iss = "service01"`.
    val_token::<Claims>(&mut validator, &gen_token(&generator, &claims), &vec!["service01"]);

    // Should fail since `iss` is now not found in `authorized_subjects`.
    claims.iss = String::from("service01");
    match validator.decode::<Claims>(&gen_token(&generator, &claims), &vec!["service02"]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Unknown or unauthorized subject \"service01\". \
            The `sub` claim (or `iss`) must exist in `authorized_subjects` [\"service02\"]")
    }
}

#[test]
fn iss_is_assumed_if_sub_is_undefined() {
    let expected_subject = "my-client-service";

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct ClaimsWithSUB {
        iss: String,
        sub: String,
        exp: i64,
        iat: i64,
        aud: String,
        jti: String
    }

    let now = Utc::now().timestamp();
    let claims_with_sub = ClaimsWithSUB {
        iss: String::from("service01"),
        sub: String::from(expected_subject),
        exp: now + 60,
        iat: now,
        aud: String::from("resource_server_audience"),
        jti: String::from("foobar")
    };
    let claims_without_sub = Claims::default();

    let generator = Generator::default();
    let mut validator = Validator::new(ValidatorOptions::default());

    let token_with_sub = generator.token(&claims_with_sub).unwrap();
    let token_without_sub = gen_token(&generator, &claims_without_sub);

    // Look for tokens with the following subjects only.
    let expected_subjects = vec![expected_subject];

    // Validation should succeed with `sub` defined.
    val_token::<ClaimsWithSUB>(&mut validator, &token_with_sub, &expected_subjects);

    // Validation should fail without it (since `iss` is assumed).
    match validator.decode::<Claims>(&token_without_sub, &expected_subjects) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Unknown or unauthorized subject \"service01\". \
            The `sub` claim (or `iss`) must exist in `authorized_subjects` [\"my-client-service\"]")
    }
}

#[test]
fn validates_kid_is_owned_by_isser() {
    let generator = Generator::default();
    let mut validator = Validator::new(ValidatorOptions::default());
    let mut claims = Claims::default();

    // Default implementations should pass because:
    // - `generator::default()` has `kid = "service01/..."`
    // - `claims::default()`    has `iss = "service01"
    val_token::<Claims>(&mut validator, &gen_token(&generator, &claims), &vec!["service01"]);

    // This should fail since now `kid` does not start with `$iss/`.
    claims.iss = String::from("service02");
    match validator.decode::<Claims>(&gen_token(&generator, &claims), &vec!["service01"]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "JWT header did not contain a valid `kid` claim. \
            As per ASAP spec, the `kid` claim must start with \"$iss/\" where $iss is the issuer \
            (kid: \"service01/1530402390-public.der\", iss: \"service02\")")
    }
}

#[test]
fn it_rejects_duplicate_jti_claims() {
    let mut claims = Claims::default();
    let mut validator_options = ValidatorOptions::default();

    // Enable duplicate `jti` detection:
    validator_options.validate_jti = true;
    claims.jti = String::from("first-nonce");

    let generator = Generator::default();
    let mut validator = Validator::new(validator_options);

    // First token (first `jti` seen) should be successful.
    val_token::<Claims>(&mut validator, &gen_token(&generator, &claims), &vec!["service01"]);
    // Second token should fail (same `jti`).
    match validator.decode::<Claims>(&gen_token(&generator, &claims), &vec!["service01"]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Duplicate `jti` encountered: \"first-nonce\"")
    }
    // Third token (different `jti`) should be successful.
    claims.jti = String::from("second-nonce");
    val_token::<Claims>(&mut validator, &gen_token(&generator, &claims), &vec!["service01"]);
}

#[test]
fn it_fails_with_wrong_public_key() {
    let claims = Claims::default();
    let mut generator = Generator::default();

    // Give the wrong `kid` for the `private_key` used.
    generator.kid = String::from(KID_02);
    let mut validator = Validator::new(ValidatorOptions::default());

    match validator.decode::<Claims>(&gen_token(&generator, &claims), &vec!["service01"]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Invalid signature")
    }
}

#[test]
fn it_fails_with_wrong_private_key() {
    let claims = Claims::default();
    let mut generator = Generator::default();

    // Give the wrong `private_key` for the `kid` used.
    generator.private_key = PRIVATE_KEY_02.to_vec();
    let mut validator = Validator::new(ValidatorOptions::default());

    match validator.decode::<Claims>(&gen_token(&generator, &claims), &vec!["service01"]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Invalid signature")
    }
}

#[test]
fn it_fails_with_no_public_key() {
    let claims = Claims::default();
    let mut generator = Generator::default();

    // Give the wrong `kid` for the private key used.
    generator.kid = String::from("not-a-kid");
    let mut validator = Validator::new(ValidatorOptions::default());

    match validator.decode::<Claims>(&gen_token(&generator, &claims), &vec!["service01"]) {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Failed to retrieve public key from keyserver: NotFound")
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

    let token = gen_token(&generator, &claims);
    let authorized_subjects = vec!["service01"];
    let token_data = val_token(&mut validator, &token, &authorized_subjects);
    assert_eq!(claims, token_data.claims);
}

#[test]
fn it_fetches_key_from_cache() {
    // Reset keyserver count to 0.
    ks_reset();

    let claims = Claims::default();
    let generator = Generator::default();
    let mut validator = Validator::new(ValidatorOptions::default());

    // Requesting the same `kid_01` twice should only result in 1 request.
    val_token::<Claims>(&mut validator, &gen_token(&generator, &claims), &vec!["service01"]);
    assert_eq!(ks_count(), "1");
    val_token::<Claims>(&mut validator, &gen_token(&generator, &claims), &vec!["service01"]);
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
    val_token::<Claims>(&mut validator, &gen_token(&generator, &claims), &vec!["service01"]);
    assert_eq!(ks_count(), "1");
    val_token::<Claims>(&mut validator, &gen_token(&generator, &claims), &vec!["service01"]);
    assert_eq!(ks_count(), "2");
}

/**
 * Benchmarks.
 */

#[bench]
fn speed_of_generating_tokens(b: &mut Bencher) {
    let claims = Claims::default();
    let generator = Generator::default();
    b.iter(|| generator.token(&claims).unwrap());
}

#[bench]
fn speed_of_generating_tokens_with_validation(b: &mut Bencher) {
    let claims = Claims::default();
    let mut generator = Generator::default();
    generator.validate_claims = true;
    b.iter(|| generator.token(&claims).unwrap());
}

#[bench]
fn speed_of_validating_tokens(b: &mut Bencher) {
    let claims = Claims::default();
    let generator = Generator::default();
    let token = generator.token(&claims).unwrap();

    let mut validator = Validator::new(ValidatorOptions::default());

    // Validate once to cache the public key:
    validator.decode::<Claims>(&token, &vec!["service01"]).unwrap();
    b.iter(|| validator.decode::<Claims>(&token, &vec!["service01"]).unwrap());
}

#[bench]
fn speed_of_validating_tokens_without_asap(b: &mut Bencher) {
    let claims = Claims::default();
    let generator = Generator::default();
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
    let generator = Generator::default();
    let token = generator.token(&claims).unwrap();

    let mut validator = Validator::new(ValidatorOptions::default());
    b.iter(|| validator.dangerous_unsafe_decode::<Claims>(&token).unwrap());
}
