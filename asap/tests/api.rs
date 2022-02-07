extern crate asap;
extern crate asap_deps_keyserver as keyserver;
extern crate base64;
extern crate chrono;
extern crate jsonwebtoken as jwt;
extern crate reqwest;
extern crate serde;
#[macro_use]
extern crate serde_json;

use crate::jwt::TokenData;
use crate::keyserver::Keyserver;
use chrono::Utc;
use std::collections::HashMap;
use std::env;
use std::thread;
use std::time::Duration;

use asap::claims::{Aud, Claims, ExtraClaims, DEFAULT_TOKEN_LIFESPAN, REQUIRED_CLAIMS};
use asap::generator::Generator;
use asap::validator::{Validator, ValidatorBuilder};

// A private key to use to sign the tokens.
const PRIVATE_KEY_01: &[u8] = include_bytes!("../support/keys/service01/1530402390-private.der");
// The issuer of the service generating the token.
const ISS_01: &str = "service01";
const ISS_02: &str = "service02";
// The path of the public key in the keyserver.
const KID_01: &str = "service01/1530402390-public.der";
const KID_02: &str = "service02/1530402393-public.der";

fn get_validator_builder(keyserver_url: &str) -> ValidatorBuilder {
    let resource_server_audience = String::from(ISS_01);
    Validator::builder(String::from(keyserver_url), resource_server_audience)
}

fn mock_claims() -> Claims {
    Claims {
        aud: Aud::One(ISS_01.to_string()),
        iss: ISS_01.to_string(),
        jti: "some-random-jti".to_string(),
        iat: Utc::now().timestamp(),
        exp: Utc::now().timestamp() + 60,
        extra_claims: None,
    }
}

fn mock_extra_claims() -> Option<ExtraClaims> {
    let mut extra_claims = HashMap::new();
    extra_claims.insert("object".to_string(), json!({ "one": ["two", "three"] }));
    extra_claims.insert("number".to_string(), json!(123));
    extra_claims.insert("string".to_string(), json!("one two three"));
    extra_claims.insert("array".to_string(), json!(["one", "two", "three"]));
    extra_claims.insert("bool".to_string(), json!(true));
    extra_claims.insert("null".to_string(), json!(null));

    Some(extra_claims)
}

fn default_aud() -> Aud {
    Aud::One(ISS_01.to_string())
}

fn default_generator() -> Generator {
    Generator::new(
        ISS_01.to_string(),
        KID_01.to_string(),
        PRIVATE_KEY_01.to_vec(),
    )
}

fn validate_claims(
    token_data: TokenData<Claims>,
    expected_aud: Aud,
    extra_claims: Option<ExtraClaims>,
) {
    let now = Utc::now().timestamp();
    assert_eq!(token_data.claims.aud, expected_aud);
    assert_eq!(&token_data.claims.iss, ISS_01);
    assert_eq!(token_data.claims.jti.len(), 20);
    assert_eq!(
        token_data.claims.exp - token_data.claims.iat,
        DEFAULT_TOKEN_LIFESPAN
    );
    assert!(token_data.claims.iat > now - 2 && token_data.claims.iat < now + 2);
    assert_eq!(token_data.claims.extra_claims, extra_claims);
}

fn setup_env(keyserver: &Keyserver) {
    // Setup environment for the validator.
    env::set_var("ASAP_SERVER_AUDIENCE", ISS_01);
    env::set_var("ASAP_KEYSERVER_URL", keyserver.url());
    env::set_var("ASAP_FALLBACK_KEYSERVER_URL", keyserver.url());
    // Setup environment for the generator.
    env::set_var("ASAP_KEY_ID", KID_01);
    env::set_var("ASAP_ISSUER", ISS_01);
    env::set_var(
        "ASAP_PRIVATE_KEY",
        include_str!("../support/keys/service01/1530402390-private.pem"),
    );
}

fn teardown_env() {
    // Tear down environment.
    env::remove_var("ASAP_SERVER_AUDIENCE");
    env::remove_var("ASAP_KEYSERVER_URL");
    env::remove_var("ASAP_FALLBACK_KEYSERVER_URL");
    env::remove_var("ASAP_KEY_ID");
    env::remove_var("ASAP_ISSUER");
    env::remove_var("ASAP_PRIVATE_KEY");
}

/**
 * Tests.
 *
 * Each test that needs a keyserver starts up a new one on an available port.
 * That means they can be run in parallel.
 */

#[tokio::test]
async fn keyserver_works() {
    // Count should start at 0.
    let keyserver = Keyserver::start();
    assert_eq!(keyserver.count().await, "0");

    // Make 100 requests.
    for _ in 0..100 {
        reqwest::get(&format!("{}{}", keyserver.url(), KID_01))
            .await
            .unwrap();
    }
    assert_eq!(keyserver.count().await, "100");
}

#[tokio::test]
async fn it_works() {
    let keyserver = Keyserver::start();
    let generator = default_generator();
    let validator = get_validator_builder(keyserver.url()).build();

    // Test with no extra claims.
    let token = generator.token(default_aud(), None).unwrap();
    let token_data = validator.decode(&token, &[ISS_01]).await.unwrap();
    validate_claims(token_data, default_aud(), None);

    // Test with extra claims.
    let token = generator.token(default_aud(), mock_extra_claims()).unwrap();
    let token_data = validator.decode(&token, &[ISS_01]).await.unwrap();
    validate_claims(token_data, default_aud(), mock_extra_claims());
}

#[tokio::test]
async fn instantiates_from_environment() {
    let keyserver = Keyserver::start();

    // Stand from env
    {
        setup_env(&keyserver);
        let generator = Generator::from_env().unwrap();
        let validator = Validator::from_env().unwrap().build();
        let token = generator.token(default_aud(), mock_extra_claims()).unwrap();
        let token_data = validator.decode(&token, &[ISS_01]).await.unwrap();
        validate_claims(token_data, default_aud(), mock_extra_claims());
        teardown_env()
    }

    // Test that it uses the fallback keyserver
    {
        setup_env(&keyserver);
        env::set_var(
            "ASAP_KEYSERVER_URL",
            "http://not-a-real-server/".to_string(),
        );
        let generator = Generator::from_env().unwrap();
        let validator = Validator::from_env().unwrap().build();
        let token = generator.token(default_aud(), mock_extra_claims()).unwrap();
        let token_data = validator.decode(&token, &[ISS_01]).await.unwrap();
        validate_claims(token_data, default_aud(), mock_extra_claims());
        teardown_env()
    }
}

#[tokio::test]
async fn validates_nbf_is_after_current_time() {
    let keyserver = Keyserver::start();

    let now = Utc::now().timestamp();
    let generator = default_generator();
    let validator = get_validator_builder(keyserver.url()).build();

    // Validation should fail since `nbf` is after current time.
    {
        let mut extra_claims = HashMap::new();
        extra_claims.insert("nbf".to_string(), json!(now + 30));

        let token = generator.token(default_aud(), Some(extra_claims)).unwrap();
        match validator.decode(&token, &[ISS_01]).await {
            Ok(_) => panic!("Validation should fail."),
            Err(e) => assert!(format!("{}", e).starts_with("Immature jwt signature")),
        }
    }

    // Validation should succeed since `nbf` is before current time.
    {
        let mut extra_claims = HashMap::new();
        extra_claims.insert("nbf".to_string(), json!(now - 30));
        let token = generator.token(default_aud(), Some(extra_claims)).unwrap();
        let _ = validator.decode(&token, &[ISS_01]).await.unwrap();
    }
}

#[tokio::test]
async fn validates_exp_is_before_current_time() {
    let keyserver = Keyserver::start();
    let generator = default_generator();
    let validator = get_validator_builder(keyserver.url()).build();

    // Generate a token which expires in one second, then wait two before validating.
    generator.set_max_lifespan(1);
    let token = generator.token(default_aud(), None).unwrap();
    thread::sleep(Duration::from_secs(2));

    // Validation should fail since `exp` is before current time.
    match validator.decode(&token, &[ISS_01]).await {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert!(format!("{}", e).starts_with("Expired jwt signature")),
    }
}

#[tokio::test]
async fn validates_if_max_lifespan_is_exceeded() {
    let keyserver = Keyserver::start();
    let generator = default_generator();
    let validator = get_validator_builder(keyserver.url()).build();

    // Validation should succeed since `max_lifespan` is below default hard limit.
    let token = generator.token(default_aud(), None).unwrap();
    let _ = validator.decode(&token, &[ISS_01]).await.unwrap();

    // Validation should fail since `max_lifespan` is above hard limit.
    generator.set_max_lifespan(3601);
    let token = generator.token(default_aud(), None).unwrap();
    match validator.decode(&token, &[ISS_01]).await {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(
            format!("{}", e),
            "Token contained a lifespan greater than the \
             `max_lifespan` (hard limit of 3600 seconds)"
        ),
    }
}

#[tokio::test]
async fn validates_if_custom_max_lifespan_is_exceeded() {
    let keyserver = Keyserver::start();
    let generator = default_generator();
    let validator = get_validator_builder(keyserver.url())
        .max_lifespan(60)
        .build();

    // Validation should succeed since `max_lifespan` is below custom limit.
    generator.set_max_lifespan(30);
    let token = generator.token(default_aud(), None).unwrap();
    let _ = validator.decode(&token, &[ISS_01]).await.unwrap();

    // Validation should fail since `max_lifespan` is above custom limit.
    generator.set_max_lifespan(120);
    let token = generator.token(default_aud(), None).unwrap();
    match validator.decode(&token, &[ISS_01]).await {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(
            format!("{}", e),
            "Token contained a lifespan greater than the \
             `max_lifespan` (hard limit of 3600 seconds)"
        ),
    }
}

#[tokio::test]
async fn validates_if_encounters_unrecognized_audience() {
    let keyserver = Keyserver::start();
    let generator = default_generator();
    let validator = get_validator_builder(keyserver.url()).build();

    // Should succeed since `Claims::default().aud = ISS_01`.
    let token = generator.token(default_aud(), None).unwrap();
    let _ = validator.decode(&token, &[ISS_01]).await.unwrap();

    // Should fail since audience does not match resource server's audience.
    let aud = Aud::One("not-whitelisted".to_string());
    let token = generator.token(aud, None).unwrap();
    match validator.decode(&token, &[ISS_01]).await {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(
            format!("{}", e),
            "Resource server audience not found in `aud` claims of \
             token [\"not-whitelisted\"]"
        ),
    }
}

#[tokio::test]
async fn works_with_aud_as_vec() {
    let keyserver = Keyserver::start();
    let generator = default_generator();
    let validator = get_validator_builder(keyserver.url()).build();

    // Should succeed since claims vec contains `ISS_01`.
    let aud = Aud::Many(vec!["foo".to_string(), ISS_01.to_string()]);
    let token = generator.token(aud, None).unwrap();
    let _ = validator.decode(&token, &[ISS_01]).await.unwrap();

    // Should fail since audience does not contain `ISS_01`.
    let aud = Aud::Many(vec!["foo".to_string(), "bar".to_string()]);
    let token = generator.token(aud, None).unwrap();
    match validator.decode(&token, &[ISS_01]).await {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(
            format!("{}", e),
            "Resource server audience not found in `aud` claims of \
             token [\"foo\", \"bar\"]"
        ),
    }
}

#[tokio::test]
async fn works_with_aud_as_string() {
    let keyserver = Keyserver::start();
    let generator = default_generator();
    let validator = get_validator_builder(keyserver.url()).build();

    // Should succeed since whitelisted_issuers contains `ISS_01`.
    let token = generator.token(default_aud(), None).unwrap();
    let _ = validator.decode(&token, &[ISS_01]).await.unwrap();

    // Should fail since whitelisted_issuers doesn't contain `ISS_01`.
    let token = generator.token(default_aud(), None).unwrap();
    match validator.decode(&token, &["foobar"]).await {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(
            format!("{}", e),
            "Unknown or unauthorized subject \"service01\". The `sub` \
             claim (or `iss`) must exist in `whitelisted_issuers` [\"foobar\"]"
        ),
    }
}

#[tokio::test]
async fn iss_is_assumed_if_sub_is_undefined() {
    let keyserver = Keyserver::start();

    let mut extra_claims = HashMap::new();
    extra_claims.insert("sub".to_string(), json!(ISS_02));

    let generator = default_generator();
    let validator = get_validator_builder(keyserver.url()).build();

    let token_with_sub = generator.token(default_aud(), Some(extra_claims)).unwrap();
    let token_no_sub = generator.token(default_aud(), None).unwrap();

    // Look for tokens with the following subjects only.
    let whitelisted_issuers = vec![ISS_02];

    // Validation should succeed with `sub` defined (`ISS_02`).
    let _ = validator
        .decode(&token_with_sub, &whitelisted_issuers)
        .await
        .unwrap();

    // Validation should fail without it (since `iss` is assumed).
    match validator.decode(&token_no_sub, &whitelisted_issuers).await {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(
            format!("{}", e),
            "Unknown or unauthorized subject \"service01\". \
             The `sub` claim (or `iss`) must exist in `whitelisted_issuers` [\"service02\"]"
        ),
    }
}

#[tokio::test]
async fn validates_kid_is_owned_by_isser() {
    let keyserver = Keyserver::start();
    let validator = get_validator_builder(keyserver.url()).build();

    // Default implementations should pass because:
    // - `default_generator()` has `iss = "service01"` and `kid = "service01/..."`
    let generator = default_generator();
    let token = generator.token(default_aud(), None).unwrap();
    let _ = validator.decode(&token, &[ISS_01]).await.unwrap();

    // This should fail since now `kid` does not start with `$iss/`.
    let generator = Generator::new(
        ISS_02.to_string(),
        KID_01.to_string(),
        PRIVATE_KEY_01.to_vec(),
    );
    let token = generator.token(default_aud(), None).unwrap();
    match validator.decode(&token, &[ISS_01]).await {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(
            format!("{}", e),
            "JWT header did not contain a valid `kid` claim. \
            As per ASAP spec, the `kid` claim must start with \"$iss/\" where $iss is the issuer \
            (kid: \"service01/1530402390-public.der\", iss: \"service02\")"
        ),
    }
}

#[tokio::test]
async fn it_rejects_duplicate_jti_claims() {
    let keyserver = Keyserver::start();
    let generator = default_generator();

    // Enable duplicate `jti` detection:
    let validator = get_validator_builder(keyserver.url())
        .validate_jti(true)
        .build();

    let token = generator.token(default_aud(), None).unwrap();

    // First token (first `jti` seen) should be successful.
    let _ = validator.decode(&token, &[ISS_01]).await.unwrap();

    // Reusing the same token should fail (same `jti`).
    match validator.decode(&token, &[ISS_01]).await {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert!(format!("{}", e).starts_with("Duplicate `jti` encountered: ")),
    }

    // A new token (different `jti`) should be successful.
    let token = generator.token(default_aud(), None).unwrap();
    let _ = validator.decode(&token, &[ISS_01]).await.unwrap();
}

#[tokio::test]
async fn it_fails_with_wrong_public_key() {
    let keyserver = Keyserver::start();
    // Give the wrong `kid` for the `private_key` used.
    let generator = Generator::new(
        ISS_01.to_string(),
        KID_02.to_string(),
        PRIVATE_KEY_01.to_vec(),
    );
    let validator = get_validator_builder(keyserver.url()).build();

    let token = generator.token(default_aud(), None).unwrap();
    match validator.decode(&token, &[ISS_01]).await {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "InvalidSignature"),
    }
}

#[tokio::test]
async fn it_fails_with_no_public_key() {
    let keyserver = Keyserver::start();
    let generator = Generator::new(
        ISS_01.to_string(),
        "not-a-kid".to_string(),
        PRIVATE_KEY_01.to_vec(),
    );
    let validator = get_validator_builder(keyserver.url()).build();

    let token = generator.token(default_aud(), None).unwrap();
    match validator.decode(&token, &[ISS_01]).await {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(format!("{}", e), "Failed to retrieve public key from keyserver: \"Failed to fetch a key from any keyserver\"")
    }
}

#[tokio::test]
async fn it_uses_the_fallback_keyserver() {
    let keyserver = Keyserver::start();
    let generator = default_generator();

    // Ensure the first keyserver fails.
    let invalid_keyserver = "http://not-a-real-server:1234/".to_string();
    let valid_keyserver = keyserver.url().to_string();
    let validator = Validator::builder(invalid_keyserver, ISS_01.to_string())
        .fallback_keyserver(valid_keyserver)
        .build();

    let token = generator.token(default_aud(), None).unwrap();
    let token_data = validator.decode(&token, &[ISS_01]).await.unwrap();
    validate_claims(token_data, default_aud(), None);
}

#[tokio::test]
async fn it_fetches_key_from_cache() {
    let server = Keyserver::start();

    let generator = default_generator();
    let validator = get_validator_builder(server.url()).build();
    let token = generator.token(default_aud(), None).unwrap();

    // Requesting the same `kid_01` twice should only result in 1 request.
    let _ = validator.decode(&token, &[ISS_01]).await.unwrap();
    assert_eq!(server.count().await, "1");
    let _ = validator.decode(&token, &[ISS_01]).await.unwrap();
    assert_eq!(server.count().await, "1");
}

#[tokio::test]
async fn it_does_not_fetch_expired_key_from_cache() {
    let server = Keyserver::start();

    let generator = default_generator();
    let token = generator.token(default_aud(), None).unwrap();

    // Make all tokens expire immediately.
    let validator = get_validator_builder(server.url())
        .cache_duration(Duration::from_nanos(0))
        .build();

    // The expired `kid_01` should be requested again = 2 requests.
    let _ = validator.decode(&token, &[ISS_01]).await.unwrap();
    assert_eq!(server.count().await, "1");
    let _ = validator.decode(&token, &[ISS_01]).await.unwrap();
    assert_eq!(server.count().await, "2");
}

#[tokio::test]
async fn it_allows_extra_claims() {
    let keyserver = Keyserver::start();
    let generator = default_generator();
    let validator = get_validator_builder(keyserver.url()).build();

    // Overwrite each of the required claims.
    let mut extra_claims = HashMap::new();
    extra_claims.insert("foo".to_string(), json!("foo"));
    extra_claims.insert("bar".to_string(), json!(1234));
    extra_claims.insert("baz".to_string(), json!(["baz", "bop"]));

    let token = generator.token(default_aud(), Some(extra_claims)).unwrap();
    let token_data = validator.decode(&token, &[ISS_01]).await.unwrap();

    let decoded_extra_claims = token_data.claims.extra_claims.unwrap();
    assert_eq!(decoded_extra_claims.get("foo").unwrap(), &json!("foo"));
    assert_eq!(decoded_extra_claims.get("bar").unwrap(), &json!(1234));
    assert_eq!(
        decoded_extra_claims.get("baz").unwrap(),
        &json!(["baz", "bop"])
    );
}

#[tokio::test]
async fn it_does_not_override_required_claims() {
    let keyserver = Keyserver::start();
    let generator = default_generator();
    let validator = get_validator_builder(keyserver.url()).build();

    // Overwrite each of the required claims.
    let mut extra_claims = HashMap::new();
    for key in &REQUIRED_CLAIMS {
        extra_claims.insert(key.to_string(), json!(key));
    }

    let token = generator.token(default_aud(), Some(extra_claims)).unwrap();
    let token_data = validator.decode(&token, &[ISS_01]).await.unwrap();

    // Test that none of the required claims were overridden.
    assert!(token_data.claims.aud != Aud::One("aud".to_string()));
    assert!(token_data.claims.iss != "iss");
    assert!(token_data.claims.jti != "jti");
    let now = Utc::now().timestamp();
    assert!(token_data.claims.iat > now - 2 && token_data.claims.iat < now + 2);
    assert_eq!(
        token_data.claims.exp - token_data.claims.iat,
        DEFAULT_TOKEN_LIFESPAN
    );
}

#[test]
fn it_caches_tokens_when_enabled() {
    let generator = default_generator();
    generator.enable_token_caching(10, ::std::time::Duration::from_millis(1000));

    let token_1 = generator.token(default_aud(), None).unwrap();
    let token_2 = generator.token(default_aud(), None).unwrap();
    assert_eq!(token_1, token_2);
}

#[test]
fn it_caches_tokens_with_extra_claims_when_enabled() {
    let generator = default_generator();
    generator.enable_token_caching(10, ::std::time::Duration::from_millis(1000));

    let mut extra_claims = HashMap::new();
    extra_claims.insert("foo".to_string(), json!("foo"));
    extra_claims.insert("bar".to_string(), json!(1234));
    extra_claims.insert("baz".to_string(), json!(["baz", "bop"]));

    let token_1 = generator
        .token(default_aud(), Some(extra_claims.clone()))
        .unwrap();
    let token_2 = generator
        .token(default_aud(), Some(extra_claims.clone()))
        .unwrap();
    assert_eq!(token_1, token_2);
}

#[test]
fn it_does_not_return_expired_cached_tokens() {
    let cache_duration = ::std::time::Duration::from_millis(100);

    let generator = default_generator();
    generator.enable_token_caching(10, cache_duration);

    let token_1 = generator.token(default_aud(), None).unwrap();
    ::std::thread::sleep(cache_duration);
    let token_2 = generator.token(default_aud(), None).unwrap();

    assert!(token_1 != token_2);
}

#[test]
fn it_regenerates_cached_tokens_when_they_are_different() {
    let generator = default_generator();
    generator.enable_token_caching(10, ::std::time::Duration::from_millis(1000));

    // Check different audience.
    let token_1 = generator.token(Aud::One(ISS_01.to_string()), None).unwrap();
    let token_2 = generator.token(Aud::One(ISS_02.to_string()), None).unwrap();
    assert!(token_1 != token_2);

    // Check different extra claims.
    let mut extra_claims_1 = HashMap::new();
    extra_claims_1.insert("foo".to_string(), json!("foo"));
    let mut extra_claims_2 = HashMap::new();
    extra_claims_2.insert("bar".to_string(), json!("bar"));

    let token_1 = generator
        .token(default_aud(), Some(extra_claims_1))
        .unwrap();
    let token_2 = generator
        .token(default_aud(), Some(extra_claims_2))
        .unwrap();
    assert!(token_1 != token_2);
}

#[tokio::test]
async fn it_rejects_unsigned_tokens() {
    // Manually create a JWT without a signature nor an "alg" in the header.
    let header = base64::encode(
        &serde_json::to_string(&json!({
            "typ": "JWT",
            "kid": KID_01.to_string()
        }))
        .unwrap(),
    );
    let body = base64::encode(&serde_json::to_string(&mock_claims()).unwrap());
    let token = header + "." + &body;

    let keyserver = Keyserver::start();
    let validator = get_validator_builder(keyserver.url()).build();

    // Validate without signature.
    match validator.decode(&token, &[ISS_01]).await {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!("InvalidToken", format!("{}", e)),
    }

    // Validate with empty signature.
    match validator.decode(&(token + "."), &[ISS_01]).await {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!(
            "JSON error: missing field `alg` at line 1 column 53",
            format!("{}", e)
        ),
    }
}

#[tokio::test]
async fn it_rejects_tokens_with_missing_signatures() {
    fn split_two(token: String) -> (String, String) {
        let mut i = token.rsplitn(2, '.');
        match (i.next(), i.next(), i.next()) {
            (Some(a), Some(b), None) => (a.to_string(), b.to_string()),
            _ => panic!("Unexpected split: {:?}", i),
        }
    }

    let mut header = jwt::Header::new(jwt::Algorithm::RS256);
    header.kid = Some(KID_01.to_string());

    // Remove signature from token.
    let token = jwt::encode(
        &header,
        &mock_claims(),
        &jwt::EncodingKey::from_rsa_der(&PRIVATE_KEY_01.to_vec()),
    )
    .unwrap();
    let (_signature, signing_input) = split_two(token);

    let keyserver = Keyserver::start();
    let validator = get_validator_builder(keyserver.url()).build();

    // Try to validate without signature.
    match validator.decode(&signing_input, &[ISS_01]).await {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!("InvalidToken", format!("{}", e)),
    }

    // Try to validate with an empty signature.
    match validator
        .decode(&(signing_input.to_string() + "."), &[ISS_01])
        .await
    {
        Ok(_) => panic!("Validation should fail."),
        Err(e) => assert_eq!("InvalidSignature", format!("{}", e)),
    }
}

#[tokio::test]
async fn it_rejects_tokens_signed_with_unsupported_alg() {
    let unsupported_algs = vec![
        (
            jwt::Algorithm::HS256,
            jwt::EncodingKey::from_secret(b"some-secret"),
        ),
        (
            jwt::Algorithm::HS384,
            jwt::EncodingKey::from_secret(b"some-secret"),
        ),
        (
            jwt::Algorithm::HS512,
            jwt::EncodingKey::from_secret(b"some-secret"),
        ),
        (
            jwt::Algorithm::RS384,
            jwt::EncodingKey::from_rsa_der(&PRIVATE_KEY_01.to_vec()),
        ),
        (
            jwt::Algorithm::RS512,
            jwt::EncodingKey::from_rsa_der(&PRIVATE_KEY_01.to_vec()),
        ),
    ];

    for (alg, key) in unsupported_algs {
        println!("{:?}", alg);
        let mut header = jwt::Header::new(alg);
        header.kid = Some(KID_01.to_string());

        let token = jwt::encode(&header, &mock_claims(), &key).unwrap();

        let keyserver = Keyserver::start();
        let validator = get_validator_builder(keyserver.url()).build();
        match validator.decode(&token, &[ISS_01]).await {
            Ok(_) => panic!("Validation should fail."),
            Err(e) => {
                let err_msg = format!("{}", e);
                assert_eq!(err_msg, "InvalidAlgorithm")
            }
        }
    }
}
