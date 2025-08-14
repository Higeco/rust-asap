//! This module contains everything you need in order to validate and verify
//! the authenticity of an incoming ASAP token.
//!
//! ```rust
//! # extern crate asap;
//! # extern crate serde;
//! # #[macro_use] extern crate serde_json;
//! #
//! # use asap::claims::Claims;
//! # use asap::validator::Validator;
//! #
//! # #[tokio::main]
//! # async fn main() {
//! #
//! # let asap_token = "<your-token-here>";
//! #
//! # // Construct the ASAP validator:
//! let keyserver = "http://my-keyserver/".to_string();
//! # let resource_server_audience = "my-server".to_string();
//! let validator = Validator::builder(keyserver, resource_server_audience)
//!     .fallback_keyserver("http://my-fallback-keyserver/".to_string())
//!     .build();
//!
//! match validator.decode(asap_token, &vec!["authorized", "subjects"]).await {
//!     Ok(token_data) => println!("claims {:?}", token_data.claims),
//!     Err(e) => eprintln!("error validation token/invalid token: {:?}", e)
//! }
//! # }
//! ```

use crate::jwt::{self, TokenData};
use chrono::Utc;
use serde_json::{from_str, to_string, Map, Value};
use std::cmp::max;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use crate::claims::Claims;
use crate::errors::{Result, ResultExt, ValidatorError};
use crate::keyserver::Keyserver;
use crate::util::{extract_aud_from_claims, extract_claim};

#[cfg(feature = "http-keyserver")]
use crate::keyserver::HttpKeyserver;

type PublicKeyCache = HashMap<String, (SystemTime, jwt::DecodingKey)>;

#[cfg(feature = "http-keyserver")]
pub type ValidatorBuilder = GenericValidatorBuilder<HttpKeyserver>;
#[cfg(feature = "http-keyserver")]
pub type Validator = GenericValidator<HttpKeyserver>;

/// The duration of how long the validator should cache public keys fetched
/// from the keyserver.
///
/// Defaults to 10 minutes.
pub const DEFAULT_CACHE_DURATION: Duration = Duration::from_secs(600);

/// The max lifespan of a token before it's considered expired.
///
/// Defaults to one hour (as per ASAP spec).
pub const DEFAULT_MAX_LIFESPAN: i64 = 60 * 60;

/// Options used to configure an ASAP Validator.
pub struct GenericValidatorBuilder<S: Keyserver> {
    /// The identifier of the resource server. Incoming ASAP tokens must include
    /// this identifier in their `aud` claim in order for the token to be valid.
    resource_server_audience: Option<String>,
    /// The keyserver to fetch the public keys from.
    keyserver: Option<S>,
    /// The algorithm to use to verify the tokens.
    ///
    /// If unset this defaults to RS256.
    jwt_algorithm: Option<jwt::Algorithm>,
    /// Since validating time fields is always a bit tricky due to clock skew,
    /// this field adds `leeway` to the `iat`, `exp` and `nbf` validation (which
    /// are measured in seconds).
    ///
    /// If unset this defaults to 0.
    leeway: Option<i64>,
    /// The max lifespan (difference between `exp` and `iat`) of the token in
    /// seconds. This defaults to one hour (as defined per spec) but you may set
    /// it to a lower value if desired.
    ///
    /// Setting to a value above one hour will have no effect (will default to one hour).
    max_lifespan: Option<i64>,
    /// Whether or not the validator should check for duplicate `jti` nonces.
    ///
    /// If this is set, then the validator will reject tokens who have a `jti`
    /// claim that the validator has seen before.
    validate_jti: bool,
    /// Whether or not the validator should check that the `kid` starts with
    /// `"$iss/"` where `$iss` is the issuer.
    ///
    /// Setting this to `true` is recommended.
    validate_kid: bool,
    /// The duration of how long the validator should cache public keys fetched
    /// from the keyserver.
    ///
    /// Defaults to 10 minutes.
    cache_duration: Option<Duration>,
}

#[cfg(feature = "http-keyserver")]
impl ValidatorBuilder {
    /// Creates a new `ValidatorBuilder`. Use this struct to easily construct
    /// a `Validator` with your chosen options.
    ///
    /// ```rust
    /// # use std::time::Duration;
    /// # use asap::validator::{Validator, ValidatorBuilder};
    ///
    /// let keyserver = "http://my-keyserver/".to_string();
    /// let resource_server_audience = "my-server".to_string();
    /// let validator = ValidatorBuilder::new(keyserver, resource_server_audience)
    ///     .leeway(5)
    ///     .max_lifespan(120)
    ///     .cache_duration(Duration::from_secs(300))
    ///     .validate_kid(true)
    ///     .validate_jti(true)
    ///     .fallback_keyserver("http://my-fallback-keyserver/".to_string())
    ///     .build();
    /// ```
    pub fn new(keyserver_url: String, resource_server_audience: String) -> ValidatorBuilder {
        let ks = HttpKeyserver::new(vec![keyserver_url]);
        GenericValidatorBuilder::with_keyserver(ks, resource_server_audience)
    }

    /// Adds a fallback keyserver for the `Validator`.
    /// These keyservers are tried in order until a key is successfully returned.
    ///
    /// ```rust
    /// # use asap::validator::{Validator, ValidatorBuilder};
    /// let primary_keyserver = "http://my-keyserver/".to_string();
    /// let fallback_keyserver = "http://my-fallback-keyserver/".to_string();
    ///
    /// let validator = Validator::builder(primary_keyserver, "my-server".to_string())
    ///     .fallback_keyserver(fallback_keyserver)
    ///     .build();
    /// ```
    pub fn fallback_keyserver(&mut self, keyserver: String) -> &mut ValidatorBuilder {
        self.keyserver.as_mut().unwrap().append_url(keyserver);
        self
    }
}

impl<S: Keyserver> GenericValidatorBuilder<S> {
    pub fn with_keyserver(keyserver: S, resource_server_audience: String) -> Self {
        GenericValidatorBuilder {
            resource_server_audience: Some(resource_server_audience),
            keyserver: Some(keyserver),

            jwt_algorithm: None,
            leeway: None,
            max_lifespan: None,
            validate_kid: true,
            validate_jti: false,
            cache_duration: None,
        }
    }

    /// Sets the `leeway` for the `Validator`.
    ///
    /// Defaults to `0`.
    pub fn leeway(&mut self, leeway: i64) -> &mut Self {
        self.leeway = Some(leeway);
        self
    }

    /// Sets the `max_lifespan` for the `Validator`.
    ///
    /// Note that while the ASAP spec defines a hard upper limit of `3600`
    /// seconds, some uses may require a higher limit (eg: when validating
    /// session tokens). You may use this to set a higher limit.
    ///
    /// Defaults to `3600` seconds.
    pub fn max_lifespan(&mut self, max_lifespan: i64) -> &mut Self {
        self.max_lifespan = Some(max_lifespan);
        self
    }

    /// Sets the `cache_duration` for the `Validator`.
    ///
    /// Defaults to `validator::DEFAULT_CACHE_DURATION`.
    pub fn cache_duration(&mut self, cache_duration: Duration) -> &mut Self {
        self.cache_duration = Some(cache_duration);
        self
    }

    /// Sets the `validate_kid` for the `Validator`.
    ///
    /// Defaults to `true`.
    pub fn validate_kid(&mut self, validate_kid: bool) -> &mut Self {
        self.validate_kid = validate_kid;
        self
    }

    /// Sets the `validate_jti` for the `Validator`.
    ///
    /// Defaults to `false`.
    pub fn validate_jti(&mut self, validate_jti: bool) -> &mut Self {
        self.validate_jti = validate_jti;
        self
    }

    pub fn algorithm(&mut self, algorithm: jwt::Algorithm) -> &mut Self {
        self.jwt_algorithm = Some(algorithm);
        self
    }

    /// Builds and returns a `Validator` with the configured options.
    pub fn build(&mut self) -> GenericValidator<S> {
        let alg = self.jwt_algorithm.take().unwrap_or(jwt::Algorithm::RS256);
        let mut jwt_validator = jwt::Validation::new(alg);
        jwt_validator.validate_aud = false;
        jwt_validator.validate_exp = false;
        jwt_validator.validate_nbf = false;
        jwt_validator.leeway = 0;
        jwt_validator.iss = None;
        jwt_validator.sub = None;
        jwt_validator.aud = None;

        GenericValidator {
            leeway: self.leeway.unwrap_or(0),
            max_lifespan: max(0, self.max_lifespan.unwrap_or(DEFAULT_MAX_LIFESPAN)),
            jwt_validator,

            keyserver: self.keyserver.take().unwrap(),
            resource_server_audience: self.resource_server_audience.take().unwrap(),

            validate_kid: self.validate_kid,
            validate_jti: self.validate_jti,
            jti_seen: Arc::new(RwLock::new(HashSet::new())),

            key_cache: Arc::new(RwLock::new(HashMap::new())),
            key_cache_duration: self.cache_duration.unwrap_or(DEFAULT_CACHE_DURATION),
        }
    }
}

/// An ASAP Validator.
///
/// Use this struct in your resource server to decode and validate incoming ASAP
/// tokens. You can use this to take care of validating the ASAP token according
/// [to the specification](https://s2sauth.bitbucket.io/spec/) (see the `decode`
/// method).
///
/// The `Validator` expects a  keyserver from which to retrieve public keys,
/// and can:
///
/// * check for duplicate `jti` nonces seen in requests by using
///     `ValidatorBuilder::validate_jti(true)`. This means that any token whose
///     `claims.jti` has been seen before will be rejected.
/// * set a `leeway` which is used in calculating the token's lifespan and
///     expiry. Use this if you need to account for internal clock drift between
///     clients/servers and you have short-lived tokens.
/// * cache public keys in order to speed up validation of tokens.
/// * set a shorter `max_lifespan` and reject tokens whose lifespan exceeds the
///     set limit.
///
/// ```rust
/// # extern crate asap;
/// # extern crate serde;
/// # #[macro_use] extern crate serde_json;
/// #
/// # use asap::claims::Claims;
/// # use asap::validator::Validator;
/// #
/// # #[tokio::main]
/// # async fn main() {
/// // Construct the ASAP validator:
/// let keyserver = "http://my-keyserver/".to_string();
/// let resource_server_audience = "my-server".to_string();
/// let validator = Validator::builder(keyserver, resource_server_audience)
///     .fallback_keyserver("http://my-fallback-keyserver/".to_string())
///     .build();
///
/// let asap_token = "<your-token-here>";
/// let whitelisted_issuers = vec!["list", "of", "whitelisted", "issuers"];
///
/// match validator.decode(asap_token, &whitelisted_issuers).await {
///     Ok(token_data) => {
///         // Here you have a successfully verified and accepted access token!
///         //
///         // Remember the directions from the ASAP spec:
///         // If the resource server successfully verifies and accepts the
///         // access token, then it MUST process the request and it MUST assume
///         // that the request was issued by the issuer.
///         println!("claims: {:?}", token_data.claims);
///
///         // If there were any extra claims in the token they will be stored
///         // in this `HashMap<String, serde_json::Value>`:
///         println!("extra claims: {:?}", token_data.claims.extra_claims);
///     },
///     Err(e) => {
///         // Oh boo, there was an error decoding and validating the ASAP token.
///         //
///         // Remember the directions from the ASAP spec:
///         // If the resource server rejects the access token, then it MUST
///         // reply with a status code of 401 UNAUTHORIZED and MUST include a
///         // WWW-Authenticate header field as per the HTTP specification.
///         eprintln!("{:?}", e);
///     }
/// }
/// # }
/// ```
pub struct GenericValidator<S: Keyserver> {
    /// Whether or not the validator should check for duplicate `jti` nonces.
    pub validate_jti: bool,
    /// Whether or not the validator should check that the `kid` starts with
    /// `"$iss/"` where `$iss` is the issuer.
    pub validate_kid: bool,
    /// The actual jwt validator (from the `jsonwebtoken` crate). This is used
    /// to decode the token and verify its signature.
    jwt_validator: jwt::Validation,
    /// The identifier of the resource server. Incoming ASAP tokens must include
    /// this identifier in their `aud` claim in order for the token to be valid.
    resource_server_audience: String,
    /// Since validating time fields is always a bit tricky due to clock skew,
    /// this field (measured in seconds) adds `leeway` to the `iat`, `exp` and
    /// `nbf` validation.
    leeway: i64,
    /// The max lifespan of the token (the difference between `exp` and `iat`).
    /// The ASAP spec defines a hard upper limit of one hour.
    max_lifespan: i64,
    /// The keyserver used to fetch public keys.
    keyserver: S,
    /// A hash-map used to store and check seen `jti` nonces.
    jti_seen: Arc<RwLock<HashSet<String>>>,
    /// A hash-map used for simple key-caching.
    key_cache: Arc<RwLock<PublicKeyCache>>,
    /// The duration each cached key is valid before it's fetched again.
    key_cache_duration: Duration,
}

#[cfg(feature = "http-keyserver")]
impl Validator {
    /// Creates a builder that can be used to construct a `Validator`.
    ///
    /// ```rust
    /// # use std::time::Duration;
    /// # use asap::validator::Validator;
    ///
    /// let keyserver = "http://my-keyserver/".to_string();
    /// let fallback_keyserver = "http://my-fallback-keyserver/".to_string();
    /// let resource_server_audience = "my-server".to_string();
    ///
    /// let validator = Validator::builder(keyserver, resource_server_audience)
    ///     .leeway(5)
    ///     .max_lifespan(120)
    ///     .validate_kid(true)
    ///     .validate_jti(true)
    ///     .cache_duration(Duration::from_secs(300))
    ///     .fallback_keyserver(fallback_keyserver)
    ///     .build();
    /// ```
    pub fn builder(keyserver: String, resource_server_audience: String) -> ValidatorBuilder {
        ValidatorBuilder::new(keyserver, resource_server_audience)
    }

    /// Instantiates a validator builder from the environment. Requires that the
    /// following environment variables be defined:
    ///
    /// * `"ASAP_SERVER_AUDIENCE"`: the resource identifier of the validator
    /// * `"ASAP_KEYSERVER_URL"`: the URL of the keyserver, must end in a "/".
    /// * `"ASAP_FALLBACK_KEYSERVER_URL"`: the URL of the fallback keyserver, must
    ///     end in a "/".
    ///
    /// ```rust
    /// use std::env;
    /// use asap::validator::Validator;
    ///
    /// env::set_var("ASAP_SERVER_AUDIENCE", "resource_server_audience");
    /// env::set_var("ASAP_KEYSERVER_URL", "http://keyserver.net/");
    /// env::set_var("ASAP_FALLBACK_KEYSERVER_URL", "http://fallback-keyserver.net/");
    ///
    /// let validator = Validator::from_env().unwrap().build();
    /// ```
    pub fn from_env() -> Result<ValidatorBuilder> {
        let get_env_var = |x| {
            std::env::var(x)
                .map_err(|_| format_err!("Could not find '{:?}' environment variable", x))
        };

        let keyserver_url = get_env_var("ASAP_KEYSERVER_URL")?;
        let fallback_keyserver_url = get_env_var("ASAP_FALLBACK_KEYSERVER_URL")?;
        let resource_server_audience = get_env_var("ASAP_SERVER_AUDIENCE")?;

        let mut vb = ValidatorBuilder::new(keyserver_url, resource_server_audience);

        {
            vb.fallback_keyserver(fallback_keyserver_url);
        }

        Ok(vb)
    }
}

impl<S: Keyserver> GenericValidator<S> {
    // Retrieves the public key for `kid`, checking the cache and then fetching
    // the key from the keyserver if the key isn't cached.
    async fn get_public_key(&self, kid: &str) -> Result<jwt::DecodingKey> {
        // Fetch key from cache if there's a key.
        {
            let mut key_cache = self
                .key_cache
                .write()
                .expect("failed to acquire lock on public key cache");
            if key_cache.contains_key(kid) {
                // Extra scope here since `self.get_key_from_cache` borrows the
                // internal cache mutably. We won't be able to remove anything from
                // the cache if this ref is still alive.
                {
                    let cached_key =
                        get_key_from_cache(&mut key_cache, self.key_cache_duration, kid);
                    if cached_key.is_ok() {
                        return cached_key;
                    }
                    eprintln!(
                        "Error fetching from cache, reason: {}. \
                     Trying keyserver...",
                        cached_key.err().unwrap()
                    );
                }
                // If there was any error fetching the key from the cache, just
                // remove the entry from cache.
                key_cache.remove(kid);
            }
        }

        // Otherwise, fetch the public key from the keyserver(s).
        if let Ok(key) = self.keyserver.get_public_key(kid).await {
            return Ok(key);
        }

        Err(
            ValidatorError::KeyserverError("Failed to fetch a key from any keyserver".to_string())
                .into(),
        )
    }

    /// Decodes and validates the given token, returning both its claims and
    /// header.
    ///
    /// This method will take care of ensuring your incoming ASAP token is valid
    /// according [to the specification](https://s2sauth.bitbucket.io/spec/).
    /// This includes validation of:
    /// - mandatory claims: `iss`, `exp`, `iat`, `aud` and `jti`
    /// - a valid and well-formed `kid` in the jwt header
    /// - the token's lifespan (`nbf`, `iat` and `exp` checks)
    /// - the `aud` matching/containing `resource_server_audience`
    /// - the issuer/subject having authorisation (via `whitelisted_issuers`)
    ///
    /// ```rust
    /// # extern crate asap;
    /// # extern crate serde;
    /// # #[macro_use] extern crate serde_json;
    /// #
    /// # use asap::claims::Claims;
    /// # use asap::validator::Validator;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// // Construct the ASAP validator:
    /// let primary_keyserver = "http://my-keyserver/".to_string();
    /// let fallback_keyserver = "http://my-fallback-keyserver/".to_string();
    /// let resource_server_audience = "my-server".to_string();
    /// let validator = Validator::builder(primary_keyserver, resource_server_audience)
    ///     .fallback_keyserver(fallback_keyserver)
    ///     .build();
    ///
    /// let asap_token = "<your-token-here>";
    /// let whitelisted_issuers = vec!["list", "of", "whitelisted", "issuers"];
    ///
    /// match validator.decode(asap_token, &whitelisted_issuers).await {
    ///     Ok(token_data) => {
    ///         // Token is a valid ASAP token and is authorised.
    ///         println!("header: {:?}", token_data.header);
    ///         println!("claims: {:?}", token_data.claims);
    ///         println!("extra_claims: {:?}", token_data.claims.extra_claims);
    ///     },
    ///     // Errors may include:
    ///     //  - invalid token or signature
    ///     //  - the token was not ASAP compliant
    ///     //  - the public key could not be retreived
    ///     Err(e) => eprintln!("{:?}", e)
    /// }
    /// # }
    /// ```
    pub async fn decode(
        &self,
        token: &str,
        whitelisted_issuers: &[&str],
    ) -> Result<TokenData<Claims>> {
        self.decode_optwl(token, Some(whitelisted_issuers)).await
    }

    pub async fn decode_without_whitelist(&self, token: &str) -> Result<TokenData<Claims>> {
        self.decode_optwl(token, None).await
    }

    async fn decode_optwl(
        &self,
        token: &str,
        whitelisted_issuers: Option<&[&str]>,
    ) -> Result<TokenData<Claims>> {
        // First, decode the header.
        let header = jwt::decode_header(token).sync()?;

        // Extract `kid` (the public key id) from jwt header.
        let kid = header
            .kid
            .clone()
            .ok_or(ValidatorError::NoKIDFound(header))?;

        // Retreive the public key (from cache or the keyserver).
        let public_key = self.get_public_key(&kid).await?;

        // Decode the token (this also validates its signature).
        let data = jwt::decode::<Claims>(token, &public_key, &self.jwt_validator).sync()?;

        // Ensure the token is valid (according to the ASAP specification).
        //
        // HACK: at the moment we're doing this messy serialise-deserialise hack
        // since `jsonwebtoken` doesn't provide us with a way of obtaining a
        // `Map<String, Value>` of the claims struct.
        // Benchmarks show that this has no noticible performance impact.
        //
        // See: https://github.com/Keats/jsonwebtoken/issues/53
        self.validate(
            &kid,
            &from_str(&to_string(&data.claims)?)?,
            whitelisted_issuers,
        )?;

        // If everything looks good, and the key is not yet cached, then store
        // the public key in the cache.
        self.key_cache
            .write()
            .expect("failed to acquire lock on public key cache")
            .entry(kid)
            .or_insert((SystemTime::now(), public_key));

        // Return the decoded token.
        Ok(data)
    }

    // Validates the JWT token as per the ASAP specification.
    // The following claims are mandatory: `iss`, `exp`, `iat`, `aud` and `jti`.
    fn validate(
        &self,
        kid: &str,
        claims: &Map<String, Value>,
        whitelisted_issuers: Option<&[&str]>,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let iss = extract_claim::<String>(claims, "iss")?;
        let exp = extract_claim::<i64>(claims, "exp")?;
        let iat = extract_claim::<i64>(claims, "iat")?;
        let jti = extract_claim::<String>(claims, "jti")?;
        let aud = extract_aud_from_claims(claims)?;

        // From ASAP spec:
        // The resource server MAY reject a token if the token nonce (`jti`) has
        // been previously seen by the resource server in another request. If
        // the resource server decides to implement duplicate detection, it MUST
        // explicitly document that behaviour.
        if self.validate_jti {
            if self
                .jti_seen
                .read()
                .expect("failed to acquire lock on jti set")
                .contains(&jti)
            {
                return Err(ValidatorError::DuplicateJTI(jti).into());
            } else {
                self.jti_seen
                    .write()
                    .expect("failed to acquire lock on jti set")
                    .insert(jti);
            }
        }

        // From ASAP spec:
        // The resource server MUST check that the key identified by `kid` is
        // owned by the issuer. In order to do so, the resource server MAY check
        // if the `kid` string starts with `$iss/` (where $iss is the value of
        // the `iss` claim) and, in affirmative case, accept that as proof of
        // ownership of the key by the issuer.
        if self.validate_kid && !kid.starts_with(&format!("{}/", &iss)) {
            return Err(ValidatorError::InvalidKID(kid.to_string(), iss).into());
        }

        // From ASAP spec:
        // The resource server MUST verify that the current time is between `nbf`
        // (optional) and `exp` (required), inclusive. For the purposes of this
        // comparison, a missing `nbf` claim defaults to the value of `iat`. The
        // resource server MAY offer, at its discretion, a grace period to
        // compensate for internal clock divergences between the client and the
        // resource server.
        let nbf = extract_claim::<i64>(claims, "nbf").unwrap_or(iat);
        if nbf > now + self.leeway {
            return Err(ValidatorError::ImmatureSignature(nbf, exp).into());
        } else if exp < now - self.leeway {
            return Err(ValidatorError::ExpiredSignature(nbf, exp).into());
        }

        // From ASAP spec:
        // The resource server MUST reject a token if it lifespan (the difference
        // between `exp` and `iat`) exceeds one hour (hard limit). A resource
        // server MAY implement, at its discretion, a more restrictive upper
        // bound for the lifespan of a token.
        if exp - iat > self.max_lifespan {
            return Err(ValidatorError::InvalidLifespan.into());
        }

        // From ASAP spec:
        // The resource server MUST verify that it is the intended audience of
        // the access token by checking that at least one of the values of `aud`
        // is the identifier of the resource server mutually agreed by the
        // client and the resource server.
        if !aud.contains(&self.resource_server_audience) {
            return Err(ValidatorError::UnrecognisedAudience(aud).into());
        }

        // From ASAP spec:
        // If `sub` claim is not defined, the resource server MUST assume that
        // the effective subject is the same as the issuer (the `iss` claim).
        let sub = extract_claim::<String>(claims, "sub").unwrap_or(iss);

        // Here, we verify that the token's subject is contained in the
        // `whitelisted_issuers` vec. This check isn't explicitly defined in the
        // spec, but the spec suggests that a resource server should decide if
        // the issuer of the token is authorised to make requests (by checking
        // checking either the `iss` or the `sub` claim). Thus, we provide
        // `whitelisted_issuers` as an argument to `Validator.decode` so the
        // user of this library may pass a vec of strings to further verify that
        // the token is valid.
        //
        // See ASAP spec:
        // The verification process [(all the above checks)] ... allows the
        // resource server to authenticate the token as a valid token issued by
        // the owner of the private key. This process does not cover the
        // following aspects that the resource server SHOULD implement by its
        // own means:
        // - The resource server MAY decide if the verified issuer is authorised
        //      to communicate with the resource server.
        // - The resource server MAY decide if the verified issuer is authorised
        //      to make requests in relation to the claimed subject (principal).
        // - The resource server MAY decide if the combination of verified
        //      issuer and effective subject is authorised to make the requested
        //      business operation.
        if let Some(issuers) = whitelisted_issuers {
            if !issuers.contains(&sub.as_ref()) {
                let subjects = issuers.iter().map(|&x| x.to_owned()).collect();
                return Err(ValidatorError::UnauthorizedSubject(sub, subjects).into());
            }
        }

        // Token has been validated and authorised, proceed!
        Ok(())
    }
}

// Attempt to fetch the public key from cache.
fn get_key_from_cache(
    key_cache: &mut PublicKeyCache,
    key_cache_duration: Duration,
    kid: &str,
) -> Result<jwt::DecodingKey> {
    if let Some((when, public_key)) = key_cache.get(kid) {
        let time_since = when.elapsed()?;
        if time_since <= key_cache_duration {
            Ok(public_key.clone())
        } else {
            Err(ValidatorError::ExpiredCache(String::from(kid)).into())
        }
    } else {
        Err(ValidatorError::CacheError.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_sync<T: Sync>() {}

    #[test]
    fn is_sync() {
        check_sync::<Validator>();
    }
}
