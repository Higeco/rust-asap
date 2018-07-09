//! This module contains everything you need in order to validate and verify
//! the authenticity of an incoming ASAP token.
//!
//! ```rust
//! # extern crate asap;
//! # extern crate serde;
//! # extern crate chrono;
//! # #[macro_use] extern crate serde_derive;
//! #
//! # use asap::validator::{Validator, ValidatorBuilder};
//! # use serde::de::DeserializeOwned;
//! # use chrono::Utc;
//! #
//! # let now = Utc::now().timestamp();
//! #
//! # // Your expected jwt claims:
//! # #[derive(Debug, Serialize, Deserialize, PartialEq)]
//! # struct MyClaims {
//! #     iat: i64,
//! #     exp: i64,
//! #     iss: String,
//! #     aud: String, // or Vec<String>
//! #     jti: String,
//! # }
//! #
//! # let asap_token = "<your-token-here>";
//! #
//! # // Construct the ASAP validator:
//! # let keyserver = String::from("http://my-keyserver/");
//! # let resource_server_audience = String::from("my-server");
//! let mut validator = ValidatorBuilder::new(keyserver, resource_server_audience)
//!     .fallback_keyserver(String::from("http://my-fallback-keyserver/"))
//!     .finish();
//! match validator.decode::<MyClaims>(asap_token, &vec!["authorized", "subjects"]) {
//!     Ok(token_data) => println!("claims {:?}", token_data.claims),
//!     Err(e) => eprintln!("error validation token/invalid token: {:?}", e)
//! }
//! ```

use std::io::Read;
use std::env;
use std::cmp::{min, max};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};
use jwt::{self, TokenData};
use serde::ser::Serialize;
use serde::de::DeserializeOwned;
use serde_json::value::Value;
use serde_json::{Map, to_string, from_str};
use chrono::Utc;
use reqwest;

use util::{extract_claim, extract_aud_from_claims};
use errors::{Result, ResultExt, ValidatorError};

/// The duration of how long the validator should cache public keys fetched
/// from the keyserver. Defaults to 10 minutes.
pub const DEFAULT_CACHE_DURATION: Duration = Duration::from_secs(600);

/// Options used to configure an ASAP Validator.
pub struct ValidatorBuilder {
    /// The identifier of the resource server. Incoming ASAP tokens must include
    /// this identifier in their `aud` claim in order for the token to be valid.
    pub resource_server_audience: String,
    /// The keyserver URL. Must have a trailing "/".
    pub keyserver_url: String,
    /// The fallback keyserver URL. Must have a trailing "/".
    pub fallback_keyserver_url: String,
    /// Since validating time fields is always a bit tricky due to clock skew,
    /// this field adds `leeway` to the `iat`, `exp` and `nbf` validation (which
    /// are measured in seconds). If unset this defaults to 0.
    pub leeway: Option<i64>,
    /// The max lifespan (difference between `exp` and `iat`) of the token in
    /// seconds. This defaults to one hour (as defined per spec) but you may set
    /// it to a lower value if desired. Setting to a value above one hour will
    /// have no effect (will default to one hour).
    pub max_lifespan: Option<i64>,
    /// Whether or not the validator should check for duplicate `jti` nonces.
    /// If this is set, then the validator will reject tokens who have a `jti`
    /// claim that the validator has seen before.
    pub validate_jti: bool,
    /// Whether or not the validator should check that the `kid` starts with
    /// `"$iss/"` where `$iss` is the issuer. Setting this to `true` is
    /// recommended.
    pub validate_kid: bool,
    /// The duration of how long the validator should cache public keys fetched
    /// from the keyserver. Defaults to 10 minutes.
    pub cache_duration: Option<Duration>
}

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
    /// let mut validator = ValidatorBuilder::new(keyserver, resource_server_audience)
    ///     .leeway(5)
    ///     .max_lifespan(120)
    ///     .cache_duration(Duration::from_secs(300))
    ///     .validate_kid(true)
    ///     .validate_jti(true)
    ///     .fallback_keyserver("http://my-fallback-keyserver/".to_string())
    ///     .finish();
    /// ```
    pub fn new(keyserver_url: String, resource_server_audience: String) -> ValidatorBuilder {
        ValidatorBuilder {
            resource_server_audience: resource_server_audience,
            keyserver_url: keyserver_url.to_string(),
            fallback_keyserver_url: keyserver_url,

            leeway: None,
            max_lifespan: None,
            validate_kid: true,
            validate_jti: false,
            cache_duration: None
        }
    }

    /// Sets the `fallback_keyserver` for the `Validator`.
    pub fn fallback_keyserver(mut self, url: String) -> ValidatorBuilder {
        self.fallback_keyserver_url = url;
        self
    }

    /// Sets the `leeway` for the `Validator`.
    pub fn leeway(mut self, leeway: i64) -> ValidatorBuilder {
        self.leeway = Some(leeway);
        self
    }

    /// Sets the `max_lifespan` for the `Validator`.
    pub fn max_lifespan(mut self, max_lifespan: i64) -> ValidatorBuilder {
        self.max_lifespan = Some(max_lifespan);
        self
    }

    /// Sets the `cache_duration` for the `Validator`.
    pub fn cache_duration(mut self, cache_duration: Duration) -> ValidatorBuilder {
        self.cache_duration = Some(cache_duration);
        self
    }

    /// Sets the `validate_kid` for the `Validator`.
    pub fn validate_kid(mut self, validate_kid: bool) -> ValidatorBuilder {
        self.validate_kid = validate_kid;
        self
    }

    /// Sets the `validate_jti` for the `Validator`.
    pub fn validate_jti(mut self, validate_jti: bool) -> ValidatorBuilder {
        self.validate_jti = validate_jti;
        self
    }

    /// Sets the `finish` for the `Validator`.
    pub fn finish(self) -> Validator {
        let jwt_validator = jwt::Validation {
            // We perform our own validation of these claims.
            leeway: 0,
            validate_exp: false,
            validate_iat: false,
            validate_nbf: false,
            iss: None,
            sub: None,
            aud: None,

            // Currently, we only support the `RS256` algorithm.
            algorithms: vec![jwt::Algorithm::RS256],
        };

        Validator {
            leeway: self.leeway.unwrap_or(0),
            max_lifespan: max(0, min(3600, self.max_lifespan.unwrap_or(3600))),
            jwt_validator: jwt_validator,

            keyserver_url: self.keyserver_url,
            fallback_keyserver_url: self.fallback_keyserver_url,
            resource_server_audience: self.resource_server_audience,

            validate_kid: self.validate_kid,
            validate_jti: self.validate_jti,
            jti_seen: HashSet::new(),

            key_cache: HashMap::new(),
            key_cache_duration: self.cache_duration.unwrap_or(DEFAULT_CACHE_DURATION)
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
/// # extern crate chrono;
/// # #[macro_use] extern crate serde_derive;
/// #
/// # use asap::validator::{Validator, ValidatorBuilder};
/// # use serde::de::DeserializeOwned;
/// # use chrono::Utc;
/// #
/// # let now = Utc::now().timestamp();
/// #
/// // Construct the ASAP validator:
/// let keyserver = String::from("http://my-keyserver/");
/// let resource_server_audience = String::from("my-server");
/// let mut validator = ValidatorBuilder::new(keyserver, resource_server_audience)
///     .fallback_keyserver(String::from("http://my-fallback-keyserver/"))
///     .finish();
///
/// // Your expected jwt claims:
/// #[derive(Debug, Serialize, Deserialize, PartialEq)]
/// struct MyClaims {
///     iat: i64,
///     exp: i64,
///     iss: String,
///     aud: String, // or Vec<String>
///     jti: String,
/// }
///
/// let asap_token = "<your-token-here>";
/// let authorized_subjects = vec!["list", "of", "authorized", "subjects"];
///
/// match validator.decode::<MyClaims>(asap_token, &authorized_subjects) {
///     Ok(token_data) => {
///         // Here you have a successfully verified and accepted access token!
///         //
///         // Remember the directions from the ASAP spec:
///         // If the resource server successfully verifies and accepts the
///         // access token, then it MUST process the request and it MUST assume
///         // that the request was issued by the issuer.
///         println!("claims {:?}", token_data.claims);
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
/// ```
pub struct Validator {
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
    /// The keyserver URL. Must have a trailing "/".
    keyserver_url: String,
    /// The fallback keyserver URL. Must have a trailing "/".
    fallback_keyserver_url: String,
    /// A hash-map used to store and check seen `jti` nonces.
    jti_seen: HashSet<String>,
    /// A hash-map used for simple key-caching.
    key_cache: HashMap<String, (SystemTime, Vec<u8>)>,
    /// The duration each cached key is valid before it's fetched again.
    key_cache_duration: Duration
}

impl Validator {
    /// Instantiates a validator from the environment. Requires that the
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
    /// let validator = Validator::from_env();
    /// ```
    pub fn from_env() -> Validator {
        let get_env_var = |x| env::var(x)
            .expect(&format!("Could not find '{:?}' environment variable", x));

        let keyserver_url = get_env_var("ASAP_KEYSERVER_URL");
        let resource_server_audience = get_env_var("ASAP_SERVER_AUDIENCE");

        ValidatorBuilder::new(keyserver_url, resource_server_audience).finish()
    }

    // Attempt to fetch the public key from cache.
    fn get_key_from_cache(&mut self, kid: &str) -> Result<Vec<u8>> {
        if let Some((when, public_key)) = self.key_cache.get(kid) {
            let time_since = when.elapsed()?;
            if time_since <= self.key_cache_duration {
                Ok(public_key.to_vec())
            } else {
                Err(ValidatorError::ExpiredCache(String::from(kid)).into())
            }
        } else {
            Err(ValidatorError::CacheError.into())
        }
    }

    // Fetch the public key from the keyserver by returning the response body
    // of: `GET <server_url><kid>`.
    fn get_key_from_server(&self, server_url: &str, kid: &str) -> Result<Vec<u8>> {
        let mut response = reqwest::get(&format!("{}{}", server_url, kid))?;
        if response.status().is_success() {
            let mut public_key = Vec::new();
            response.read_to_end(&mut public_key)?;
            Ok(public_key)
        } else {
            Err(ValidatorError::KeyserverError(response.status()).into())
        }
    }

    // Retrieves the public key for `kid`, checking the cache and then fetching
    // the key from the keyserver if the key isn't cached.
    fn get_public_key(&mut self, kid: &str) -> Result<Vec<u8>> {
        // Fetch key from cache if there's a key.
        if self.key_cache.contains_key(kid) {
            // Extra scope here since `self.get_key_from_cache` borrows the
            // internal cache mutably. We won't be able to remove anything from
            // the cache if this ref is still alive.
            {
                let cached_key = self.get_key_from_cache(&kid);
                if cached_key.is_ok() {
                    return cached_key;
                }
                eprintln!("Error fetching from cache, reason: {}. \
                    Trying keyserver...", cached_key.err().unwrap());
            }
            // If there was any error fetching the key from the cache, just
            // remove the entry from cache.
            self.key_cache.remove(kid);
        }

        // Otherwise, fetch the public key from the keyserver(s).
        self.get_key_from_server(&self.keyserver_url, &kid)
            .or_else(|e| {
                eprintln!("Error fetching from keyserver, reason: {}. \
                    Trying fallback keyserver...", e);
                self.get_key_from_server(&self.fallback_keyserver_url, &kid)
            })
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
    /// - the issuer/subject having authorisation (via `authorized_subjects`)
    ///
    /// ```rust
    /// # extern crate asap;
    /// # extern crate serde;
    /// # extern crate chrono;
    /// # #[macro_use] extern crate serde_derive;
    /// #
    /// # use asap::validator::{Validator, ValidatorBuilder};
    /// # use serde::de::DeserializeOwned;
    /// # use chrono::Utc;
    /// #
    /// # let now = Utc::now().timestamp();
    /// #
    /// # // Construct the ASAP validator:
    /// # let keyserver = String::from("http://my-keyserver/");
    /// # let resource_server_audience = String::from("my-server");
    /// # let mut validator = ValidatorBuilder::new(keyserver, resource_server_audience)
    /// #     .fallback_keyserver(String::from("http://my-fallback-keyserver/"))
    /// #     .finish();
    /// #
    /// # // Your expected jwt claims:
    /// # #[derive(Debug, Serialize, Deserialize, PartialEq)]
    /// # struct MyClaims {
    /// #     iat: i64,
    /// #     exp: i64,
    /// #     iss: String,
    /// #     aud: String, // or Vec<String>
    /// #     jti: String,
    /// # }
    /// #
    /// let asap_token = "<your-token-here>";
    /// let authorized_subjects = vec!["list", "of", "authorized", "subjects"];
    ///
    /// match validator.decode::<MyClaims>(asap_token, &authorized_subjects) {
    ///     Ok(token_data) => {
    ///         // Token is a valid ASAP token and is authorised.
    ///         println!("claims {:?}", token_data.claims);
    ///         println!("header {:?}", token_data.header);
    ///     },
    ///     // Errors may include:
    ///     //  - invalid token or signature
    ///     //  - the token was not ASAP compliant
    ///     //  - the public key could not be retreived
    ///     Err(e) => eprintln!("{:?}", e)
    /// }
    /// ```
    pub fn decode<T>(&mut self, token: &str, authorized_subjects: &Vec<&str>) -> Result<TokenData<T>>
        where T: DeserializeOwned + Serialize
    {
        // First, decode the header.
        let header = jwt::decode_header(token).sync()?;

        // Extract `kid` (the public key id) from jwt header.
        let kid = if header.kid.is_some() {
            header.kid.unwrap().to_string()
        } else {
            return Err(ValidatorError::NoKIDFound(header).into());
        };

        // Retreive the public key (from cache or the keyserver).
        let public_key = self.get_public_key(&kid)?;

        // Decode the token (this also validates its signature).
        let data = jwt::decode::<T>(token, &public_key, &self.jwt_validator).sync()?;

        // Ensure the token is valid (according to the ASAP specification).
        //
        // HACK: at the moment we're doing this messy serialise-deserialise hack
        // since `jsonwebtoken` doesn't provide us with a way of obtaining a
        // `Map<String, Value>` of the claims struct.
        // Benchmarks show that this has no noticible performance impact.
        //
        // See: https://github.com/Keats/jsonwebtoken/issues/53
        self.validate(&kid, &from_str(&to_string(&data.claims)?)?, authorized_subjects)?;

        // If everything looks good, and the key is not yet cached, then store
        // the public key in the cache.
        if !self.key_cache.contains_key(&kid) {
            self.key_cache.insert(kid, (SystemTime::now(), public_key));
        }

        // Return the decoded token.
        Ok(data)
    }

    /// Decodes the given token, returning both its claims and header.
    ///
    /// !!! WARNING !!!
    ///
    /// This function performs **_NO ASAP OR SIGNATURE VALIDATION_** on the
    /// token. **Do not use this** unless you know what you are doing.
    ///
    /// !!! WARNING !!!
    pub fn dangerous_unsafe_decode<T>(&mut self, token: &str) -> Result<TokenData<T>>
        where T: DeserializeOwned
    {
        Ok(jwt::dangerous_unsafe_decode::<T>(token).sync()?)
    }

    // Validates the JWT token as per the ASAP specification.
    // The following claims are mandatory: `iss`, `exp`, `iat`, `aud` and `jti`.
    fn validate(&mut self, kid: &str, claims: &Map<String, Value>, authorized_subjects: &Vec<&str>) -> Result<()> {
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
            if self.jti_seen.contains(&jti) {
                return Err(ValidatorError::DuplicateJTI(jti.to_string()).into());
            } else {
                self.jti_seen.insert(jti.to_string());
            }
        }

        // From ASAP spec:
        // The resource server MUST check that the key identified by `kid` is
        // owned by the issuer. In order to do so, the resource server MAY check
        // if the `kid` string starts with `$iss/` (where $iss is the value of
        // the `iss` claim) and, in affirmative case, accept that as proof of
        // ownership of the key by the issuer.
        if self.validate_kid && !kid.starts_with(&format!("{}/", &iss)) {
            return Err(ValidatorError::InvalidKID(kid.to_string(), iss.to_string()).into());
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
        // `authorized_subjects` vec. This check isn't explicitly defined in the
        // spec, but the spec suggests that a resource server should decide if
        // the issuer of the token is authorised to make requests (by checking
        // checking either the `iss` or the `sub` claim). Thus, we provide
        // `authorized_subjects` as an argument to `Validator.decode` so the
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
        if !authorized_subjects.contains(&&*sub) {
            let sub = sub.to_string();
            let subjects = authorized_subjects.clone()
                .into_iter()
                .map(|x| x.to_owned())
                .collect();
            return Err(ValidatorError::UnauthorizedSubject(sub, subjects).into());
        }

        // Token has been validated and authorised, proceed!
        Ok(())
    }
}


