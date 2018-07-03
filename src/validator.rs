use std::io::Read;
use std::env;
use std::cmp;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use jwt;
use serde::de::DeserializeOwned;
use serde_json::value::{from_value, Value};
use serde_json::{self, Map};
use chrono::Utc;
use reqwest;
use failure::Error;

use errors::ResultExt;

/// The duration of how long the validator should cache public keys fetched
/// from the keyserver. Defaults to 10 minutes.
pub const DEFAULT_CACHE_DURATION: Duration = Duration::from_secs(600);

// The types of errors a Validator may encounter.
#[derive(Fail, Debug)]
enum ValidatorError {
    #[fail(display = "JWT header did not contain a `kid` claim: {:?}", _0)]
    NoKIDFound(jwt::Header),

    #[fail(display = "JWT header did not contain a valid `kid` claim. \
        As per ASAP spec, the `kid` claim must start with \"$iss/\" where $iss is the issuer (kid: {:?}, iss: {:?})", _0, _1)]
    InvalidKID(String, String),

    #[fail(display = "Received `None` when fetching from cache")]
    CacheError,

    #[fail(display = "Failed to retrieve public key from keyserver")]
    KeyserverError,

    #[fail(display = "Expired item: {:?}", _0)]
    ExpiredCache(String),

    #[fail(display = "Expired token")]
    ExpiredToken,

    #[fail(display = "Premature jwt signature, nbf: {:?} exp: {:?}", _0, _1)]
    PrematureSignature(i64, i64),

    #[fail(display = "Expired jwt signature, nbf: {:?} exp: {:?}", _0, _1)]
    ExpiredSignature(i64, i64),

    #[fail(display = "Required claim not found in token: {:?}", _0)]
    ClaimNotFound(String),

    #[fail(display = "Resource server audience not found in `aud` claims of token {:?}", _0)]
    UnrecognisedAudience(Vec<String>),

    #[fail(display = "Unknown or unauthorized subject {:?}. `iss` claim must exist in `authorized_subjects` {:?}", _0, _1)]
    UnauthorizedSubject(String, Vec<String>)
}

/// Options used to configure an ASAP Validator.
pub struct ValidatorOptions {
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
    /// The duration of how long the validator should cache public keys fetched
    /// from the keyserver. Defaults to 10 minutes.
    pub cache_duration: Option<Duration>
}

/// An ASAP Validator.
///
/// ```rust
/// # extern crate asap;
/// # extern crate serde;
/// # extern crate chrono;
/// # #[macro_use] extern crate serde_derive;
/// #
/// # use asap::validator::{Validator, ValidatorOptions};
/// # use serde::de::DeserializeOwned;
/// # use chrono::Utc;
/// #
/// # let now = Utc::now().timestamp();
/// #
/// // Construct the ASAP validator:
/// let mut validator = Validator::new(ValidatorOptions {
///     leeway: None,
///     max_lifespan: None,
///     keyserver_url: String::from("http://my-keyserver/"),
///     fallback_keyserver_url: String::from("http://my-fallback-keyserver/"),
///     resource_server_audience: String::from("my-server"),
///     cache_duration: None
/// });
///
/// // Your expected jwt claims:
/// #[derive(Debug, Serialize, Deserialize, PartialEq)]
/// struct MyClaims {
///     iat: i64,
///     exp: i64,
///     iss: String,
///     aud: String, // or Vec<String>///     aud: String, // or Vec<String>
///     jti: String,
/// }
///
/// let asap_token = "<your-token-here>".to_string();
/// let authorized_subjects = vec!["list", "of", "authorized", "subjects"];
///
/// match validator.decode::<MyClaims>(asap_token, &authorized_subjects) {
///     Ok(token_data) => {
///         println!("claims {:?}", token_data.claims);
///     },
///     Err(e) => eprintln!("{:?}", e)
/// }
/// ```
///
/// TODO: be compliant with ASAP spec:
/// - The resource server MAY reject a token if the token nonce (“jti”) has been previously seen by the resource server
///     in another request. If the resource server decides to implement duplicate detection, it MUST explicitly document
///     that behaviour.
/// - If the resource server successfully verifies and accepts the access token, then it MUST process the request and it
///     MUST assume that the request was issued by the issuer. If the resource server rejects the access token, then it
///     MUST reply with a status code of 401 UNAUTHORIZED and MUST include a WWW-Authenticate header field as per the
///     HTTP specification (just document this)
pub struct Validator {
    /// The actual jwt validator (from `jsonwebtoken` crate).
    jwt_validator: jwt::Validation,
    /// The identifier of the resource server. Incoming ASAP tokens must include
    /// this identifier in their `aud` claim in order for the token to be valid.
    resource_server_audience: String,
    /// Since validating time fields is always a bit tricky due to clock skew,
    /// this field adds `leeway` to the `iat`, `exp` and `nbf` validation.
    leeway: i64,
    /// The max lifespan of the token (the difference between `exp` and `iat`).
    max_lifespan: i64,
    /// The keyserver URL. Must have a trailing "/".
    keyserver_url: String,
    /// The fallback keyserver URL. Must have a trailing "/".
    fallback_keyserver_url: String,
    /// A hash-map used for simple key-caching.
    cache: HashMap<String, (SystemTime, Vec<u8>)>,
    /// The time each cached key is used saved before being fetched again.
    cache_duration: Duration
}

impl Validator {
    /// Creates a new ASAP Validator from the passed options.
    pub fn new(opts: ValidatorOptions) -> Validator {
        Validator {
            jwt_validator: jwt::Validation::new(jwt::Algorithm::RS256),
            resource_server_audience: opts.resource_server_audience,
            leeway: opts.leeway.unwrap_or(0),
            max_lifespan: cmp::max(0, cmp::min(3600, opts.max_lifespan.unwrap_or(3600))),
            keyserver_url: opts.keyserver_url,
            fallback_keyserver_url: opts.fallback_keyserver_url,
            cache: HashMap::new(),
            cache_duration: opts.cache_duration.unwrap_or(DEFAULT_CACHE_DURATION)
        }
    }

    /// Instantiates a validator from the environment. Requires that the following
    /// environment variables be defined:
    ///
    /// * ASAP_KEYSERVER_URL: the URL of the keyserver, must end in a "/".
    /// * ASAP_FALLBACK_KEYSERVER_URL: the URL of the fallback keyserver, must end in a "/".
    pub fn from_env() -> Validator {
        let get_env_var = |x| env::var(x).expect(&format!("Could not find '{:?}' variable", x));
        Validator::new(ValidatorOptions {
            leeway: None,
            max_lifespan: None,
            keyserver_url: get_env_var("ASAP_KEYSERVER_URL"),
            fallback_keyserver_url: get_env_var("ASAP_FALLBACK_KEYSERVER_URL"),
            resource_server_audience: get_env_var("ASAP_SERVER_AUDIENCE"),
            cache_duration: None
        })
    }

    // Decode the given token with the given public key.
    fn decode_token<T: DeserializeOwned>(&self, token: &str, public_key: &Vec<u8>) -> Result<jwt::TokenData<T>, Error> {
        let token_data = jwt::decode::<T>(token, public_key, &self.jwt_validator).sync()?;
        Ok(token_data)
    }

    // Attempt to fetch the public key from cache and use that to decode the token.
    fn get_key_from_cache(&mut self, kid: &str) -> Result<Vec<u8>, Error> {
        if let Some((when, public_key)) = self.cache.get(kid) {
            let time_since = when.elapsed()?;
            if time_since <= self.cache_duration {
                Ok(public_key.to_vec())
            } else {
                Err(ValidatorError::ExpiredCache(String::from(kid)).into())
            }
        } else {
            Err(ValidatorError::CacheError.into())
        }
    }

    // Fetch the public key by returning the response body of: `GET <server_url><kid>`.
    fn get_key_from_server(&self, server_url: &str, kid: &str) -> Result<Vec<u8>, Error> {
        let mut response = reqwest::get(&format!("{}{}", server_url, kid))?;
        if response.status().is_success() {
            let mut public_key = Vec::new();
            response.read_to_end(&mut public_key)?;
            Ok(public_key)
        } else {
            Err(ValidatorError::KeyserverError.into())
        }
    }

    // Retrieves the public key for `kid`, checking the cache and then fetching
    // the key from the keyserver if the key isn't cached.
    fn get_public_key(&mut self, kid: &str) -> Result<Vec<u8>, Error> {
        // Fetch key from cache if there's a key.
        if self.cache.contains_key(kid) {
            // Extra scope here since `self.get_key_from_cache` borrows the internal cache mutably.
            // We won't be able to remove anything from the cache if the ref is still alive.
            {
                let cached_key = self.get_key_from_cache(&kid);
                if cached_key.is_ok() {
                    return cached_key;
                }
                eprintln!("Error fetching from cache, reason: {}. Trying keyserver...", cached_key.err().unwrap());
            }
            // If there was any error fetching the key from the cache, just remove the entry.
            self.cache.remove(kid);
        }

        // Otherwise, fetch the public key from the keyserver(s).
        self.get_key_from_server(&self.keyserver_url, &kid)
            .or_else(|e| {
                eprintln!("Error fetching from keyserver, reason: {}. Trying fallback keyserver...", e);
                self.get_key_from_server(&self.fallback_keyserver_url, &kid)
            })
    }

    /// Decodes the given token, returning both its claims and header.
    ///
    /// TODO: explain spec compliance
    ///
    /// ```rust
    /// # extern crate asap;
    /// # extern crate serde;
    /// # extern crate chrono;
    /// # #[macro_use] extern crate serde_derive;
    /// #
    /// # use asap::validator::{Validator, ValidatorOptions};
    /// # use serde::de::DeserializeOwned;
    /// # use chrono::Utc;
    /// #
    /// # let now = Utc::now().timestamp();
    /// #
    /// # // Construct the ASAP validator:
    /// # let mut validator = Validator::new(ValidatorOptions {
    /// #     leeway: None,
    /// #     max_lifespan: None,
    /// #     keyserver_url: String::from("http://my-keyserver/"),
    /// #     fallback_keyserver_url: String::from("http://my-fallback-keyserver/"),
    /// #     resource_server_audience: String::from("my-server"),
    /// #     cache_duration: None
    /// # });
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
    /// let asap_token = "<your-token-here>".to_string();
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
    pub fn decode<T: DeserializeOwned>(&mut self, token: String, authorized_subjects: &Vec<&str>) -> Result<jwt::TokenData<T>, Error> {
        // First, decode the header to get the `kid`.
        let header = jwt::decode_header(&token).sync()?;

        // Extract key id from jwt header.
        let kid = if header.kid.is_some() {
            header.kid.unwrap().to_string()
        } else {
            return Err(ValidatorError::NoKIDFound(header).into());
        };

        // Retreive public key (from cache or the keyserver).
        let public_key = self.get_public_key(&kid)?;

        // Decode the token.
        let token_data = self.decode_token::<T>(&token, &public_key)?;

        // Ensure the token is valid (according to ASAP).
        self.validate(&kid, &token_data.claims_map, authorized_subjects)?;

        // If everything worked, then store the public key in the cache.
        self.cache.insert(kid, (SystemTime::now(), public_key));

        // Return the decoded token.
        Ok(token_data)
    }

    /// Decodes the given token, returning both its claims and header.
    ///
    /// WARNING! This function performs NO ASAP OR SIGNATURE VALIDATION on the
    /// token. Do not use this unless you know what you are doing.
    pub fn dangerous_unsafe_decode<T: DeserializeOwned>(&mut self, token: &str) -> Result<jwt::TokenData<T>, Error> {
        let token_data = jwt::dangerous_unsafe_decode::<T>(token).sync()?;
        Ok(token_data)
    }

    // Validates the JWT token as per the ASAP specification.
    // As per the ASAP spec, the following claims are mandatory: `iss`, `exp`,
    // `iat`, `aud` and `jti`.
    //
    // TODO: (review) make parts of the validation optional/toggle-able perhaps?
    // NOTE: currently using local-fork of `jsonwebtoken` for `claims_map`!
    fn validate(&self, kid: &str, claims: &Map<String, Value>, authorized_subjects: &Vec<&str>) -> Result<(), Error> {
        let now = Utc::now().timestamp();
        let iss = extract_claim::<String>(claims, "iss")?;
        let exp = extract_claim::<i64>(claims, "exp")?;
        let iat = extract_claim::<i64>(claims, "iat")?;
        let aud = extract_aud_from_claims(claims)?;
        // TODO: `jti` validation
        // let jti = extract_claim::<String>(claims, "jti")?;

        // From ASAP spec:
        // The resource server MUST check that the key identified by “kid” is owned by the issuer.
        // In order to do so, the resource server MAY check if the “kid” string starts with “$iss/” (where $iss is
        // the value of the “iss” claim) and, in affirmative case, accept that as proof of ownership of the key by
        // the issuer.
        if !kid.starts_with(&format!("{}/", &iss)) {
            return Err(ValidatorError::InvalidKID(kid.to_string(), kid.to_string()).into());
        }

        // From ASAP spec:
        // The resource server MUST verify that the current time is between “nbf” (optional) and “exp” (required),
        // inclusive. For the purposes of this comparison, a missing “nbf” claim defaults to the value of “iat”. The
        // resource server MAY offer, at its discretion, a grace period to compensate for internal clock divergences
        // between the client and the resource server.
        let nbf = extract_claim::<i64>(claims, "nbf").unwrap_or(iat);
        if nbf > now + self.leeway {
            return Err(ValidatorError::PrematureSignature(nbf, exp).into());
        } else if exp < now - self.leeway {
            return Err(ValidatorError::ExpiredSignature(nbf, exp).into());
        }

        // From ASAP spec:
        // The resource server MUST reject a token if it lifespan (the difference between “exp” and “iat”) exceeds one
        // hour (hard limit). A resource server MAY implement, at its discretion, a more restrictive upper bound for the
        // lifespan of a token.
        if exp - iat > self.max_lifespan {
            return Err(ValidatorError::ExpiredToken.into());
        }

        // From ASAP spec:
        // The resource server MUST verify that it is the intended audience of the access token by checking that at
        // least one of the values of `aud` is the identifier of the resource server mutually agreed by the client and
        // the resource server.
        if !aud.contains(&self.resource_server_audience) {
            return Err(ValidatorError::UnrecognisedAudience(aud).into());
        }

        // From ASAP spec:
        // If `sub` claim is not defined, the resource server MUST assume that the effective subject is the same as the
        // issuer (the `iss` claim)
        let sub = extract_claim::<String>(claims, "sub").unwrap_or(iss);

        // Here, we verify that the token's subject is contained in the `authorized_subjects` vec. This check isn't
        // explicitly defined in the spec, but the spec suggests that a resource server should decide if the issuer of
        // the token is authorised to make requests (either by checking the `iss` or the `sub` claims).
        // Thus, we provide `authorized_subjects` as an argument to `Validator.decode` so the user of this library may
        // pass a vec of strings to further verify that the token is valid.
        //
        // See ASAP spec:
        // The verification process [(all the above checks)] ... allows the resource server to authenticate the token as
        // a valid token issued by the owner of the private key. This process does not cover the following aspects that
        // the resource server SHOULD implement by its own means:
        // - The resource server MAY decide if the verified issuer is authorised to communicate with the resource server.
        // - The resource server MAY decide if the verified issuer is authorised to make requests in relation to the
        //      claimed subject (principal).
        // - The resource server MAY decide if the combination of verified issuer and effective subject is authorised to
        //      make the requested business operation.
        if !authorized_subjects.contains(&&*sub) {
            let subjects = authorized_subjects.clone().into_iter().map(|x| x.to_owned()).collect();
            return Err(ValidatorError::UnauthorizedSubject(sub.to_string(), subjects).into());
        }

        // Token has been validated and authorised, proceed!
        Ok(())
    }
}

// Helper fn to extract the `aud` claim (which may be a string or array of strings)
// from a claims map. Always returns the `aud` claims as a `Vec<String>`.
fn extract_aud_from_claims(claims: &Map<String, Value>) -> Result<Vec<String>, Error> {
    if let Some(aud) = claims.get("aud") {
        let as_string: Result<String, serde_json::Error> = from_value(aud.clone());
        if as_string.is_ok() {
            Ok(vec![as_string.unwrap()])
        } else {
            let as_vec: Vec<String> = from_value(aud.clone())?;
            Ok(as_vec)
        }
    } else {
        Err(ValidatorError::ClaimNotFound("aud".to_string()).into())
    }
}

// Helper fn to extract the given claim from a claims map.
fn extract_claim<T: DeserializeOwned>(claims: &Map<String, Value>, key: &str) -> Result<T, Error> {
    if let Some(x) = claims.get(key) {
        Ok(from_value::<T>(x.clone())?)
    } else {
        return Err(ValidatorError::ClaimNotFound(key.to_string()).into());
    }
}
