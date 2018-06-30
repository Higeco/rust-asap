use std::io::Read;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_json::value::{to_value, Value};
use jwt;
use reqwest;
use failure::Error;
use errors::ResultExt;

/// The duration of how long the validator should cache public keys fetched
/// from the keyserver. Defaults to 10 minutes.
pub const DEFAULT_CACHE_DURATION: Duration = Duration::from_secs(600);

// The types of errors a Validator may encounter.
#[derive(Fail, Debug)]
enum ValidatorError {
    #[fail(display = "JWT header did not contain a valid `kid`: {:?}", _0)]
    InvalidKID(jwt::Header),

    #[fail(display = "Received `None` when fetching from cache")]
    CacheError,

    #[fail(display = "Failed to retrieve public key from keyserver")]
    KeyserverError,

    #[fail(display = "Expired item: {:?}", _0)]
    ExpiredCache(String)
}

/// Options used to configure an ASAP Validator.
pub struct ValidatorOptions {
    /// The keyserver URL. Must have a trailing "/".
    pub keyserver_url: String,
    /// The fallback keyserver URL. Must have a trailing "/".
    pub fallback_keyserver_url: String,

    /// If it contains a value, the validation will check that the `aud` field is
    /// the same as the one provided and will error otherwise.
    /// Since `aud` can be either a String or a Vec in the JWT spec, you must use
    /// the `ValidatorOptions::audience()` fn to generate one.
    ///
    /// ```rust
    /// use asap::validator::ValidatorOptions;
    ///
    /// let mut opts = ValidatorOptions /* ... */
    /// # {
    /// #    keyserver_url: String::from("http://keyserver/"),
    /// #    fallback_keyserver_url: String::from("http://keyserver/"),
    /// #    aud: None,
    /// #    iss: None,
    /// #    sub: None,
    /// #    cache_duration: None
    /// # };
    /// opts.aud = ValidatorOptions::audience(&"me"); // string
    /// opts.aud = ValidatorOptions::audience(&["me", "you"]); // array of strings
    /// ```
    pub aud: Option<Value>,
    /// If it contains a value, the validation will check that the `iss` field is
    /// the same as the one provided and will error otherwise.
    pub iss: Option<String>,
    /// If it contains a value, the validation will check that the `sub` field is
    /// the same as the one provided and will error otherwise.
    pub sub: Option<String>,

    /// The duration of how long the validator should cache public keys fetched
    /// from the keyserver. Defaults to 10 minutes.
    pub cache_duration: Option<Duration>
}

impl ValidatorOptions {
    /// Helper method to easily generate the audience options for ValidatorOptions.
    /// Since the `aud` may be either a string or vec, use this when setting it.
    ///
    /// ```rust
    /// use asap::validator::ValidatorOptions;
    ///
    /// // Set to a string:
    /// let mut opts = ValidatorOptions {
    ///     aud: ValidatorOptions::audience(&"me"),
    ///     // other fields...
    /// #    keyserver_url: String::from("http://keyserver/"),
    /// #    fallback_keyserver_url: String::from("http://keyserver/"),
    /// #    iss: None,
    /// #    sub: None,
    /// #    cache_duration: None
    /// };
    ///
    /// // Set to an array of strings:
    /// let mut opts = ValidatorOptions {
    ///     aud: ValidatorOptions::audience(&["me", "you"]),
    ///     // other fields...
    /// #    keyserver_url: String::from("http://keyserver/"),
    /// #    fallback_keyserver_url: String::from("http://keyserver/"),
    /// #    iss: None,
    /// #    sub: None,
    /// #    cache_duration: None
    /// };
    /// ```
    pub fn audience<T: Serialize>(audience: &T) -> Option<Value> {
        Some(to_value(audience).unwrap())
    }
}

/// An ASAP Validator.
///
/// ```rust
/// # extern crate asap;
/// # extern crate serde;
/// # #[macro_use] extern crate serde_derive;
/// # use asap::validator::{Validator, ValidatorOptions};
/// # use serde::de::DeserializeOwned;
/// #
/// // Construct the ASAP validator:
/// let mut validator = Validator::new(ValidatorOptions {
///     // If you pass the `aud`, `iss` and `sub` fields then they will be verified
///     // with the token as well.
///     aud: ValidatorOptions::audience(&"aud"),
///     iss: Some(String::from("iss")),
///     sub: Some(String::from("sub")),
///     // Your keyserver URLs:
///     keyserver_url: String::from("http://my-keyserver/"),
///     fallback_keyserver_url: String::from("http://my-fallback-keyserver/"),
///     // How long should the Validator keep public keys in the cache?
///     cache_duration: None
/// });
///
/// // Your expected jwt claims:
/// #[derive(Debug, Serialize, Deserialize, PartialEq)]
/// struct MyClaims {
///     iss: String,
///     sub: String,
///     aud: String,
/// }
///
/// let asap_token = "<your-token-here>".to_string();
///
/// match validator.validate::<MyClaims>(asap_token) {
///     Ok(token_data) => println!("claims {:?}", token_data.claims),
///     Err(e) => eprintln!("{:?}", e)
/// }
/// ```
pub struct Validator {
    /// The actual jwt validator (from `jsonwebtoken` crate).
    jwt_validator: jwt::Validation,
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
        let mut jwt_validator = jwt::Validation::new(jwt::Algorithm::RS256);
        jwt_validator.set_audience(&opts.aud);
        jwt_validator.iss = opts.iss;
        jwt_validator.sub = opts.sub;

        Validator {
            jwt_validator: jwt_validator,
            keyserver_url: opts.keyserver_url,
            fallback_keyserver_url: opts.fallback_keyserver_url,
            cache: HashMap::new(),
            cache_duration: opts.cache_duration.unwrap_or(DEFAULT_CACHE_DURATION)
        }
    }

    // Decode the given token with the given public key.
    fn decode_token<'a, T: DeserializeOwned>(&self, token: &'a str, public_key: &Vec<u8>) -> Result<jwt::TokenData<T>, Error> {
        let token_data = jwt::decode::<T>(token, public_key, &self.jwt_validator).sync()?;
        Ok(token_data)
    }

    // Attempt to fetch the public key from cache and use that to decode the token.
    fn from_cache<'a, T: DeserializeOwned>(&mut self, kid: &'a str, token: &'a str) -> Result<jwt::TokenData<T>, Error> {
        if let Some((when, public_key)) = self.cache.get(kid) {
            let time_since = when.elapsed()?;
            if time_since <= self.cache_duration {
                return self.decode_token(token, public_key);
            }

            return Err(ValidatorError::ExpiredCache(String::from(kid)).into());
        }

        Err(ValidatorError::CacheError.into())
    }

    // Fetch the public key by returning the response body of: `GET <server_url><kid>`.
    fn fetch_key<'a>(&self, server_url: &'a str, kid: &'a str) -> Result<Vec<u8>, Error> {
        let mut response = reqwest::get(&format!("{}{}", server_url, kid))?;
        if response.status().is_success() {
            let mut public_key = Vec::new();
            response.read_to_end(&mut public_key)?;
            return Ok(public_key);
        }

        Err(ValidatorError::KeyserverError.into())
    }

    /// Validates the given token, returning both the claims and the header.
    ///
    /// ```rust
    /// # extern crate asap;
    /// # extern crate serde;
    /// # #[macro_use] extern crate serde_derive;
    /// # use asap::validator::{Validator, ValidatorOptions};
    /// # use serde::de::DeserializeOwned;
    /// #
    /// # // Construct the ASAP validator:
    /// # let mut validator = Validator::new(ValidatorOptions {
    /// #     aud: ValidatorOptions::audience(&"aud"),
    /// #     iss: Some(String::from("iss")),
    /// #     sub: Some(String::from("sub")),
    /// #     keyserver_url: String::from("http://my-keyserver/"),
    /// #     fallback_keyserver_url: String::from("http://my-fallback-keyserver/"),
    /// #     cache_duration: None
    /// # });
    /// #
    /// # // Your expected jwt claims:
    /// # #[derive(Debug, Serialize, Deserialize, PartialEq)]
    /// # struct MyClaims {
    /// #     iss: String,
    /// #     sub: String,
    /// #     aud: String,
    /// # }
    /// #
    /// let asap_token = "<your-token-here>".to_string();
    ///
    /// match validator.validate::<MyClaims>(asap_token) {
    ///     Ok(token_data) => {
    ///         println!("claims {:?}", token_data.claims);
    ///         println!("header {:?}", token_data.header);
    ///     },
    ///     Err(e) => eprintln!("{:?}", e)
    /// }
    /// ```
    pub fn validate<T: DeserializeOwned>(&mut self, token: String) -> Result<jwt::TokenData<T>, Error> {
        // First, decode the header to get the `kid`.
        let header = jwt::decode_header(&token).sync()?;
        if let Some(kid) = header.kid {
            // Fetch key from cache if there's a key.
            if self.cache.contains_key(&kid) {
                // Extra scope here since `self.from_cache` borrows the internal cache mutably.
                // We won't be able to remove anything from the cache if the ref is still alive.
                {
                    let cached = self.from_cache(&kid, &token);
                    if cached.is_ok() {
                        return cached;
                    }
                    eprintln!("Error fetching from cache, reason: {}. Trying keyserver...", cached.err().unwrap());
                }
                // If there was any error fetching the key from the cache, just remove the entry.
                self.cache.remove(&kid);
            }

            // Otherwise, fetch the public key from the keyserver(s).
            let public_key = self.fetch_key(&self.keyserver_url, &kid)
                .or_else(|e| {
                    eprintln!("Error fetching from keyserver, reason: {}. Trying fallback keyserver...", e);
                    self.fetch_key(&self.fallback_keyserver_url, &kid)
                })?;

            // Decode the token, and store the public key in the cache.
            let result = self.decode_token(&token, &public_key);
            self.cache.insert(kid, (SystemTime::now(), public_key));
            return result;
        } else {
            Err(ValidatorError::InvalidKID(header).into())
        }
    }
}
