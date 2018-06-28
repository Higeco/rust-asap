use std::io::Read;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use serde::de::DeserializeOwned;
use jwt;
use reqwest;
use failure::Error;
use errors::ResultExt;

/// The duration of how long the validator should cache public keys fetched
/// from the keyserver. Defaults to 10 minutes.
const DEFAULT_CACHE_DURATION: Duration = Duration::from_secs(600);

/// The types of errors a Validator may encounter.
#[derive(Fail, Debug)]
pub enum ValidatorError {
    #[fail(display = "JWT header did not contain a valid `kid`: {:?}.", _0)]
    InvalidKID(jwt::Header),

    #[fail(display = "Received `None` when fetching from cache.")]
    CacheError,

    #[fail(display = "Expired item: {:?}.", _0)]
    ExpiredCache(String),
}

/// Options used to configure an ASAP Validator.
pub struct ValidatorOptions {
    /// The keyserver URL. Must have a trailing "/".
    pub keyserver_url: String,
    /// The fallback keyserver URL. Must have a trailing "/".
    pub fallback_keyserver_url: String,

    // ??? check spec that this is what it actually is...
    /// ...
    pub audience: String,

    /// The duration of how long the validator should cache public keys fetched
    /// from the keyserver. Defaults to 10 minutes.
    pub cache_duration: Option<Duration>
}

/// An ASAP Validator.
pub struct Validator {
    /// The keyserver URL. Must have a trailing "/".
    keyserver_url: String,
    /// The fallback keyserver URL. Must have a trailing "/".
    fallback_keyserver_url: String,

    // ??? check spec that this is what it actually is...
    /// ...
    audience: String,

    /// A hash-map used for simple key-caching.
    cache: HashMap<String, (SystemTime, Vec<u8>)>,
    /// The time each cached key is used before being fetched again.
    cache_duration: Duration
}

impl Validator {
    /// Creates a new ASAP Validator from the passed options.
    pub fn new(options: ValidatorOptions) -> Validator {
        Validator {
            audience: options.audience,
            keyserver_url: options.keyserver_url,
            fallback_keyserver_url: options.fallback_keyserver_url,
            cache: HashMap::new(),
            cache_duration: options.cache_duration.unwrap_or(DEFAULT_CACHE_DURATION)
        }
    }

    /// ...
    fn decode_token<'a, T: DeserializeOwned>(&self, token: &'a str, public_key: &Vec<u8>) -> Result<jwt::TokenData<T>, Error> {
        // Decode the token (with audience).
        // NOTE: validation can support an array here, add that
        let mut validation = jwt::Validation::new(jwt::Algorithm::RS256);
        validation.set_audience(&self.audience);

        let token_data = jwt::decode::<T>(token, public_key, &validation).sync()?;
        Ok(token_data)
    }

    /// ...
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

    /// ...
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
                    eprintln!("Error fetching from cache, reason: {:?}. Trying keyserver...", cached.err().unwrap());
                }
                // If there was any error fetching the key from the cache, just delete it.
                self.cache.remove(&kid);
            }

            // Otherwise, fetch the public key from the keyserver(s).
            let mut get_result = reqwest::get(&format!("{}{}", self.keyserver_url, kid));
            if get_result.is_err() {
                eprintln!("Error with keyserver, using fallback keyserver: {:?}.", get_result.err().unwrap());
                get_result = reqwest::get(&format!("{}{}", self.fallback_keyserver_url, kid));
            }
            let mut server_response = get_result?;
            let mut public_key = Vec::new();
            server_response.read_to_end(&mut public_key)?;

            let result = self.decode_token(&token, &public_key);
            self.cache.insert(kid, (SystemTime::now(), public_key));

            return result;
        } else {
            Err(ValidatorError::InvalidKID(header).into())
        }
    }
}
