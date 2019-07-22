//! This module contains all things relating to the generation of ASAP tokens.
//! Use this module if you need to generate ASAP tokens or authorisation headers
//! for outgoing requests.
//!
//! ```rust
//! # extern crate asap;
//! # extern crate serde;
//! # extern crate chrono;
//! # #[macro_use] extern crate serde_json;
//! #
//! # use asap::claims::Aud;
//! # use asap::generator::Generator;
//! # use serde::de::DeserializeOwned;
//! # use std::collections::HashMap;
//! # use chrono::Utc;
//! #
//! // The identifier of the service that issues the token (`iss`).
//! let iss = "service01".to_string();
//! // The key id (`kid`) of the public key in your keyserver.
//! let kid = "service01/my-key-id".to_string();
//! // The `private_key` used to sign each token.
//! let private_key = include_bytes!("../support/keys/service01/1530402390-private.der").to_vec();
//!
//! let generator = Generator::new(iss, kid, private_key);
//!
//! // You can then use the generator to create ASAP tokens:
//!
//! // The intended audience of your token:
//! let aud = Aud::One("target-service".to_string());
//! // To create a normal token with no extra claims:
//! let extra_claims = None;
//!
//! // Authorization tokens: "eyJ0eXAiOiJKV..."
//! generator.token(aud, extra_claims).unwrap();
//! // Or authorization headers: "Bearer eyJ0eXAiOiJKV..."
//! // generator.auth_header(aud, extra_claims).unwrap();
//! ```
//!
//! You may also provide extra claims to your generated token. To do so, is it
//! recommended that you use `serde_json`:
//!
//! ```rust
//! # extern crate asap;
//! # extern crate serde;
//! # extern crate chrono;
//! # #[macro_use] extern crate serde_json;
//! #
//! # use asap::claims::{ExtraClaims, Aud};
//! # use asap::generator::Generator;
//! # use serde::de::DeserializeOwned;
//! # use std::collections::HashMap;
//! # use chrono::Utc;
//! #
//! # // The identifier of the service that issues the token (`iss`).
//! # let iss = "service01".to_string();
//! # // The key id (`kid`) of the public key in your keyserver.
//! # let kid = "service01/my-key-id".to_string();
//! # // The `private_key` used to sign each token.
//! # let private_key = include_bytes!("../support/keys/service01/1530402390-private.der").to_vec();
//! #
//! # let generator = Generator::new(iss, kid, private_key);
//! # let aud = Aud::One("target-service".to_string());
//! #
//! let mut extra_claims = HashMap::new();
//! extra_claims.insert("myExtraClaim".to_string(), json!("is_really_neat"));
//!
//! // Authorization tokens: "eyJ0eXAiOiJKV..."
//! // But this time, the token also contains your extra claims.
//! let token = generator.token(aud, Some(extra_claims)).unwrap();
//! ```

use crate::claims::{Aud, Claims, ClaimsBuilder, ExtraClaims};
use crate::jwt;
use lru_time_cache::LruCache;
use std::env;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::errors::{Result, ResultExt};
use crate::util::convert_pem_to_der;

/// An ASAP generator.
///
/// The generator can:
///
/// * Generate ASAP tokens and pre-formatted Authorization headers.
/// * Be created from environment variables.
/// * Be configured to perform automatic validation of your custom `Claims`
///     struct if you want (it's disabled by default).
///
/// ```rust
/// # extern crate asap;
/// # extern crate serde;
/// # extern crate chrono;
/// # #[macro_use] extern crate serde_json;
/// #
/// # use asap::claims::Aud;
/// # use asap::generator::Generator;
/// # use serde::de::DeserializeOwned;
/// # use chrono::Utc;
/// #
/// // The identifier of the service that issues the token (`iss`).
/// let iss = "service01".to_string();
/// // The key id (`kid`) of the public key in your keyserver.
/// let kid = "service01/my-key-id".to_string();
/// // The `private_key` used to sign each token.
/// let private_key = include_bytes!("../support/keys/service01/1530402390-private.der").to_vec();
///
/// let generator = Generator::new(iss, kid, private_key);
/// ```
pub struct Generator {
    header: jwt::Header,
    private_key: Vec<u8>,
    claims_builder: Arc<RwLock<ClaimsBuilder>>,
    cache: Arc<RwLock<Option<LruCache<String, String>>>>,
}

impl Generator {
    /// Creates an ASAP token generator which will generate tokens with the given
    /// key id and sign them with the given private key.
    ///
    /// ## Key ID
    ///
    /// The identifier of the key used to sign the token in the format
    /// `"issuer/key-id"` where issuer matches `claims.iss`.
    ///
    /// `kid`: key identifier, as defined by JWS, with the difference that here it
    /// is mandatory. The key identifier MUST be a String that is a non-empty sequence
    /// of non-empty substrings joined with the forward slash character (`/`).
    /// None of the substrings can be `.` or `..`. As a further restriction, the
    /// key identifier must match the following Java regular expression: `^[\w.\-\+/]*$`.
    ///
    /// NOTE: For the sake of simplicity, at the moment this library does not
    /// ensure that the `kid` matches the regular expression `^[\w.\-\+/]*$`.
    ///
    /// ## Private Key
    ///
    /// The private key to use when generating the token.
    /// Currently, this only supports keys in the `.der` format.
    ///
    /// You can use `openssl` to convert to a `.pem` key to `.der`:
    ///
    /// ```bash
    /// # Convert private key to `.der`:
    /// openssl rsa -in private_key.key -outform DER -out private_key.der
    /// # Create a public key in `.der` format:
    /// openssl rsa -in private_key.der -inform DER -RSAPublicKey_out -outform DER -out public_key.der
    /// ```
    pub fn new(iss: String, kid: String, private_key: Vec<u8>) -> Generator {
        let mut header = jwt::Header::new(jwt::Algorithm::RS256);
        header.kid = Some(kid);

        let claims_builder = ClaimsBuilder::new(iss);
        Generator {
            header,
            private_key,
            claims_builder: Arc::new(RwLock::new(claims_builder)),
            cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Calling this method will enable token caching.
    /// **Caution:** caching generated tokens provides a significant performance
    /// improvement, at the cost of re-using ASAP tokens.
    ///
    /// **Do not use this if your server requires unique `jti` claims**.
    ///
    /// This is intended for use with a server that does not validate `jti`
    /// claims (since they're an optional part of the ASAP spec).
    /// If your server is using `rust-asap` for validation then ensure that
    /// it is not set to validate the `jti` claim.
    ///
    /// `max_count`: the maximum amount of tokens cached.
    /// `ttl`: how long tokens should be cached before expiring.
    ///
    /// Calling `Generator::enable_token_caching` multiple times will drop any
    /// previous caches stored.
    pub fn enable_token_caching(&self, max_count: usize, ttl: Duration) {
        let new_cache =
            LruCache::<String, String>::with_expiry_duration_and_capacity(ttl, max_count);
        let mut cur_cache = self.cache.write().expect("failed to acquire lock on cache");
        *cur_cache = Some(new_cache);
    }

    /// Disables token caching and returns the token cache (if any).
    pub fn disable_token_caching(&self) -> Option<LruCache<String, String>> {
        let mut cur_cache = self.cache.write().expect("failed to acquire lock on cache");
        let old_cache = cur_cache.clone();
        *cur_cache = None;

        old_cache
    }

    /// Sets the max lifespan (in seconds) of the tokens created by this generator.
    ///
    /// ```rust
    /// # extern crate asap;
    /// # extern crate serde;
    /// # extern crate chrono;
    /// # #[macro_use] extern crate serde_derive;
    /// #
    /// # use asap::claims::Aud;
    /// # use asap::generator::Generator;
    /// # use serde::de::DeserializeOwned;
    /// # use chrono::Utc;
    /// #
    /// // The identifier of the service that issues the token (`iss`).
    /// let iss = "service01".to_string();
    /// // The key id (`kid`) of the public key in your keyserver.
    /// let kid = "service01/my-key-id".to_string();
    /// // The `private_key` used to sign each token.
    /// let private_key = include_bytes!("../support/keys/service01/1530402390-private.der").to_vec();
    ///
    /// // Make generated tokens expire after 60 seconds.
    /// let generator = Generator::new(iss, kid, private_key);
    /// generator.set_max_lifespan(60);
    /// ```
    pub fn set_max_lifespan(&self, lifespan: i64) {
        self.claims_builder
            .write()
            .expect("failed to acquire lock on claims builder")
            .lifespan(lifespan);
    }

    /// Instantiates a generator from the environment. Requires that the
    /// following environment variables be defined:
    ///
    /// * `"ASAP_KEY_ID"`: the key id of the public key in the keyserver
    /// * `"ASAP_PRIVATE_KEY"`: the private key used to sign the token. The private
    ///     key must be in the `.pem` format.
    ///
    /// This method uses `openssl` to convert the private key from `.pem` to
    /// `.der`, since `.der` formats can't be provided directly as an env var.
    ///
    /// ```rust
    /// use std::env;
    /// use asap::generator::Generator;
    ///
    /// env::set_var("ASAP_ISSUER", "my-iss");
    /// env::set_var("ASAP_KEY_ID", "my-iss/my-key-id");
    /// env::set_var("ASAP_PRIVATE_KEY", include_str!("../support/keys/service01/1530402390-private.pem"));
    ///
    /// let generator = Generator::from_env().unwrap();
    /// ```
    pub fn from_env() -> Result<Generator> {
        let get_env_var = |x| {
            env::var(x).map_err(|_| format_err!("Could not find '{:?}' environment variable", x))
        };

        // Retrieve the private key from env (in `pem` format).
        let pem_key = get_env_var("ASAP_PRIVATE_KEY")?;
        let der_key = convert_pem_to_der(pem_key.as_bytes())?;
        let iss = get_env_var("ASAP_ISSUER")?;
        let kid = get_env_var("ASAP_KEY_ID")?;

        Ok(Generator::new(iss, kid, der_key))
    }

    /// Generates an ASAP token with the given claims.
    ///
    /// Providing `extra_claims = None` will generate a standard ASAP token.
    ///
    /// You may optionally provide a `HashMap<String, serde_json::Value>` which
    /// you can use to add extra claims to the token:
    ///
    /// ```rust
    /// # extern crate asap;
    /// # extern crate serde;
    /// # extern crate chrono;
    /// # #[macro_use] extern crate serde_json;
    /// #
    /// # use asap::claims::Aud;
    /// # use asap::generator::Generator;
    /// # use serde::de::DeserializeOwned;
    /// # use std::collections::HashMap;
    /// # use chrono::Utc;
    /// #
    /// # // The identifier of the service that issues the token (`iss`).
    /// # let iss = "service01".to_string();
    /// # // The key id (`kid`) of the public key in your keyserver.
    /// # let kid = "service01/my-key-id".to_string();
    /// # // The `private_key` used to sign each token.
    /// # let private_key = include_bytes!("../support/keys/service01/1530402390-private.der").to_vec();
    /// #
    /// # let generator = Generator::new(iss, kid, private_key);
    /// #
    /// // Your target audience (the `aud` claim):
    /// let aud = Aud::One("target-audience".to_string());
    /// // Alternatively, you may define multiple audiences:
    /// let aud = Aud::Many(vec!["service01".to_string(), "service02".to_string()]);
    ///
    /// // You may also optionally define extra claims to be added to your token:
    /// let mut extra_claims = HashMap::new();
    /// extra_claims.insert("foo".to_string(), json!("foo"));
    /// extra_claims.insert("bar".to_string(), json!(1234));
    /// extra_claims.insert("baz".to_string(), json!(["baz", "bop"]));
    ///
    /// generator.token(aud, Some(extra_claims)).unwrap();
    /// ```
    pub fn token(&self, aud: Aud, extra_claims: Option<ExtraClaims>) -> Result<String> {
        let claims = self
            .claims_builder
            .write()
            .expect("failed to acquire lock on claims builder")
            .build(aud, extra_claims);

        let cache_enabled = self
            .cache
            .read()
            .expect("failed to acquire lock on cache")
            .is_some();
        if cache_enabled {
            // Lock and check if we have a cached token.
            {
                let mut cache_opt = self.cache.write().expect("failed to acquire lock on cache");
                let cache = cache_opt.as_mut().unwrap();
                let cache_key = claims.cache_key();
                if let Some(cached_token) = cache.get(&cache_key) {
                    return Ok(cached_token.to_string());
                }
            }

            // If we didn't have a cached token, don't lock while generating the new token.
            let token = Generator::generate_token(&self.header, &claims, &self.private_key)?;

            // Lock while we update the cache with the new token.
            {
                let mut cache_opt = self.cache.write().expect("failed to acquire lock on cache");
                let cache = cache_opt.as_mut().unwrap();
                cache.insert(claims.cache_key(), token.clone());
            }

            return Ok(token);
        }

        // Encode it and sign it with the private key.
        Generator::generate_token(&self.header, &claims, &self.private_key)
    }

    fn generate_token(header: &jwt::Header, claims: &Claims, private_key: &[u8]) -> Result<String> {
        let token = jwt::encode(&header, &claims, &private_key).sync()?;
        Ok(token)
    }

    /// Generates a pre-formatted Authorization header, ready to be used in a HTTP request.
    ///
    /// ```rust
    /// # extern crate asap;
    /// # extern crate serde;
    /// # extern crate chrono;
    /// # #[macro_use] extern crate serde_json;
    /// #
    /// # use asap::claims::Aud;
    /// # use asap::generator::Generator;
    /// # use serde::de::DeserializeOwned;
    /// # use chrono::Utc;
    /// #
    /// # // The identifier of the service that issues the token (`iss`).
    /// # let iss = "service01".to_string();
    /// # // The key id (`kid`) of the public key in your keyserver.
    /// # let kid = "service01/my-key-id".to_string();
    /// # // The `private_key` used to sign each token.
    /// # let private_key = include_bytes!("../support/keys/service01/1530402390-private.der").to_vec();
    /// #
    /// # let generator = Generator::new(iss, kid, private_key);
    /// # let aud = Aud::One("target-audience".to_string());
    /// let auth_header = generator.auth_header(aud, None).unwrap();
    /// println!("{:?}", auth_header); // "Bearer eyJ0eXAiOiJKV..."
    /// ```
    pub fn auth_header(&self, aud: Aud, extra_claims: Option<ExtraClaims>) -> Result<String> {
        Ok(format!("Bearer {}", self.token(aud, extra_claims)?))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::claims::Aud;

    fn check_sync<T: Sync>() {}

    #[test]
    fn is_sync() {
        check_sync::<Generator>();
    }

    #[test]
    fn it_does_not_cache_more_tokens_than_max_count() {
        let iss = "service01";
        let kid = "service01/1530402390-public.der";
        let private_key = include_bytes!("../support/keys/service01/1530402390-private.der");

        let generator = Generator::new(iss.to_string(), kid.to_string(), private_key.to_vec());

        // Caches all 3 tokens.
        generator.enable_token_caching(10, ::std::time::Duration::from_millis(1000));
        let _token_1 = generator.token(Aud::One(iss.to_string()), None).unwrap();
        let _token_2 = generator.token(Aud::One("foo".to_string()), None).unwrap();
        let _token_3 = generator
            .token(Aud::Many(vec![iss.to_string(), "foo".to_string()]), None)
            .unwrap();
        assert_eq!(generator.cache.write().unwrap().as_ref().unwrap().len(), 3);

        // Only caches 2/3 tokens.
        generator.enable_token_caching(2, ::std::time::Duration::from_millis(1000));
        let _token_1 = generator.token(Aud::One(iss.to_string()), None).unwrap();
        let _token_2 = generator.token(Aud::One("foo".to_string()), None).unwrap();
        let _token_3 = generator
            .token(Aud::Many(vec![iss.to_string(), "foo".to_string()]), None)
            .unwrap();
        assert_eq!(generator.cache.write().unwrap().as_ref().unwrap().len(), 2);
    }
}
