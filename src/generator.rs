//! This module contains all things relating to the generation of ASAP tokens.
//! Use this module if you need to generate ASAP tokens or authorisation headers
//! for outgoing requests.
//!
//! ```rust
//! # extern crate asap;
//! # extern crate serde;
//! # extern crate chrono;
//! # #[macro_use] extern crate serde_derive;
//! #
//! # use asap::claims::{DefaultClaims, Aud};
//! # use asap::generator::Generator;
//! # use serde::de::DeserializeOwned;
//! # use chrono::Utc;
//! #
//! // The identifier of the service that issues the token (`iss`).
//! let iss = "service01".to_string();
//! // The key id (`kid`) of the public key in your keyserver.
//! let kid = "service01/my-key-id".to_string();
//! // The `private_key` used to sign each token.
//! let private_key = include_bytes!("../support/keys/service01/1530402390-private.der").to_vec();
//!
//! let mut generator = Generator::new(iss, kid, private_key);
//!
//! // You can then use the generator to create ASAP tokens:
//!
//! // The intended audience of your token:
//! let aud = Aud::One("target-service".to_string());
//! // You can add custom extra claims too if you need:
//! let extra_claims: Option<DefaultClaims> = None;
//!
//! // Authorization tokens: "eyJ0eXAiOiJKV..."
//! generator.token::<DefaultClaims>(aud, extra_claims).unwrap();
//! // Or authorization headers: "Bearer eyJ0eXAiOiJKV..."
//! // generator.auth_header(aud, extra_claims).unwrap();
//! ```
//!
//! You may also provide extra claims to your generated token, as long as your
//! struct can be serialised and deserialised:
//!
//! ```rust
//! # extern crate asap;
//! # extern crate serde;
//! # extern crate chrono;
//! # #[macro_use] extern crate serde_derive;
//! #
//! # use asap::claims::{DefaultClaims, Aud};
//! # use asap::generator::Generator;
//! # use serde::de::DeserializeOwned;
//! # use chrono::Utc;
//! #
//! # // The identifier of the service that issues the token (`iss`).
//! # let iss = "service01".to_string();
//! # // The key id (`kid`) of the public key in your keyserver.
//! # let kid = "service01/my-key-id".to_string();
//! # // The `private_key` used to sign each token.
//! # let private_key = include_bytes!("../support/keys/service01/1530402390-private.der").to_vec();
//! #
//! # let mut generator = Generator::new(iss, kid, private_key);
//! # let aud = Aud::One("target-service".to_string());
//! #
//! #[derive(Serialize, Deserialize)]
//! struct ExtraClaims {
//!     foo: String,
//!     bar: i64,
//!     baz: Vec<String>
//! }
//!
//! let extra_claims = Some(ExtraClaims {
//!     foo: "foo".to_string(),
//!     bar: 1234,
//!     baz: vec!["baz".to_string()]
//! });
//!
//! generator.token(aud, extra_claims).unwrap();
//! ```

use claims::{Aud, ClaimsBuilder};
use jwt;
use serde::ser::Serialize;
use std::env;

use errors::{Result, ResultExt};
use util::convert_pem_to_der;

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
/// # #[macro_use] extern crate serde_derive;
/// #
/// # use asap::claims::{DefaultClaims, Aud};
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
/// let mut generator = Generator::new(iss, kid, private_key);
/// ```
pub struct Generator {
    header: jwt::Header,
    private_key: Vec<u8>,
    claims_builder: ClaimsBuilder,
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
    /// NOTE: For the sake of simplicity, at this moment this library does not
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
            claims_builder,
        }
    }

    /// Sets the max lifespan (in seconds) of the tokens created by this generator.
    ///
    /// ```rust
    /// # extern crate asap;
    /// # extern crate serde;
    /// # extern crate chrono;
    /// # #[macro_use] extern crate serde_derive;
    /// #
    /// # use asap::claims::{DefaultClaims, Aud};
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
    /// let mut generator = Generator::new(iss, kid, private_key);
    /// generator.set_max_lifespan(60);
    /// ```
    pub fn set_max_lifespan(&mut self, lifespan: i64) {
        self.claims_builder.lifespan(lifespan);
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
    /// You may optionally define your own struct (as long as it implements
    /// `Serialize` and `Deserialize`) which you can use to add extra claims to
    /// your token:
    ///
    /// ```rust
    /// # extern crate asap;
    /// # extern crate serde;
    /// # extern crate chrono;
    /// # #[macro_use] extern crate serde_derive;
    /// #
    /// # use asap::claims::{DefaultClaims, Aud};
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
    /// # let mut generator = Generator::new(iss, kid, private_key);
    /// #
    /// // Your target audience (the `aud` claim):
    /// let aud = Aud::One("target-audience".to_string());
    /// // Alternatively, you may define multiple audiences:
    /// let aud = Aud::Many(vec!["service01".to_string(), "service02".to_string()]);
    ///
    /// // You may also optionally define extra claims to be added to your token:
    /// #[derive(Serialize, Deserialize)]
    /// struct ExtraClaims {
    ///     foo: String,
    ///     bar: i64,
    ///     baz: Vec<String>
    /// }
    ///
    /// let extra_claims = ExtraClaims {
    ///     foo: "foo".to_string(),
    ///     bar: 1234,
    ///     baz: vec!["baz".to_string()]
    /// };
    ///
    /// generator.token(aud, Some(extra_claims)).unwrap();
    /// ```
    pub fn token<T: Serialize>(&mut self, aud: Aud, extra_claims: Option<T>) -> Result<String> {
        let claims = self.claims_builder.build(aud, extra_claims);

        // Encode it and sign it with the private key.
        let token = jwt::encode(&self.header, &claims, &self.private_key).sync()?;
        Ok(token)
    }

    /// Generates a pre-formatted Authorization header, ready to be used in a HTTP request.
    ///
    /// ```rust
    /// # extern crate asap;
    /// # extern crate serde;
    /// # extern crate chrono;
    /// # #[macro_use] extern crate serde_derive;
    /// #
    /// # use asap::claims::{DefaultClaims, Aud};
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
    /// # let mut generator = Generator::new(iss, kid, private_key);
    /// # let aud = Aud::One("target-audience".to_string());
    /// # let extra_claims: Option<DefaultClaims> = None;
    /// let auth_header = generator.auth_header(aud, extra_claims).unwrap();
    /// println!("{:?}", auth_header); // "Bearer eyJ0eXAiOiJKV..."
    /// ```
    pub fn auth_header<T: Serialize>(
        &mut self,
        aud: Aud,
        extra_claims: Option<T>,
    ) -> Result<String> {
        Ok(format!("Bearer {}", self.token(aud, extra_claims)?))
    }
}
