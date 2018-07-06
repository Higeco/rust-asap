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
//! # use asap::generator::Generator;
//! # use serde::de::DeserializeOwned;
//! # use chrono::Utc;
//! #
//! # // Your jwt claims that will be encoded in the token, this example contains
//! # // the minimum required claims that the ASAP spec requires:
//! # #[derive(Debug, Serialize, Deserialize, PartialEq)]
//! # struct MyClaims {
//! #     iss: String,
//! #     jti: String,
//! #     iat: i64,
//! #     exp: i64,
//! #     aud: String, // or `Vec<String>`
//! # }
//! #
//! # let now = Utc::now().timestamp();
//! # let claims = MyClaims {
//! #     iss: String::from("service01"),
//! #     exp: now + 3000,
//! #     iat: now,
//! #     aud: String::from("resource_server_audience"),
//! #     jti: String::from("foobar")
//! # };
//! #
//! # // The `kid` of the public key in your keyserver.
//! # let kid = String::from("service01/my-key-id");
//! # // The `private_key` used to sign each token.
//! # let private_key = include_bytes!("../support/keys/service01/1530402390-private.der").to_vec();
//! #
//! let generator = Generator::new(kid, private_key);
//!
//! // Authorization tokens: "eyJ0eXAiOiJKV..."
//! generator.token(&claims).unwrap();
//! // Authorization headers: "Bearer eyJ0eXAiOiJKV..."
//! generator.auth_header(&claims).unwrap();
//! // Optionally check `Claims` struct for ASAP compliance:
//! generator.validate_claims(&claims).unwrap();
//! ```

use jwt;
use std::env;
use serde::ser::Serialize;
use serde_json::{to_string, from_str};
use serde_json::map::Map;
use openssl::rsa::Rsa;

use util::{extract_claim, extract_aud_from_claims};
use errors::{Result, ResultExt, ValidatorError};

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
/// # use asap::generator::Generator;
/// # use serde::de::DeserializeOwned;
/// # use chrono::Utc;
/// #
/// // Your jwt claims that will be encoded in the token, this example contains
/// // the minimum required claims that the ASAP spec requires:
/// #[derive(Debug, Serialize, Deserialize, PartialEq)]
/// struct MyClaims {
///     iss: String,
///     jti: String,
///     iat: i64,
///     exp: i64,
///     aud: String, // or `Vec<String>`
/// }
///
/// let now = Utc::now().timestamp();
/// let claims = MyClaims {
///     iss: String::from("service01"),
///     exp: now + 3000,
///     iat: now,
///     aud: String::from("resource_server_audience"),
///     jti: String::from("foobar")
/// };
///
/// // The `kid` of the public key in your keyserver.
/// let kid = String::from("my-iss/my-key-id");
/// // The `private_key` used to sign each token.
/// let private_key = include_bytes!("../support/keys/service01/1530402390-private.der");
///
/// let generator = Generator::new(kid, private_key.to_vec());
/// match generator.token(&claims) {
///     Ok(token) => println!("{:?}", token),
///     Err(e) => eprintln!("Error generating token: {}", e)
/// }
/// ```
pub struct Generator {
    /// Key ID. The identifier of the key used to sign the token in the format
    /// `"issuer/key-id"` where issuer matches `claims.iss`.
    ///
    /// FROM SPEC:
    /// “kid”: key identifier, as defined by JWS, with the difference that here it
    /// is mandatory. The key identifier MUST be a String that is a non-empty sequence
    /// of non-empty substrings joined with the forward slash character (“/”).
    /// None of the substrings can be “.” or “..”. As a further restriction, the
    /// key identifier must match the following Java regular expression: ^[\w.\-\+/]*$.
    pub kid: String,
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
    pub private_key: Vec<u8>,
    /// Whether or not the generator should validate your given `Claims` struct
    /// before generating a token. Note that if your `Claims` struct does not
    /// have the claims required by the ASAP specification it will likely be
    /// rejected.
    ///
    /// If you set this to `true`, then generating a token with a
    /// `Claims` struct that does not **appear** to be compliant will fail (this
    /// does not perform a full validation as that should be done by the `Validator`
    /// instead).
    ///
    /// Defaults to `false`.
    pub validate_claims: bool
}

// TODO: provide a predefined claims struct (both as a default and as an example)
// --> provide some helper methods to use it
// TODO: (optionally) validate the claims struct by checking its fields?
impl Generator {
    /// Creates an ASAP token generator which will generate tokens with the given
    /// `kid` and sign them with the given `private_key`.
    pub fn new(kid: String, private_key: Vec<u8>) -> Generator {
        Generator {
            kid: kid,
            private_key: private_key,
            validate_claims: false
        }
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
    /// env::set_var("ASAP_KEY_ID", "my-iss/my-key-id");
    /// env::set_var("ASAP_PRIVATE_KEY", include_str!("../support/keys/service01/1530402390-private.pem"));
    ///
    /// let generator = Generator::from_env();
    /// ```
    pub fn from_env() -> Generator {
        let get_env_var = |x| env::var(x)
            .expect(&format!("Could not find '{:?}' environment variable", x));

        // Retrieve the private key from env (in `pem` format).
        let key = get_env_var("ASAP_PRIVATE_KEY");
        let rsa = Rsa::private_key_from_pem(key.as_bytes()).unwrap();
        let private_key = rsa.private_key_to_der().unwrap();

        Generator {
            kid: get_env_var("ASAP_KEY_ID"),
            private_key: private_key,
            validate_claims: false
        }
    }

    /// Generates an ASAP token with the given claims.
    ///
    /// ```rust
    /// # extern crate asap;
    /// # extern crate serde;
    /// # #[macro_use] extern crate serde_derive;
    /// # extern crate chrono;
    /// #
    /// # use asap::generator::Generator;
    /// # use serde::de::DeserializeOwned;
    /// # use chrono::Utc;
    /// #
    /// # // Your jwt claims that will be encoded in the token, this example contains
    /// # // the minimum required claims that the ASAP spec requires:
    /// # #[derive(Debug, Serialize, Deserialize, PartialEq)]
    /// # struct MyClaims {
    /// #     iss: String,
    /// #     jti: String,
    /// #     iat: i64,
    /// #     exp: i64,
    /// #     aud: String, // or `Vec<String>`
    /// # }
    /// #
    /// # let now = Utc::now().timestamp();
    /// # let claims = MyClaims {
    /// #     iss: String::from("service01"),
    /// #     exp: now + 3000,
    /// #     iat: now,
    /// #     aud: String::from("resource_server_audience"),
    /// #     jti: String::from("foobar")
    /// # };
    /// #
    /// # // The `kid` of the public key in your keyserver.
    /// # let kid = String::from("my-iss/my-key-id");
    /// # // The `private_key` used to sign each token.
    /// # let private_key = include_bytes!("../support/keys/service01/1530402390-private.der");
    /// #
    /// let generator = Generator::new(kid, private_key.to_vec());
    /// let token = generator.token(&claims).unwrap();
    /// println!("{:?}", token); // eyJ0eXAiOiJKV...
    /// ```
    pub fn token<T: Serialize>(&self, claims: &T) -> Result<String> {
        // Generate the jwt header.
        let mut header = jwt::Header::default();
        header.kid = Some(self.kid.to_string());
        header.alg = jwt::Algorithm::RS256;

        // If set, perform a quick validation of the claims struct.
        if self.validate_claims {
            self.validate_claims(claims)?;
        }

        // Encode it and sign it with the private key.
        let token = jwt::encode(&header, claims, &self.private_key).sync()?;
        Ok(token)
    }

    /// Generates a pre-formatted Authorization header, ready to be used in a HTTP request.
    ///
    /// ```rust
    /// # extern crate asap;
    /// # extern crate serde;
    /// # #[macro_use] extern crate serde_derive;
    /// # extern crate chrono;
    /// #
    /// # use asap::generator::Generator;
    /// # use serde::de::DeserializeOwned;
    /// # use chrono::Utc;
    /// #
    /// # // Your jwt claims that will be encoded in the token, this example contains
    /// # // the minimum required claims that the ASAP spec requires:
    /// # #[derive(Debug, Serialize, Deserialize, PartialEq)]
    /// # struct MyClaims {
    /// #     iss: String,
    /// #     jti: String,
    /// #     iat: i64,
    /// #     exp: i64,
    /// #     aud: String, // or `Vec<String>`
    /// # }
    /// #
    /// # let now = Utc::now().timestamp();
    /// # let claims = MyClaims {
    /// #     iss: String::from("service01"),
    /// #     exp: now + 3000,
    /// #     iat: now,
    /// #     aud: String::from("resource_server_audience"),
    /// #     jti: String::from("foobar")
    /// # };
    /// #
    /// # // The `kid` of the public key in your keyserver.
    /// # let kid = String::from("my-iss/my-key-id");
    /// # // The `private_key` used to sign each token.
    /// # let private_key = include_bytes!("../support/keys/service01/1530402390-private.der").to_vec();
    /// #
    /// let generator = Generator::new(kid, private_key);
    /// let auth_header = generator.auth_header(&claims).unwrap();
    /// println!("{:?}", auth_header); // "Bearer eyJ0eXAiOiJKV..."
    /// ```
    pub fn auth_header<T: Serialize>(&self, claims: &T) -> Result<String> {
        let token = self.token(claims)?;
        Ok(format!("Bearer {}", token))
    }

    /// This is a helper method you can use to ensure your `Claims` struct is
    /// valid according [to the ASAP specification](https://s2sauth.bitbucket.io/spec/).
    ///
    /// This method ensures that:
    ///
    /// - Each of the mandatory claims are present:
    ///     - `iss`: This String identifies the service that issues the token.
    ///     - `iat`: The issued at time.
    ///     - `exp`: Token expiry timestamp. If the environment can guarantee a
    ///         good synchronisation between the internal clocks of the systems
    ///         involved in the communication, a sub-minute expire time is
    ///         recommended. There is a hard upper limit of one hour.
    ///     - `aud`: The audience. May be a `String` or a `Vec<String>`.
    ///     - `jti`: Token identifier. a generated nonce value that is unique
    ///         within the temporal window of the token life time. The client
    ///         MUST ensure that there is a very low probability that at any point
    ///         in time there are more than one valid and non-expired tokens with
    ///         the same “jti” value, considering that there may be many issuers
    ///         and many instances of the same issuer.
    /// - The `kid` is in the correct format (that is begins with `"issuer/"`).
    /// - The difference between `exp` and `iat` does not exceed one hour.
    ///
    /// This method **DOES NOT** perform any other checks or validations. Use
    /// this method only to test if your `Claims` struct is compliant with the
    /// spec, but use the `asap::validator::Validator` struct to verify that the
    /// resource server should accept and honour the generated token.
    ///
    /// ```rust
    /// # extern crate asap;
    /// # extern crate serde;
    /// # #[macro_use] extern crate serde_derive;
    /// # extern crate chrono;
    /// #
    /// # use chrono::Utc;
    /// # use asap::generator::Generator;
    /// #
    /// # let kid = String::from("my-iss/my-key-id");
    /// # let private_key = include_bytes!("../support/keys/service01/1530402390-private.der").to_vec();
    /// #
    /// # let generator = Generator::new(kid, private_key);
    ///
    /// #[derive(Debug, Serialize, Deserialize, PartialEq)]
    /// struct MyCustomClaims {
    ///     jti: String,
    ///     aud: Vec<String>,
    ///     iat: i64,
    ///     exp: i64,
    ///     extra_custom_claim: String
    /// }
    ///
    /// // Here we're using `chrono`'s `Utc` module to get the current time as an
    /// // `i64`, but as long as you provide an `i64` you can use whatever you want.
    /// let now = Utc::now().timestamp();
    /// let my_claims = MyCustomClaims {
    ///     jti: String::from("my-jti-nonce"),
    ///     aud: vec![String::from("resource-server"), String::from("another-resource-server")],
    ///     iat: now,
    ///     exp: now + 60,
    ///     extra_custom_claim: String::from("my-custom-claim")
    /// };
    ///
    /// // This will error because the `iss` claim doesn't exist:
    /// match generator.validate_claims(&my_claims) {
    ///     Ok(_) => println!("Your claims struct is valid according to the spec!"),
    ///     Err(e) => eprintln!("Your claims struct is invalid, reason: {:?}", e)
    /// }
    /// ```
    pub fn validate_claims<T: Serialize>(&self, claims: &T) -> Result<()> {
        // Easiest way to get the values from a generic struct is to serialise
        // it and then deserialise it into a map.
        let claims_map: Map<_, _> = from_str(&to_string(claims)?)?;

        // Check that mandatory claims exist.
        let iss = extract_claim::<String>(&claims_map, "iss")?;
        let exp = extract_claim::<i64>(&claims_map, "exp")?;
        let iat = extract_claim::<i64>(&claims_map, "iat")?;
        // We don't perform validation on these claims (that's the job of the
        // resource server/Validator) but we do check that they exist.
        let _jti = extract_claim::<String>(&claims_map, "jti")?;
        let _aud = extract_aud_from_claims(&claims_map)?;

        // From ASAP spec:
        // The resource server MUST check that the key identified by `kid` is
        // owned by the issuer. In order to do so, the resource server MAY check
        // if the `kid` string starts with `$iss/` (where $iss is the value of
        // the `iss` claim) and, in affirmative case, accept that as proof of
        // ownership of the key by the issuer.
        if !self.kid.starts_with(&format!("{}/", &iss)) {
            return Err(ValidatorError::InvalidKID(self.kid.to_string(), iss.to_string()).into());
        }

        // From ASAP spec:
        // The resource server MUST reject a token if it lifespan (the difference
        // between `exp` and `iat`) exceeds one hour (hard limit). A resource
        // server MAY implement, at its discretion, a more restrictive upper
        // bound for the lifespan of a token.
        if exp - iat > 3600 {
            return Err(ValidatorError::InvalidLifespan.into());
        }

        Ok(())
    }

}
