use chrono::Utc;
use serde::ser::Serialize;

use util::generate_jti;

// Default token lifespan (one hour).
pub const DEFAULT_TOKEN_LIFESPAN: i64 = 60 * 60;

/// A helper struct that can be used to ease generating and validating tokens
/// with no extra claims.
///
/// ```rust
/// # extern crate asap;
/// # extern crate serde;
/// # extern crate chrono;
/// # #[macro_use] extern crate serde_derive;
/// #
/// # use asap::claims::{DefaultClaims, Aud};
/// # use asap::generator::Generator;
/// # use asap::validator::Validator;
/// #
/// # let aud = Aud::One("service02".to_string());
/// # let iss = "service01".to_string();
/// # let kid = "service01/my-key-id".to_string();
/// # let private_key = include_bytes!("../support/keys/service01/1530402390-private.der").to_vec();
/// # let mut generator = Generator::new(iss, kid, private_key);
/// # let keyserver = "http://my-keyserver/".to_string();
/// # let mut validator = Validator::builder(keyserver, "service02".to_string())
/// #     .fallback_keyserver("http://my-fallback-keyserver/".to_string())
/// #     .build();
/// #
/// // Since the compiler needs type information, you can use `DefaultClaims` to
/// // make these operations easier.
/// let token = generator.token::<DefaultClaims>(aud, None).unwrap();
/// let token_data = validator.decode::<DefaultClaims>(&token, &vec!["service01"]);
/// ```
#[derive(Serialize, Deserialize)]
pub struct NoClaims;
pub type DefaultClaims = Claims<NoClaims>;

/// Since the `aud` claim may be either a `String` or `Vec<String>`, use this
/// struct to ensure that the value is serialised and deserialised correctly.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(untagged)]
pub enum Aud {
  /// Becomes: `"aud": "your-audience"`.
  One(String),
  /// Becomes: `"aud": ["list", "of", "your", "audiences"]`.
  Many(Vec<String>),
}

/// A claims struct that contains the required ASAP fields.
#[derive(Serialize, Deserialize)]
pub struct Claims<T> {
    /// SPEC: A value that identifies the resource server.
    aud: Aud,
    /// SPEC: The service identifier of the client.
    iss: String,
    /// SPEC: A generated nonce value that is unique within the  temporal window
    /// of the token life time. The client MUST ensure that  there is a very low
    /// probability that at any point in time there are more than one valid and
    /// non-expired tokens with the same `jti` value, considering that there
    /// may be many issuers and many instances of the same issuer.
    jti: String,
    /// SPEC: The current time according to the client's internal clock.
    iat: i64,
    /// SPEC: A time in the future (`exp` MUST be after `iat`). For security
    /// reasons, the client SHOULD issue short-lived tokens. If the environment
    /// can guarantee a good synchronisation between the internal clocks of the
    /// systems involved in the communication, a sub-minute expire time is
    /// recommended. There is a hard limit of one hour.
    exp: i64,

    /// Extra claims may be added to the token. These values will be serialised
    /// into the root of the token. If `None` is passed then no extra claims
    /// will be added to the token.
    ///
    /// WARNING: take care **not to overwrite any of the above required claims**.
    #[serde(flatten)]
    pub extra_claims: Option<T>
}

/// A nice helper that is used when creating the `Claims` struct for token
/// generation.
pub(crate) struct ClaimsBuilder {
    iss: String,
    lifespan: i64,
}

impl ClaimsBuilder {
    /// Creates a new `ClaimsBuilder` that may be used to build `Claims` structs.
    pub(crate) fn new(iss: String) -> ClaimsBuilder {
        let lifespan = DEFAULT_TOKEN_LIFESPAN;
        ClaimsBuilder { iss, lifespan }
    }

    /// Sets the lifespan of `Claims` structs built by this `ClaimsBuilder`.
    ///
    /// Defaults to `DEFAULT_TOKEN_LIFESPAN`.
    pub(crate) fn lifespan(&mut self, lifespan: i64) -> &mut ClaimsBuilder {
        self.lifespan = lifespan;
        self
    }

    /// Creates a `Claims` struct. This method may be called multiple times to
    /// continue creating different `Claims` structs with the same configuration.
    pub(crate) fn build<T: Serialize>(&mut self, aud: Aud, extra_claims: Option<T>) -> Claims<T> {
        let iss = self.iss.clone();
        let jti = generate_jti();

        let iat = Utc::now().timestamp();
        let exp = iat + self.lifespan;


        Claims {aud, iss, iat, exp, jti, extra_claims}
    }
}
