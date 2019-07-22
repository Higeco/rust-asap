use chrono::Utc;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serializer};
use serde_json::Value;
use std::collections::HashMap;

use crate::util::generate_jti;

// Default token lifespan (one hour).
pub const DEFAULT_TOKEN_LIFESPAN: i64 = 60 * 60;

/// Claims required by ASAP. Cannot be overriden by the `extra_claims` field.
pub const REQUIRED_CLAIMS: [&str; 5] = ["aud", "iss", "jti", "iat", "exp"];

/// This type exists to ease adding in any extra claims to your ASAP token.
/// It is a HashMap where the keys correspond to top-level keys in the serialised token.
/// Note that overriding the required ASAP claims will have no effect.
///
/// ```rust
/// extern crate asap;
/// extern crate serde;
/// #[macro_use] extern crate serde_json;
///
/// use asap::claims::Aud;
/// use asap::generator::Generator;
/// use std::collections::HashMap;
///
/// let mut extra_claims = HashMap::new();
/// extra_claims.insert("myCustomClaim".to_string(), json!("foobar"));
/// extra_claims.insert("anotherClaim".to_string(), json!(1234));
///
/// # let aud = Aud::One("service02".to_string());
/// # let iss = "service01".to_string();
/// # let kid = "service01/my-key-id".to_string();
/// # let private_key = include_bytes!("../support/keys/service01/1530402390-private.der").to_vec();
/// # let generator = Generator::new(iss, kid, private_key);
/// let token = generator.token(aud, Some(extra_claims)).unwrap();
/// ```
pub type ExtraClaims = HashMap<String, Value>;

/// Since the `aud` claim may be either a `String` or `Vec<String>`, use this
/// struct to ensure that the value is serialised and deserialised correctly.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum Aud {
    /// Becomes: `"aud": "your-audience"`.
    One(String),
    /// Becomes: `"aud": ["list", "of", "your", "audiences"]`.
    Many(Vec<String>),
}

impl Aud {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str<S: Into<String>>(aud: S) -> Aud {
        Aud::One(aud.into())
    }

    pub fn from_vec(list: Vec<&str>) -> Aud {
        Aud::Many(list.iter().map(|s| s.to_string()).collect())
    }
}

/// A claims struct that contains the required ASAP fields.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// SPEC: A value that identifies the resource server.
    pub aud: Aud,
    /// SPEC: The service identifier of the client.
    pub iss: String,
    /// SPEC: A generated nonce value that is unique within the  temporal window
    /// of the token life time. The client MUST ensure that  there is a very low
    /// probability that at any point in time there are more than one valid and
    /// non-expired tokens with the same `jti` value, considering that there
    /// may be many issuers and many instances of the same issuer.
    pub jti: String,
    /// SPEC: The current time according to the client's internal clock.
    pub iat: i64,
    /// SPEC: A time in the future (`exp` MUST be after `iat`). For security
    /// reasons, the client SHOULD issue short-lived tokens. If the environment
    /// can guarantee a good synchronisation between the internal clocks of the
    /// systems involved in the communication, a sub-minute expire time is
    /// recommended. There is a hard limit of one hour.
    pub exp: i64,

    /// Extra claims may be added to the token. These values will be serialised
    /// into the root of the token. If `None` is passed then no extra claims
    /// will be added to the token.
    #[serde(
        flatten,
        deserialize_with = "de_extra_claims",
        serialize_with = "ser_extra_claims"
    )]
    pub extra_claims: Option<ExtraClaims>,
}

fn de_extra_claims<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ExtraClaims>, D::Error> {
    let extra_claims = ExtraClaims::deserialize(deserializer)?;
    if !extra_claims.is_empty() {
        Ok(Some(extra_claims))
    } else {
        Ok(None)
    }
}

fn ser_extra_claims<S: Serializer>(
    extra_claims: &Option<ExtraClaims>,
    s: S,
) -> Result<S::Ok, S::Error> {
    if let Some(claims) = extra_claims {
        let mut map = s.serialize_map(Some(claims.len()))?;
        for (k, v) in claims {
            if !REQUIRED_CLAIMS.contains(&k.as_str()) {
                map.serialize_entry(k, v)?;
            }
        }

        map.end()
    } else {
        s.serialize_none()
    }
}

impl Claims {
    pub fn cache_key(&self) -> String {
        serde_json::to_string(&json!({
            "aud": json!(self.aud),
            "iss": json!(self.iss),
            "iat": json!(self.iat),
            "exp": json!(self.exp),
            "extra_claims": json!(self.extra_claims)
        }))
        .unwrap()
    }
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
    pub(crate) fn build(&self, aud: Aud, extra_claims: Option<ExtraClaims>) -> Claims {
        let iss = self.iss.clone();
        let jti = generate_jti();

        let iat = Utc::now().timestamp();
        let exp = iat + self.lifespan;

        Claims {
            aud,
            iss,
            iat,
            exp,
            jti,
            extra_claims,
        }
    }
}
