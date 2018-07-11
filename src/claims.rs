use chrono::Utc;
use serde::ser::Serialize;

use util::generate_jti;

pub const DEFAULT_LIFESPAN: i64 = 3600;

/// TODO:
#[derive(Serialize, Deserialize)]
pub struct NoClaims;
pub type DefaultClaims = Claims<NoClaims>;

// TODO: get this working with serde...

/// TODO:
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(untagged)]
pub enum Aud {
  /// TODO:
  One(String),
  /// TODO:
  Many(Vec<String>),
}

/// TODO:
#[derive(Serialize, Deserialize)]
pub struct Claims<T> {
    /// TODO:
    #[serde(rename = "aud")]
    pub aud: Aud,
    /// TODO:
    pub iss: String,
    /// TODO:
    pub jti: String,
    /// TODO:
    pub iat: i64,
    /// TODO:
    pub exp: i64,

    // TODO: guard against this overwriting the required claims?
    /// TODO:
    #[serde(flatten)]
    pub extra_claims: Option<T>
}

pub struct ClaimsBuilder {
    iss: String,
    lifespan: i64,
}

impl ClaimsBuilder {
    pub fn new(iss: String) -> ClaimsBuilder {
        let lifespan = DEFAULT_LIFESPAN;
        ClaimsBuilder {
            iss,
            lifespan,
        }
    }

    pub fn lifespan(&mut self, lifespan: i64) -> &mut ClaimsBuilder {
        self.lifespan = lifespan;
        self
    }

    pub fn build<T: Serialize>(&mut self, aud: Aud, extra_claims: Option<T>) -> Claims<T> {
        let iss = self.iss.clone();
        let jti = generate_jti();

        let iat = Utc::now().timestamp();
        let exp = iat + self.lifespan;


        Claims {aud, iss, iat, exp, jti, extra_claims}
    }
}
