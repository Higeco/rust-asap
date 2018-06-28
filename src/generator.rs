use jwt;
use serde::ser::Serialize;
use failure::Error;
use errors::ResultExt;

/// ...
// options
//  privateKey, kid, expiresInSeconds, notBefore
pub struct Generator<'a> {
    /// ...
    pub kid: String,
    /// ...
    pub private_key: &'a [u8]
}

impl<'a> Generator<'a> {
    /// Generates an ASAP token with the given claims.
    pub fn generate<T: Serialize>(&self, claims: &T) -> Result<String, Error> {
        // ...
        let mut header = jwt::Header::default();
        header.kid = Some(self.kid.to_string());
        header.alg = jwt::Algorithm::RS256;

        // ...
        let token = jwt::encode(&header, claims, self.private_key).sync()?;
        Ok(token)
    }

    /// Generates a pre-formatted Authorization header.
    pub fn generate_auth_header<T: Serialize>(&self, claims: &T) -> Result<String, Error> {
        let token = self.generate(claims)?;
        Ok(format!("Bearer {}", token))
    }
}
