use pem;
use rand::distributions::Alphanumeric;
use rand::{self, Rng};
use serde::de::DeserializeOwned;
use serde_json::map::Map;
use serde_json::{from_value, Value};

use crate::errors::{Result, ValidatorError};

// Extract the `aud` claim (which may be a string or array of strings) from a
// claims map.
//
// Always returns the `aud` claims as a `Vec<String>`.
pub fn extract_aud_from_claims(claims: &Map<String, Value>) -> Result<Vec<String>> {
    if let Some(value) = claims.get("aud") {
        if value.is_array() {
            Ok(from_value::<Vec<String>>(value.clone())?)
        } else {
            Ok(vec![from_value::<String>(value.clone())?])
        }
    } else {
        Err(ValidatorError::ClaimNotFound("aud".to_string()).into())
    }
}

pub fn extract_claim<T>(claims: &Map<String, Value>, key: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    if let Some(x) = claims.get(key) {
        Ok(from_value::<T>(x.clone())?)
    } else {
        Err(ValidatorError::ClaimNotFound(key.to_string()).into())
    }
}

pub fn convert_pem_to_der(input: &[u8]) -> Result<Vec<u8>> {
    let key = pem::parse(input).map_err(|err| format_err!("failed to parse pem data: {}", err))?;
    Ok(key.contents)
}

pub fn generate_jti() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(20)
        .map(char::from)
        .collect::<String>()
}

#[test]
fn key_conversion() {
    let pem = include_bytes!("../support/keys/service01/1530402390-private.pem");
    let der = include_bytes!("../support/keys/service01/1530402390-private.der");

    let key = convert_pem_to_der(pem).unwrap();

    assert_eq!(key.as_slice(), der.as_ref())
}
