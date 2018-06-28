// TODO: get env vars (ASAP_KEYSERVER, etc, etc)
// TODO: support Array of audiences in claims

extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate jsonwebtoken as jwt;
extern crate reqwest;

extern crate failure;
#[macro_use] extern crate failure_derive;

pub mod errors;
pub mod generator;
pub mod validator;
#[cfg(test)] mod tests;
