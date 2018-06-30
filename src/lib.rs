//! This is the ASAP crate.
//!
//! TODO: review ASAP spec and ensure this is compliant:
//! [ASAP Specification](https://s2sauth.bitbucket.io/spec/)
//!
//! TODO: add general example here?

// TODO: create generator and validator from env (ASAP_KEYSERVER, etc, etc)
// TODO: add configurable `leeway` option for validator
// TODO: test extra claims are verified: exp, nbf, iat
//  --> potentially put this functionality into the Generator

extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;
extern crate jsonwebtoken as jwt;
extern crate reqwest;

extern crate failure;
#[macro_use] extern crate failure_derive;

mod errors;
pub mod generator;
pub mod validator;
#[cfg(test)] mod tests;
