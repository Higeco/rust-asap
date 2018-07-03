//! This is the ASAP crate.
//!
//! TODO:
//!     - document that this has optional `jti` validation
//!     - document supported algorithms (RS256 only for now)
//!
//! TODO: review ASAP spec and ensure this is compliant:
//! [ASAP Specification](https://s2sauth.bitbucket.io/spec/)
//!
//! TODO: add general example or explanation of ASAP spec here?

// TODO: have a predefined "claims" mod that assists in creating claims
// TODO: create generator and validator from env (ASAP_KEYSERVER, etc, etc)
// TODO: add configurable `leeway` option for validator
// TODO: test extra claims are verified: exp, nbf, iat
//  --> potentially put this functionality into the Generator

extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;
extern crate jsonwebtoken as jwt;
extern crate reqwest;
extern crate chrono;
extern crate failure;
#[macro_use] extern crate failure_derive;

mod errors;
pub mod generator;
pub mod validator;
#[cfg(test)] mod tests;
