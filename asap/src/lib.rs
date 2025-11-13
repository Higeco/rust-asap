//! This is a rust library for generating and validating ASAP tokens. It provides
//! options for doing so that are compliant with the [ASAP specification](https://s2sauth.bitbucket.io/spec/).
//!
//! ASAP is a protocol that extends JWT. It does this so resource servers can be
//! confident that incoming requests with signed ASAP tokens are indeed coming
//! from the intended client. If you want to know more, see [the specification](https://s2sauth.bitbucket.io/spec/).
//!
//! Things to note about this ASAP library:
//!
//! * This library is *awesome*. If you use Rust and want ASAP, you should use this!
//! * At the moment it only supports the `RS256` algorithm. This is the most used
//!     algorithm that ASAP uses, so there's been no need to implement any others.
//! * The ASAP `Validator` struct can optionally detect duplicate `jti` nonces.
//!
//! This library aims to be fully compliant with the ASAP specification [found here](https://s2sauth.bitbucket.io/spec/).
//! If you notice anything out of the ordinary, please don't hesitate to make a Issue
//! or PR stating where it doesn't comply.
//!
//! This library also aims to be really simple to use! You should concentrate
//! less on ASAP, and more on writing your client or service. If you spend too
//! much time working with this library, then it's failed its purpose. Please
//! make an Issue/PR telling us why, and we'll do our best to make it better.
//!
//! Here's a quick example of how you can generate tokens using this library:
//!
//! ```rust
//! # extern crate asap;
//! # extern crate serde;
//! # #[macro_use] extern crate serde_json;
//! #
//! use asap::claims::Aud;
//! use asap::generator::Generator;
//!
//! // The identifier of the service that issues the token (`iss`).
//! let iss = "service01".to_string();
//! // The key id (`kid`) of the public key in your keyserver.
//! let kid = "service01/my-key-id".to_string();
//! // The `private_key` used to sign each token.
//! let private_key = include_bytes!("../support/keys/service01/1530402390-private.der").to_vec();
//!
//! // Here's your generator! 🎉
//! let generator = Generator::new(iss, kid, private_key);
//!
//! // Generate tokens, etc...
//! # let aud = Aud::One("aud".to_string());
//! # let extra_claims = None;
//! let token = generator.token(aud, extra_claims).unwrap();
//! ```
//!
//! And here's another example of how you can validate tokens:
//!
//! ```rust
//! # extern crate asap;
//! # extern crate serde;
//! # #[macro_use] extern crate serde_json;
//! #
//! # use serde::de::DeserializeOwned;
//! use asap::claims::Claims;
//! use asap::validator::Validator;
//!
//! # #[tokio::main]
//! # async fn main() {
//!
//! let asap_token = "<your-asap-token>";
//!
//! // The keyserver(s) which hosts your public keys.
//! let primary_keyserver = "http://my-keyserver/".to_string();
//! let fallback_keyserver = "http://my-fallback-keyserver/".to_string();
//! // The audience of the server/resource that validates the incoming tokens.
//! let resource_server_audience = "my-server".to_string();
//!
//! // Build the ASAP validator:
//! let validator = Validator::builder(primary_keyserver, resource_server_audience)
//!     .fallback_keyserver(fallback_keyserver)
//!     .build();
//!
//! // A list of issuers that are allowed to access this server/resource.
//! let whitelisted_issuers = vec!["list", "of", "whitelisted", "issuers"];
//! match validator.decode(asap_token, &whitelisted_issuers).await {
//!     Ok(token_data) => {
//!         // Here you have a successfully verified and accepted access token!
//!         //
//!         // Remember the directions from the ASAP spec:
//!         // If the resource server successfully verifies and accepts the
//!         // access token, then it MUST process the request and it MUST assume
//!         // that the request was issued by the issuer.
//!         println!("claims {:?}", token_data.claims);
//!     },
//!     Err(e) => {
//!         // Oh boo, there was an error decoding and validating the ASAP token.
//!         //
//!         // Remember the directions from the ASAP spec:
//!         // If the resource server rejects the access token, then it MUST
//!         // reply with a status code of 401 UNAUTHORIZED and MUST include a
//!         // WWW-Authenticate header field as per the HTTP specification.
//!         eprintln!("{:?}", e);
//!     }
//! }
//! # }
//! ```
//!
//! That's really it! It should be simple - that's the goal.

extern crate chrono;
#[macro_use]
extern crate anyhow;
#[cfg(not(feature = "fips"))]
extern crate jsonwebtoken as jwt;
#[cfg(feature = "fips")]
extern crate jsonwebtoken_aws_lc as jwt;
extern crate lru_time_cache;
extern crate pem;
extern crate rand;
extern crate reqwest;
extern crate serde;
extern crate thiserror;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;

pub mod claims;
mod errors;
pub mod generator;
mod util;
pub mod validator;
