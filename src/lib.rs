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
//! # extern crate chrono;
//! # #[macro_use] extern crate serde_derive;
//! #
//! # use asap::generator::Generator;
//! # use serde::de::DeserializeOwned;
//! #
//! // The JWT claims that will be encoded in the token, thanks to Rust's nice
//! // generics you can define your own as long as it implements the `Serialize`
//! // `Deserialize` and `PartialEq` traits.
//! // This example contains the minimum required claims that the ASAP spec requires:
//! #[derive(Debug, Serialize, Deserialize, PartialEq)]
//! struct MyClaims {
//!     iss: String,
//!     jti: String,
//!     iat: i64,
//!     exp: i64,
//!     // The `aud` claim may also be of type: `Vec<String>`
//!     aud: String,
//!     // You can add your extra claims here as necessary!
//!     // extra_claim_1: String,
//!     // extra_claim_2: i64,
//!     // ...
//!     // ...
//! }
//!
//! // You can use whatever method to obtain the current time in seconds as `i64`.
//! let now = chrono::Utc::now().timestamp();
//!
//! let claims = MyClaims {
//!     iss: String::from("service01"),
//!     exp: now + 3000,
//!     iat: now,
//!     aud: String::from("resource_server_audience"),
//!     jti: String::from("foobar")
//! };
//!
//! // The `kid` of the public key in your keyserver.
//! let kid = String::from("my-iss/my-key-id");
//! // The `private_key` used to sign each token.
//! let private_key = include_bytes!("../support/keys/service01/1530402390-private.der");
//!
//! let generator = Generator::new(kid, private_key.to_vec());
//! match generator.token(&claims) {
//!     Ok(token) => println!("{:?}", token),
//!     Err(e) => eprintln!("Error generating token: {}", e)
//! }
//! ```
//!
//! And here's another example of how you can validate tokens:
//!
//! ```rust
//! # extern crate asap;
//! # extern crate serde;
//! # extern crate chrono;
//! # #[macro_use] extern crate serde_derive;
//! #
//! # use asap::validator::{Validator, ValidatorOptions};
//! # use serde::de::DeserializeOwned;
//! # use chrono::Utc;
//! #
//! # let now = Utc::now().timestamp();
//! #
//! // Construct the ASAP validator:
//! let mut validator = Validator::new(ValidatorOptions {
//!     leeway: None,
//!     max_lifespan: None,
//!     keyserver_url: String::from("http://my-keyserver/"),
//!     fallback_keyserver_url: String::from("http://my-fallback-keyserver/"),
//!     resource_server_audience: String::from("my-server"),
//!     validate_jti: false,
//!     cache_duration: None
//! });
//!
//! // Your expected jwt claims:
//! #[derive(Debug, Serialize, Deserialize, PartialEq)]
//! struct MyClaims {
//!     iat: i64,
//!     exp: i64,
//!     iss: String,
//!     aud: String, // or Vec<String>
//!     jti: String,
//! }
//!
//! let asap_token = "<your-token-here>".to_string();
//! let authorized_subjects = vec!["list", "of", "authorized", "subjects"];
//!
//! match validator.decode::<MyClaims>(asap_token, &authorized_subjects) {
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
//! ```
//!
//! That's really it! It should be simple - that's the goal.
//! Thanks for using this crate!

// TODO: have a predefined "claims" mod that assists in creating claims?

extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;
extern crate asap_deps_jsonwebtoken as jwt;
extern crate reqwest;
extern crate chrono;
extern crate openssl;
extern crate failure;
#[macro_use] extern crate failure_derive;

mod util;
mod errors;
pub mod generator;
pub mod validator;
#[cfg(test)] mod tests;
