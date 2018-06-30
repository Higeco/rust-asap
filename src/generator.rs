use jwt;
use serde::ser::Serialize;
use errors::ResultExt;
use failure::Error;

/// An ASAP generator.
///
/// ```rust
/// # extern crate asap;
/// # extern crate serde;
/// # #[macro_use] extern crate serde_derive;
/// # use asap::generator::Generator;
/// # use serde::de::DeserializeOwned;
/// #
/// // Your jwt claims that will be encoded in the token:
/// #[derive(Debug, Serialize, Deserialize, PartialEq)]
/// struct MyClaims {
///     aud: String,
///     sub: String,
///     iss: String,
/// }
/// let claims = MyClaims {
///     aud: String::from("aud"),
///     sub: String::from("sub"),
///     iss: String::from("iss"),
/// };
///
/// // The `kid` of the public key in your keyserver.
/// let kid = String::from("my-iss/my-key-id");
/// // The `private_key` used to sign each token.
/// let private_key = include_bytes!("../support/keys/01-private.der");
///
/// let generator = Generator::new(kid, private_key);
/// match generator.generate(&claims) {
///     Ok(token) => println!("{:?}", token),
///     Err(e) => eprintln!("Error generating token: {}", e)
/// }
/// ```
pub struct Generator<'a> {
    /// Key ID. The identifier of the key used to sign the token in the format
    /// `"issuer/key-id"` where issuer matches `claims.iss`.
    ///
    /// TODO: ENSURE THIS IS RIGHT - BECAUSE IT'S NOT ATM
    pub kid: String,
    /// The private key to use when generating the token.
    /// Currently, this only supports keys in the `.der` format.
    ///
    /// Use `openssl` to convert to a key to the `.der` format:
    ///
    /// ```bash
    /// # Convert private key to `.der`:
    /// openssl rsa -in private_key.key -outform DER -out private_key.der
    /// # Create a public key in `.der` format:
    /// openssl rsa -in private_key.der -inform DER -RSAPublicKey_out -outform DER -out public_key.der
    /// ```
    pub private_key: &'a [u8]
}

impl<'a> Generator<'a> {
    /// Creates an ASAP token generator which will generate tokens with the given
    /// `kid` and sign them with the given `private_key`.
    pub fn new(kid: String, private_key: &[u8]) -> Generator {
        Generator {
            kid: kid,
            private_key: private_key
        }
    }

    /// Generates an ASAP token with the given claims.
    ///
    /// ```rust
    /// # extern crate asap;
    /// # extern crate serde;
    /// # #[macro_use] extern crate serde_derive;
    /// # use asap::generator::Generator;
    /// # use serde::de::DeserializeOwned;
    /// #
    /// # // Your jwt claims that will be encoded in the token:
    /// # #[derive(Debug, Serialize, Deserialize, PartialEq)]
    /// # struct MyClaims {
    /// #     aud: String,
    /// #     sub: String,
    /// #     iss: String,
    /// # }
    /// # let claims = MyClaims {
    /// #     aud: String::from("aud"),
    /// #     sub: String::from("sub"),
    /// #     iss: String::from("iss"),
    /// # };
    /// #
    /// # // The `kid` of the public key in your keyserver.
    /// # let kid = String::from("my-iss/my-key-id");
    /// # // The `private_key` used to sign each token.
    /// # let private_key = include_bytes!("../support/keys/01-private.der");
    /// #
    /// let generator = Generator::new(kid, private_key);
    /// let token = generator.generate(&claims).unwrap();
    /// println!("{:?}", token); // eyJ0eXAiOiJKV...
    /// ```
    pub fn generate<T: Serialize>(&self, claims: &T) -> Result<String, Error> {
        // Generate the jwt header.
        let mut header = jwt::Header::default();
        header.kid = Some(self.kid.to_string());
        header.alg = jwt::Algorithm::RS256;

        // Encode it and sign it with the private key.
        let token = jwt::encode(&header, claims, self.private_key).sync()?;
        Ok(token)
    }

    /// Generates a pre-formatted Authorization header.
    ///
    /// ```rust
    /// # extern crate asap;
    /// # extern crate serde;
    /// # #[macro_use] extern crate serde_derive;
    /// # use asap::generator::Generator;
    /// # use serde::de::DeserializeOwned;
    /// #
    /// # // Your jwt claims that will be encoded in the token:
    /// # #[derive(Debug, Serialize, Deserialize, PartialEq)]
    /// # struct MyClaims {
    /// #     aud: String,
    /// #     sub: String,
    /// #     iss: String,
    /// # }
    /// # let claims = MyClaims {
    /// #     aud: String::from("aud"),
    /// #     sub: String::from("sub"),
    /// #     iss: String::from("iss"),
    /// # };
    /// #
    /// # // The `kid` of the public key in your keyserver.
    /// # let kid = String::from("my-iss/my-key-id");
    /// # // The `private_key` used to sign each token.
    /// # let private_key = include_bytes!("../support/keys/01-private.der");
    /// #
    /// let generator = Generator::new(kid, private_key);
    /// let auth_header = generator.generate_auth_header(&claims).unwrap();
    /// println!("{:?}", auth_header); // "Bearer eyJ0eXAiOiJKV..."
    /// ```
    pub fn generate_auth_header<T: Serialize>(&self, claims: &T) -> Result<String, Error> {
        let token = self.generate(claims)?;
        Ok(format!("Bearer {}", token))
    }
}
