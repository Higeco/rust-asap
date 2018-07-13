# ASAP for Rust

[![crates.io](https://img.shields.io/crates/v/asap.svg)](https://crates.io/crates/asap)
[![dependency status](https://deps.rs/repo/bitbucket/cosmotherly/rust-asap/status.svg)](https://deps.rs/repo/bitbucket/cosmotherly/rust-asap)
[![build status](https://img.shields.io/bitbucket/pipelines/cosmotherly/rust-asap.svg)](https://bitbucket.org/cosmotherly/rust-asap/addon/pipelines/home#!/)

[Documentation](https://docs.rs/asap).

This is a rust library for generating and validating ASAP tokens. It provides options for doing so that are compliant with the [ASAP specification](https://s2sauth.bitbucket.io/spec/).

**Why should you use this library?**

* Do you want to generate 1 ASAP token/millisecond?
* Do you want to validate 5 ASAP tokens/millisecond?
* Do you want to bring your own token `Claims` in whatever format you'd like?
* Do you want/need to use ASAP with one of the greatest languages ever?

Basically, yes. Yes, you should use this library if you want ASAP and use Rust.

## Usage

### Installation

To install, add the following lines to your `Cargo.toml`:

```toml
asap = "<latest-version-from-crates.io>"
# These crates are required for defining your own `Claims` struct which needs
# to be serialised into the token (and deserialised out of it).
serde_derive = "1"
serde = "1"
```

### Documentation

And see [the documentation and API](https://docs.rs/asap) which should be straightforward enough for anything you'd need.

## Development/Testing

To run tests:

```
cargo test
```

Note that some tests need a keyserver to work. They start up the [mini
keyserver in the workspace](./support/keyserver) on a random port at the
beginning of the test. Because each test has its own keyserver, they can
run in parallel.

## References

* ASAP Spec: https://s2sauth.bitbucket.io/spec/
* JWT Spec: https://tools.ietf.org/html/rfc7519
* JWS Spec: https://tools.ietf.org/html/rfc7515

## License

[MIT](./LICENSE.md)
