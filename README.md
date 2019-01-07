# ASAP for Rust

[![crates.io](https://img.shields.io/crates/v/asap.svg)](https://crates.io/crates/asap)
[![dependency status](https://deps.rs/repo/bitbucket/atlassianlabs/rust-asap/status.svg)](https://deps.rs/repo/bitbucket/atlassianlabs/rust-asap)
[![build status](https://img.shields.io/bitbucket/pipelines/atlassianlabs/rust-asap.svg)](https://bitbucket.org/atlassianlabs/rust-asap/addon/pipelines/home#!/)

[Documentation](https://docs.rs/asap).

This is a rust library for generating and validating ASAP tokens. It provides options for doing so that are compliant with the [ASAP specification](https://s2sauth.bitbucket.io/spec/).

**Why should you use this library?**

* Do you want to generate 1 ASAP token/millisecond?
* Do you want to validate 5 ASAP tokens/millisecond?
* Do you want to bring your own token `Claims` in whatever format you'd like?
* Do you want/need to use ASAP with one of the greatest languages ever?

Basically, yes. Yes, you should use this library if you want ASAP and use Rust.

This repository also provides a useful tool for using ASAP on the command line:

```bash
# Install the binary:
cargo install asap_cli

# Setup your ASAP keys:
asap init

# Make an ASAP authorised request via curl:
asap curl https://my-asap-secured-server/
```

## Usage (library)

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

## Usage (binary)

See the help output from the binary itself by running:

```bash
asap help
```

## Development/Testing

To run tests:

```
cargo test
```

Note that some tests need a keyserver to work. They start up the [mini
keyserver in the workspace](./asap/support/keyserver) on a random port at the
beginning of the test. Because each test has its own keyserver, they can
run in parallel.

## References

* ASAP Spec: https://s2sauth.bitbucket.io/spec/
* JWT Spec: https://tools.ietf.org/html/rfc7519
* JWS Spec: https://tools.ietf.org/html/rfc7515

## License

This library is dual licensed under either of the following, at your option:

* Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
* MIT License (LICENSE-MIT or http://opensource.org/licenses/MIT)

## Contributors

Pull requests, issues and comments welcome. For pull requests:

* Add tests for new features and bug fixes
* Follow the existing style
* Separate unrelated changes into multiple pull requests
* See the existing issues for things to start contributing.

For bigger changes, make sure you start a discussion first by creating an issue and explaining the intended change.

Atlassian requires contributors to sign a Contributor License Agreement, known as a CLA. This serves as a record stating that the contributor is entitled to contribute the code/documentation/translation to the project and is willing to have it used in distributions and derivative works (or is willing to transfer ownership).

Prior to accepting your contributions we ask that you please follow the appropriate link below to digitally sign the CLA. The Corporate CLA is for those who are contributing as a member of an organization and the individual CLA is for those contributing as an individual.

* [CLA for corporate contributors](https://na2.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=e1c17c66-ca4d-4aab-a953-2c231af4a20b)
* [CLA for individuals](https://na2.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=3f94fbdc-2fbe-46ac-b14c-5d152700ae5d)

## Disclaimer

This is not an official Atlassian product (experimental or otherwise), it is just code that happens to be owned by Atlassian.

