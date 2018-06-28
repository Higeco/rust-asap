# ASAP for Rust

TODO: write information about lib

## Usage

TODO: write usage? build docs?

## Running tests

Currently, running the tests has some limitations:

* needs a local keyserver
* they need to be run serially

To run the tests, perform the following:

```bash
# Run a simple keyserver.
cargo run -p keyserver

# In a different shell, run the tests serially:
RUST_TEST_THREADS=1 cargo test
```
