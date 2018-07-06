set -e

# Since the tests need to be run serially run them with just one thread.
RUST_TEST_THREADS=1 cargo test --lib

# Documentation tests.
cargo test --doc

# Benchmarks.
cargo bench
