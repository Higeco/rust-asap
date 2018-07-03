set -e

RUST_TEST_THREADS=1 cargo test --lib
# cargo doc --no-deps
