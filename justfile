RBT := "RUST_BACKTRACE=1"

# Runs the project's tests.
test: build fmt
	cargo test
	cargo clippy

# Benchmarks the project.
bench:
	cargo bench

# Builds the project.
build:
	cargo build

# Formats the project.
fmt:
	cargo fmt

# Runs the asap_cli binary.
@run +args: build
	{{RBT}} ./target/debug/asap {{args}}

# Publishes all the packages in the workspace.
publish: test
	cargo publish --manifest-path ./asap/support/keyserver/Cargo.toml || true
	cargo publish --manifest-path ./asap/Cargo.toml || true
	cargo publish --manifest-path ./asap_cli/Cargo.toml || true
