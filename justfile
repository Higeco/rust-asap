RBT := "RUST_BACKTRACE=1"

# Runs the project's tests.
test: build fmt
	cargo test

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
	cargo publish --manifest-path ./asap/support/keyserver/Cargo.toml
	cargo publish --manifest-path ./asap/Cargo.toml
	cargo publish --manifest-path ./asap_cli/Cargo.toml
