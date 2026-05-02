.PHONY: build check test doc lint fmt fmt-check clean distclean

build:
	cargo build --all-features

check:
	cargo check --all-features
	cargo check --no-default-features
	cargo check

test: fmt-check
	cargo clippy --all-targets --all-features -- -W clippy::pedantic -D warnings
	cargo test --all-features
	RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps

lint:
	cargo clippy --all-features -- -D warnings
	mdl *.md 

fmt:
	cargo fmt

fmt-check:
	cargo fmt --all --check


clean:
	cargo clean

distclean: clean
	rm -rf Cargo.lock
