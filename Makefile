.PHONY: build check test audit doc lint fmt fmt-check clean distclean

build:
	cargo build --all-features

check:
	cargo check --all-features
	cargo check --no-default-features
	cargo check

audit:
	cargo audit --deny warnings

test: fmt-check audit
	cargo clippy --all-targets --all-features -- -W clippy::pedantic -D warnings
	cargo test --all-features
	RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps

lint:
	cargo clippy --all-features -- -D warnings
	mdl *.md doc/*.md

fmt:
	cargo fmt

fmt-check:
	cargo fmt --all --check


clean:
	cargo clean

distclean: clean
	rm -rf Cargo.lock
