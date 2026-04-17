.PHONY: build check test doc lint fmt clean distclean

build:
	cargo build --all-features

check:
	cargo check --all-features
	cargo check --no-default-features
	cargo check

test:
	cargo test --all-features

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps

lint:
	cargo clippy --all-features -- -D warnings
	mdl *.md 

fmt:
	cargo fmt

clean:
	cargo clean

distclean: clean
	rm -rf Cargo.lock
