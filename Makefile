CARGO ?= cargo
.PHONY: build test check
build:
	$(CARGO) build --locked --workspace --bins
test:
	$(CARGO) test --locked --workspace
check:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --locked --workspace --all-targets -- -D warnings
