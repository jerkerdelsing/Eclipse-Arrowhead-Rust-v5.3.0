CARGO ?= cargo
SYSTEMS = serviceregistry authentication consumer-authorization serviceorchestration-dynamic serviceorchestration-simple
.PHONY: build check test contracts docs
build:
	$(CARGO) build --locked --release -p arrowhead-core-rust --bins
	mkdir -p bin
	@for system in $(SYSTEMS); do cp ../target/release/$$system bin/$$system; done
check:
	$(CARGO) fmt --check
	$(CARGO) clippy --locked --all-targets -- -D warnings
test:
	$(CARGO) test --locked --all-targets
contracts:
	$(CARGO) run --locked -p arrowhead-core-rust --bin core-documentation -- ../../Eclipse-Arrowhead-java/ah5-core-java-spring ../../Arrowhead/ah5-common-java-spring
docs: contracts
	cd documentation && pdflatex -interaction=nonstopmode -halt-on-error Rust-Core-Systems.tex
	cd documentation && pdflatex -interaction=nonstopmode -halt-on-error Rust-Core-Systems.tex
	cd documentation && pdflatex -interaction=nonstopmode -halt-on-error Rust-Core-Systems.tex
	mkdir -p output/pdf
	cp documentation/Rust-Core-Systems.pdf output/pdf/Rust-Core-Systems.pdf
