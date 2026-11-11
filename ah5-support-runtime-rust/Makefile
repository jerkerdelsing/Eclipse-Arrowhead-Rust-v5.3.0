JAVA_SUPPORT ?= ../../Arrowhead/ah5-support-java-spring
JAVA_COMMON ?= ../../Arrowhead/ah5-common-java-spring
.PHONY: build test check contracts docs docs-all
build:
	cargo build --locked --bins
	$(MAKE) -C ../ah5-LocalCloudManager-rust build
test:
	cargo test --locked
	$(MAKE) -C ../ah5-LocalCloudManager-rust test
check:
	cargo fmt -- --check
	cargo clippy --locked --all-targets -- -D warnings
	$(MAKE) -C ../ah5-LocalCloudManager-rust check
contracts:
	cargo run --locked -p arrowhead-support-rust --bin support-documentation -- "$(JAVA_SUPPORT)" "$(JAVA_COMMON)" documentation
docs:
	mkdir -p output/pdf tmp/latex
	cd documentation && pdflatex -interaction=nonstopmode -halt-on-error -output-directory=../tmp/latex Rust-Support-Systems.tex > ../tmp/latex/master-pass1.log
	cd documentation && pdflatex -interaction=nonstopmode -halt-on-error -output-directory=../tmp/latex Rust-Support-Systems.tex > ../tmp/latex/master-pass2.log
	cd documentation && pdflatex -interaction=nonstopmode -halt-on-error -output-directory=../tmp/latex Rust-Support-Systems.tex > ../tmp/latex/master-pass3.log
	cp tmp/latex/Rust-Support-Systems.pdf output/pdf/
	$(MAKE) -C ../ah5-LocalCloudManager-rust docs
docs-all:
	mkdir -p tmp/latex
	cd documentation && for source in */*.tex Compatibility-Annex.tex; do pdflatex -interaction=nonstopmode -halt-on-error -output-directory=../tmp/latex "$$source" > ../tmp/latex/compile-last.log || exit 1; done
	$(MAKE) -C ../ah5-LocalCloudManager-rust docs

.PHONY: localcloudmanager localcloudmanager-docs
localcloudmanager:
	$(MAKE) -C ../ah5-LocalCloudManager-rust build
localcloudmanager-docs:
	$(MAKE) -C ../ah5-LocalCloudManager-rust docs
