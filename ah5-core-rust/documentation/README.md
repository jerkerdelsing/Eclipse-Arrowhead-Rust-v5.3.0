# Arrowhead LaTeX documents

The five system directories contain editable SysD (system description), SysDD (system design), SD (service description) and HTTPS IDD (interface design) documents. All are marked **DEVELOPMENT**, targeting system version 5.2.2. They describe the delivered Rust profile and its real limitations, not a completed equivalence certification.

The original `arrowhead.cls` and logo come from the local Arrowhead roadmap LaTeX templates. The native Rust generator in `src/bin/documentation.rs` writes the documents, configuration examples and `contracts.json` source/route audit. Make durable document changes in the generator. Do not put operational configuration or secrets in the generated example directory.

From the repository root:

```sh
make docs
```

The combined source is `Rust-Core-Systems.tex`; the final preview is `output/pdf/Rust-Core-Systems.pdf`. The build uses local LaTeX, with three passes to resolve the Arrowhead class's contents and total-page metadata. Compile an individual document from this directory:

```sh
pdflatex -interaction=nonstopmode -halt-on-error Authentication/Authentication-SysDD.tex
pdflatex -interaction=nonstopmode -halt-on-error Authentication/Authentication-SysDD.tex
```

The documents use additional class/logo assets and are not standalone single-file compiler inputs. Their method/path and access tables are generated from the same route inventory used by the Rust runtime. DTO fields and their exact Java source provenance remain in the hashed reference inventory; exhaustive DTO/error semantics and protocol parity require the separate release gates in `COMPATIBILITY.md`.

The source audit deliberately preserves class-qualified Java constants so identical unqualified constant names in different modules cannot silently mix interface paths. It fails when a mapped path is unresolved or missing. Matching a path does not prove equivalent behavior, policy or persistence.
