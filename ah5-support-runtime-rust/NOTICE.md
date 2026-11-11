# Notices

The additional LocalCloudManager nested package is relocated from the local Rust cloud core-systems source, with shared runtime dependencies and embedded UI retained. Its separate Cargo.lock, attribution, source hashes and qualification boundary are recorded in LocalCloudManager/NOTICE.md, docs/source-manifest.json and COMPATIBILITY.md. This legacy HTTP package must not be confused with the parent native-mTLS support implementation described below. No live cloud source/deployment is replaced.

SPDX-License-Identifier: EPL-2.0

This Rust development port derives interfaces and behavior from the local Eclipse Arrowhead support/common Java source and reuses the native Rust core runtime developed in the same workspace. Original Java authors' copyright and Eclipse Arrowhead trademark rights remain with their respective owners. This is not an upstream release endorsement or production certification.

The `documentation/arrowhead.cls` and Arrowhead logo are copied from the project's Arrowhead LaTeX templates; retain their original notices. Source inventory hashes and paths are recorded in `documentation/contracts.json`.

Actual Rust dependencies are recorded in Cargo.toml/Cargo.lock. These include Tokio, Axum/Hyper, rustls/webpki, reqwest, ring, Serde, SHA2, Chrono, UUID, the openssl Rust bindings and vendored OpenSSL (Apache-2.0), plus transitive crates. Their respective licenses/notices apply and must accompany redistribution. Unlike the core port, this support port links the OpenSSL library for certificate functions. Runtime certificate work does not invoke the OpenSSL executable; isolated PKI tests do.
