# trackone-evidence

Rust-native verifier and export runner for the supported TrackOne evidence
bundle contract.

This crate intentionally does not depend on PyO3 or the Python package. It
starts from an existing evidence bundle or pipeline output and proves the
verifier/export policy can execute through Rust surfaces only.
