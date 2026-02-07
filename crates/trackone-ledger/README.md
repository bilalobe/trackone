# trackone-ledger

`trackone-ledger` is the Rust home for TrackOne’s ledger/commitment rules:

- Canonical JSON encoding (ADR-003)
- Merkle policy (ADR-003): SHA-256 leaves, hash-sorted ordering, duplicate-last, empty-root
- Block header + day record construction, plus canonical `day.bin` bytes

This crate is intended to be **single-sourced**: both batching and verification
code should call into it to avoid subtle divergence.

When the optional `trackone_core` Rust extension is built (via `crates/trackone-gateway`),
the Python pipeline can call into these rules through `trackone_core.merkle` and
`trackone_core.ledger`.
