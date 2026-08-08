# trackone-evidence application

Rust-native verification and deterministic compaction for the active TrackOne
v2 evidence-bundle contract. The package provides the `trackone-evidence` CLI
and a reusable Rust `v2` module.

## Boundary and ownership

This application starts from an existing v2 evidence bundle. It does not
ingest telemetry, own gateway state, export legacy day bundles, or publish
lifecycle data. Timestamp proof verification is delegated to
[`trackone-ots`](../../crates/trackone-ots/README.md) and
[`trackone-rfc3161`](../../crates/trackone-rfc3161/README.md); the application
has no Python runtime dependency.

Manifest v3 is the only emitted envelope. Manifest v2 remains supported as
read-only input for the unchanged v2 commitment profile. The removed legacy
v1 `verify` and `export` surfaces have no aliases or compatibility shims.

## Verify

Verify a directory bundle:

```bash
cargo run --locked -p trackone-evidence -- verify \
  --root toolset/vectors/verifiable-telemetry-canonical-cbor-v2/fixtures/corrected-epoch-class-a \
  --tsa-ca-file toolset/vectors/verifiable-telemetry-canonical-cbor-v2/trust/tsa-root.pem \
  --tsa-crls-file toolset/vectors/verifiable-telemetry-canonical-cbor-v2/trust/tsa-crls.pem \
  --tsa-policy 1.3.6.1.4.1.55555.1 \
  --tsa-signer-cert-sha256 14ab98cafe09d9d1d01562af42d69a904b01023d9cd5b03bd07e5779710c8014 \
  --json --pretty
```

Use `--tsa-intermediates-file` when the deployment validation archive has an
intermediate CA. `--allow-missing-tsa` changes only the missing-channel
requirement; it does not bypass validation of a supplied timestamp.
`--verifier-policy-id` and `--verifier-policy-file` bind an explicit verifier
policy. JSON results report disclosure scope, executed and skipped checks,
channel states, and the overall outcome.

## Compact and replay

Create a deterministic manifest-v3 gzip carrier and verify it through the same
policy:

```bash
trackone-evidence compact --root BUNDLE --output bundle.v3.tar.gz \
  --tsa-ca-file tsa-root.pem --tsa-crls-file tsa-crls.pem \
  --tsa-policy 1.3.6.1.4.1.55555.1 --tsa-signer-cert-sha256 HEX

trackone-evidence verify --archive bundle.v3.tar.gz \
  --tsa-ca-file tsa-root.pem --tsa-crls-file tsa-crls.pem \
  --tsa-policy 1.3.6.1.4.1.55555.1 --tsa-signer-cert-sha256 HEX \
  --json
```

The carrier media type is
`application/vnd.trackone.evidence-bundle.v3+gzip`. It contains exactly one
bounded gzip member. Class A records are packed as exact CBOR byte strings and
duplicates are retained. Use `--include-extensions` only when extension
artifacts intentionally belong in the disclosure.

## Checks

```bash
cargo test --locked -p trackone-evidence
cargo test --locked -p trackone-evidence --test v2_vector_bundles
```
