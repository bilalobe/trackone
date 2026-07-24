# trackone-evidence application

Rust-native verifier and export application for the supported TrackOne
evidence-bundle contract. The package provides both the `trackone-evidence`
CLI and a reusable Rust library for callers that need the same verification
and export policy.

## Boundary and ownership

This application starts from an existing evidence bundle or pipeline output.
It does not ingest telemetry, own gateway state, or publish lifecycle data. It
depends directly on [`trackone-ots`](../../crates/trackone-ots/README.md) and
[`trackone-rfc3161`](../../crates/trackone-rfc3161/README.md) for timestamp
proof, metadata, and TSA signer-certificate verification; it never reaches through the
gateway service and contains no PyO3 or Python runtime dependency.

The library implementation is split into `verify`, `export`, `policy`,
`manifest`, `bundle`, `git_ops`, and `v2` modules. Stable public types and entry
points remain re-exported from the crate root.

## CLI

Verify a v1 bundle:

```bash
cargo run --locked -p trackone-evidence -- verify \
  --root out/site_demo \
  --facts out/site_demo/facts
```

Use `--policy-mode strict --require-ots` when a complete OTS attestation is
required. `--disclosure-class A|B|C`, `--commitment-profile-id ID`, and
`--json` control the verification policy and output shape.

Verify a draft-08 v2 bundle:

```bash
cargo run --locked -p trackone-evidence -- verify-v2 \
  --root toolset/vectors/verifiable-telemetry-canonical-cbor-v2/fixtures/corrected-epoch-class-a \
  --tsa-ca-file toolset/vectors/verifiable-telemetry-canonical-cbor-v2/trust/tsa-root.pem \
  --tsa-crls-file toolset/vectors/verifiable-telemetry-canonical-cbor-v2/trust/tsa-crls.pem \
  --tsa-policy 1.3.6.1.4.1.55555.1 \
  --tsa-signer-cert-sha256 14ab98cafe09d9d1d01562af42d69a904b01023d9cd5b03bd07e5779710c8014
```

Use `--tsa-intermediates-file` when the deployment validation archive has an
intermediate CA. JSON results expose the signed TSA-asserted generation time,
serial number, and optional accuracy. Historical path evaluation at that time
does not prove when the token was first observed.

Export a curated day-scoped bundle from pipeline output:

```bash
cargo run --locked -p trackone-evidence -- export \
  --pipeline-dir out/site_demo \
  --evidence-repo /path/to/evidence \
  --site an-001 \
  --day 2025-10-07
```

Export options include `--include-frames`, `--git-commit`, `--tag`,
`--tag-name`, and `--bundle-out`. The command prints the resulting bundle path
on success.

## Checks

```bash
cargo test --locked -p trackone-evidence
cargo test --locked -p trackone-evidence --test v2_vector_bundles
```
