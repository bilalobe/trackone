# trackone-evidence application

Rust-native verification and deterministic compaction for the active
Verifiable Telemetry Ledgers profile. The package provides the
`trackone-evidence` CLI and a reusable Rust `vtl` module.

## Boundary and ownership

This application starts from an existing VTL evidence bundle. It does not
ingest telemetry, own gateway state, export legacy day bundles, or publish
lifecycle data. Timestamp verification is delegated to
[`trackone-rfc3161`](../../crates/trackone-rfc3161/README.md); the application
has no Python runtime dependency.

Producer manifest version 1 is the only accepted and emitted envelope. Verifier
results carry no version member: they are verifier-authored output identified by
`verifier_policy_id`, not a producer-supplied input. The current slate has no
aliases or compatibility shims for the former manifest v2/v3 formats.

Internally, the VTL implementation separates producer-manifest parsing from
untrusted bundle access. The manifest module owns typed envelope decoding and
duplicate-name rejection; the path module owns portable-path validation,
bounded reads, digest-bound artifact access, and Linux race-resistant opening.
Verification and deterministic carriage consume those boundaries rather than
performing direct filesystem access.

## Verify

Verify a directory bundle:

```bash
cargo run --locked -p trackone-evidence -- verify \
  --root BUNDLE \
  --tsa-ca-file tsa-root.pem \
  --tsa-crls-file tsa-crls.pem \
  --tsa-policy 1.3.6.1.4.1.55555.1 \
  --tsa-signer-cert-sha256 HEX \
  --json --pretty
```

Use `--tsa-intermediates-file` when the deployment validation archive has an
intermediate CA. The baseline TSA channel is mandatory; a pending producer
claim produces an incomplete result, while unavailable state produces a
failed result. Use
`--tsa-max-future-skew-seconds` to set the deployment's accepted clock-skew
bound. `--verifier-policy-id` and `--verifier-policy-file` bind an explicit
verifier policy.

The claimed disclosure class and the exercised verification scope are
separate. By default Class A selects `public_recompute`, Class B selects
`disclosed_batch_recompute`, and Class C selects `anchor_only`. A verifier can
deliberately exercise a narrower scope:

```bash
trackone-evidence verify --root BUNDLE \
  --scope disclosed_batch_recompute --batch 3 --batch 4 \
  --json
```

`--batch` selects complete Class A batches and is valid only with
`disclosed_batch_recompute`. `--require-claimed-scope` turns deliberate downscoping
into a `scope_not_exercised` failure. Anchor-only verification does not read
record-opening artifacts; disclosed-batch recomputation reads only the selected
complete batches.

## Compact and replay

Create a deterministic gzip carrier and verify it through the same policy:

```bash
trackone-evidence compact --root BUNDLE --output bundle.tar.gz \
  --tsa-ca-file tsa-root.pem --tsa-crls-file tsa-crls.pem \
  --tsa-policy 1.3.6.1.4.1.55555.1 --tsa-signer-cert-sha256 HEX

trackone-evidence verify --archive bundle.tar.gz \
  --tsa-ca-file tsa-root.pem --tsa-crls-file tsa-crls.pem \
  --tsa-policy 1.3.6.1.4.1.55555.1 --tsa-signer-cert-sha256 HEX \
  --json
```

The deterministic carrier preserves the version-one manifest and each exact
referenced artifact byte string. Use `--include-extensions` only when extension
artifacts intentionally belong in the disclosure.

## Checks

```bash
cargo test --locked -p trackone-evidence
cargo test --locked -p trackone-evidence --test vtl_bundles
```
