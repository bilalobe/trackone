# TrackOne

TrackOne is an alpha-stage telemetry and verification workspace for low-power devices, gateway-side ingest, deterministic artifact generation, and publishable release artifacts.

The repository combines:

- Python tooling for gateway, verification, and demo/pipeline flows
- Rust workspace crates for shared protocol, ingest, ledger, gateway bindings, and pod firmware helpers
- Machine-readable contract artifacts, conformance vectors, and example statements under `toolset/`
- Helm packaging for Kubernetes deployment
- Release automation for crates, wheels, and chart artifacts

[![crates.io](https://img.shields.io/crates/v/trackone-core)](https://crates.io/crates/trackone-core)
[![crates.io](https://img.shields.io/crates/v/trackone-constants)](https://crates.io/crates/trackone-constants)
[![crates.io](https://img.shields.io/crates/v/trackone-ingest)](https://crates.io/crates/trackone-ingest)
[![crates.io](https://img.shields.io/crates/v/trackone-gateway)](https://crates.io/crates/trackone-gateway)
[![crates.io](https://img.shields.io/crates/v/trackone-pod-fw)](https://crates.io/crates/trackone-pod-fw)
[![crates.io](https://img.shields.io/crates/v/trackone-ledger)](https://crates.io/crates/trackone-ledger)
[![PyPI](https://img.shields.io/pypi/v/trackone)](https://pypi.org/project/trackone/)

## What TrackOne is for

TrackOne is organized around a simple idea:

- Device-side telemetry should be bounded and replay-resistant
- Gateway-side processing should converge toward canonical, deterministic artifacts
- Verification outputs should be machine-checkable and releaseable
- Deployment artifacts should be reproducible and version-aligned

At a high level, the repo covers:

- Shared protocol and crypto-adjacent types
- Deterministic canonicalization and ledger helpers
- Python-facing gateway bindings
- Pod firmware support helpers
- Pipeline/demo and verification tooling
- Kubernetes packaging via Helm

## Repository layout

```
.
├── crates/                  # Rust workspace crates
│   ├── trackone-core
│   ├── trackone-constants
│   ├── trackone-ingest
│   ├── trackone-ledger
│   ├── trackone-gateway
│   └── trackone-pod-fw
├── src/trackone_core/       # Python package surface for native bindings
├── scripts/                 # Gateway/demo/verification tooling
├── tests/                   # Python test suites
├── toolset/                 # Schemas, CDDL, vectors, and example statement payloads
├── deploy/helm/trackone/    # Helm chart
├── docs/                    # Project documentation
├── adr/                     # Architecture Decision Records
├── Cargo.toml               # Rust workspace root
└── pyproject.toml           # Python package + tooling config
```

## Main components

### Rust workspace crates

- `trackone-core` — core protocol types, crypto-facing traits, and shared invariants
- `trackone-constants` — shared constants used across crates
- `trackone-ingest` — framed Postcard ingest, replay, fixtures, and pod emission helpers
- `trackone-ledger` — canonicalization and deterministic ledger/commitment helpers
- `trackone-gateway` — PyO3-backed Rust gateway crate exposed to Python
- `trackone-pod-fw` — firmware-side helpers for pod integration

Current seal/keylock-boundary note:

- `trackone-ledger` presently also carries the low-level digest / `hex64`
  primitives used by the trust-root sealing path; this is intentionally **not**
  a separate `trackone-seal` crate yet. See
  [`ADR-046`](adr/ADR-046-sealed-trust-root-boundary-and-deferring-trackone-seal.md).

### Python/tooling side

- `src/trackone_core/` — Python package wrapper around the native extension
- `scripts/` — gateway, verification, and demo pipeline scripts
- `tests/` — unit, integration, and end-to-end validation

Current `trackone_core` surface labels:

- `stable`: `trackone_core.ledger`, `trackone_core.merkle`, `trackone_core.release`
- `provisional`: `trackone_core.crypto`, `trackone_core.ots`, top-level `Gateway`, `GatewayBatch`
- `experimental`: `trackone_core.radio`, top-level `PyRadio`
- `internal`: `trackone_core._native`

Current `scripts.gateway` surface labels:

- `stable`: `frame_verifier`, `merkle_batcher`, `verification_manifest`, `verify_cli`
- `provisional`: `canonical_cbor`, `input_integrity`, `ots_anchor`, `provisioning_records`, `sensorthings_projection`, `verification_gate`
- `experimental`: `peer_attestation`, `tsa_stamp`
- `internal`: config/schema/TSA helper modules and consistency-check helpers

Current `scripts.evidence` surface labels:

- `provisional`: `export_release`

Current `scripts.pod_sim` surface labels:

- `experimental`: `pod_sim`, `parity_check`

### Deployment side

- `deploy/helm/trackone/` — Helm chart for published-artifact deployments and optional local overrides

## Quick start

### Python development setup

This project uses **uv** for Python environment and dependency management.

```bash
uv sync
```

The root `dev` dependency group is included by default for local `uv sync`.
If you also want the broader CI/test/security tool surface:

```bash
uv sync --extra ci --extra test --extra security
```

PyNaCl is opt-in. Add the extra that matches the helper surface you need:

- `uv sync --extra peer-signatures` for experimental peer attestation helpers
- `uv sync --extra legacy-crypto` for legacy/dev PyNaCl helpers, parity checks, vector regeneration, and benchmark paths

### Rust workspace checks

```bash
cargo check --workspace
cargo test --workspace
```

### Python test run

```bash
uv run pytest
```

The default Python test/tooling path does not require PyNaCl. Tests that
exercise optional peer-signature or legacy PyNaCl helpers are installed
explicitly in tox or by adding the corresponding extra above.

## Common developer workflows

### Run focused Rust checks

```bash
cargo check -p trackone-core
cargo test -p trackone-ledger
cargo test -p trackone-pod-fw --features std
```

### Build the Python extension locally

```bash
uv run maturin develop --manifest-path crates/trackone-gateway/Cargo.toml
```

### Supported root workflows

The supported local path for the current evidence spine is:

```bash
# One-time environment setup
just setup-dev

# Build/update the native extension
just native-dev

# Generate the default demo evidence set
just demo

# Re-run verification against the default output
just verify

# Run the Python benchmark suite
just bench

# Run the Rust-only serialization benchmarks
just bench-rust
```

Notes:

- `just demo` writes to `out/site_demo` by default; override with `just demo out_dir=out/other_demo`.
- `just verify` defaults to `out/site_demo`; override with `just verify out_dir=out/other_demo`.
- `just bench` runs the Python (`tox -e bench`) pytest-benchmark suite.
- `just bench-rust` runs the Rust-side serialization benchmark report through
  the current `trackone-core` cargo test target.

### Run project-wide quality checks

```bash
uv run tox
```

Or run a focused tox environment:

```bash
uv run tox -e lint
uv run tox -e type
uv run tox -e security
```

## Releases

Tagged releases publish release artifacts through GitHub Actions.

Current release outputs include:

- Rust crates
- Python wheel artifacts
- Helm chart OCI artifacts

Version alignment matters across workspace crates, Python packaging, and deployment artifacts, so release cuts should be treated as coordinated workspace releases rather than isolated per-language bumps.

## Deployment

### Recommended: install the published Helm chart artifact

For normal deployments, use the published OCI chart:

```bash
helm upgrade --install trackone oci://ghcr.io/<owner>/trackone/charts/trackone \
  --version <release-version> \
  --namespace trackone \
  --create-namespace \
  --set postgres.auth.existingSecret=<your-postgres-secret>
```

If registry images are private, add your image-pull secret and any deployment-specific values overrides.

### Optional local / Minikube-style workflow

Use the local chart and local image overrides only when you explicitly want local image builds and in-cluster development behavior.

```bash
eval "$(minikube -p ${MINIKUBE_PROFILE:-minikube} docker-env)"
docker build -t trackone/ots-calendar:local -f deploy/docker/calendar/Dockerfile deploy/docker/calendar
docker build -t trackone/gateway:local -f deploy/docker/gateway/Dockerfile .
docker build -t trackone/core:local -f deploy/docker/core/Dockerfile .
docker build -t trackone/constants:local -f deploy/docker/constants/Dockerfile .
docker build -t trackone/pod-fw:local -f deploy/docker/pod-fw/Dockerfile .
helm upgrade --install trackone deploy/helm/trackone \
  -f deploy/helm/trackone/values-local.yaml
```

For detailed chart configuration and deployment options, see [`deploy/helm/trackone/README.md`](deploy/helm/trackone/README.md).

## How it works (pipeline)

End-to-end (see `scripts/gateway/run_pipeline_demo.py`):

1. A Rust producer emits postcard framed telemetry (`rust-postcard-v1`).
1. Gateway verifies frames through native Rust admission, enforces replay window, and projects accepted frames into canonical facts (`frame_verifier.py`).
1. Gateway derives a read-only SensorThings projection from the verified fact set (`sensorthings_projection.py`).
1. Facts are batched into a daily Merkle tree and persisted with headers (`merkle_batcher.py`).
1. Day blob is anchored with OpenTimestamps (`ots_anchor.py`).
1. Independent verification recomputes the Merkle root and checks the OTS proof (`verify_cli.py`).

Outputs live under `out/site_demo/` by default:

- `facts/` — authoritative canonical CBOR facts plus JSON projections
- `blocks/` — block headers that record the authoritative daily Merkle root
- `day/` — the day evidence set / anchoring set for the run
- `day/YYYY-MM-DD.cbor` — the authoritative day blob
- `day/YYYY-MM-DD.cbor.ots` — the OpenTimestamps proof for the day blob
- `day/YYYY-MM-DD.ots.meta.json` — day-local OTS metadata bound to the artifact/proof pair
- `day/YYYY-MM-DD.verify.json` — verifier-facing manifest with relative artifact refs and digests
- `provisioning/authoritative-input.json` — authoritative deployment/provisioning input for the run
- `provisioning/records.json` — canonical provisioning-record bundle used for projection context
- `sensorthings/YYYY-MM-DD.observations.json` — read-only SensorThings-style projection artifact

For a Git-published evidence set, keep:

- `facts/`, `blocks/`, `day/`, `provisioning/authoritative-input.json`, `provisioning/records.json`, `sensorthings/`, and the verification manifest
- `frames.ndjson` only when raw framed input disclosure is intended for that bundle

The supported framed ingest profile is `rust-postcard-v1`. The verifier-facing
public authority is the post-projection deterministic CBOR commitment profile,
`trackone-canonical-cbor-v1`; JSON files are projections for inspection and
tooling.

Do not publish workspace/runtime residue:

- `device_table.json` — runtime replay/key state only
- `audit/` — local rejection diagnostics; schema-governed operator evidence,
  not beta public-spine commitment artifacts

The verification manifest `day/<date>.verify.json` is publication-safe and
part of the public spine: it carries relative artifact refs plus digests,
disclosure-class metadata, executed/skipped checks, and does not embed
host-local verifier paths.

Git-publishable evidence bundles can be exported with:

- `scripts/evidence/export_release.py` — verifier-gated evidence export that copies the curated evidence subset into a day-scoped bundle layout and can optionally commit, tag, and bundle the result in a dedicated evidence repo.

Machine-readable contract split:

- JSON projection and operational artifact contracts live under `toolset/unified/schemas/` as JSON Schema.
- The verifier-facing day manifest contract is described by `toolset/unified/schemas/verify_manifest.schema.json`.
- The authoritative CBOR commitment family is described separately in `toolset/unified/cddl/commitment-artifacts-v1.cddl`.
- The public commitment-vector manifest contract is described by `toolset/unified/schemas/commitment_vector_manifest.schema.json`.
- The public commitment-vector fact projection contract is described by `toolset/unified/schemas/commitment_fact_projection.schema.json`; it is intentionally separate from the runtime `fact.schema.json` shape.
- Rejection audit records are described by `toolset/unified/schemas/rejection_audit.schema.json`; they explain non-admission decisions for operators and auditors, but are not part of the day commitment profile unless promoted to a future artifact family.
- SCITT statement payload shapes and examples live under:
  - `toolset/unified/schemas/scitt_*.schema.json`
  - `toolset/unified/cddl/scitt-statements-v1.cddl`
  - `toolset/unified/examples/scitt_*.json`
- The published canonical CBOR commitment corpus lives under `toolset/vectors/trackone-canonical-cbor-v1/` and is used by Rust/Python parity tests. Its `manifest.json` names the CBOR encoding profile, profile constraints, and ADR-003 Merkle policy so an external verifier can recompute the corpus without inspecting TrackOne source code.

## Current release line

The latest tagged release is `0.1.0-alpha.17`.
The current `main` branch is tracking `alpha.18` follow-on work; release detail for `alpha.17` lives in [`CHANGELOG.md`](CHANGELOG.md), and `Unreleased` tracks the next release work.

- `alpha.17` continued admitted-telemetry hardening:

  - public commitment-vector manifest/fact-projection contracts are now explicit and source-independent for detached verification
  - independent verifier/public-contract hardening now enforces canonical CBOR shortest-form rules and stricter portable-manifest semantics
  - runtime/exported fact JSON now uses lowercase public `kind` labels (`env.sample`, `pipeline.event`, `health.status`, `custom.raw`) while preserving stable Rust CBOR discriminants

- `alpha.15` hardened the admitted-telemetry boundary:

  - native framed decrypt/material validation remains authoritative
  - replay admission and duplicate/out-of-window rejection on the supported framed-ingest path now have a native owner
  - accepted framed telemetry is shaped into canonical facts through the native gateway seam before Python persists artifacts
  - Python still owns the workflow executor, file lifecycle, audit logging, schema-routing, and broader reporting/export choreography
  - verifier output, manifest rewriting, and projection helpers now share release/reporting/domain helper surfaces under `trackone_core`

- `alpha.14` hardened the current public spine:

  - verifier-facing `day/<date>.verify.json`
  - published canonical CBOR commitment vectors and Rust/Python parity gates
  - native `sha256_hex` / `hex64` helpers on the Python/Rust boundary
  - manifest-backed local verification gates before export/publication
  - separate authoritative provisioning input under `provisioning/authoritative-input.json`
  - schema-backed read-only SensorThings projection artifacts
  - shared Rust/Python release constants for `commitment_profile_id` and disclosure classes
  - SCITT statement payload contracts and examples
  - sealed trust-root boundary documentation in [`ADR-046`](adr/ADR-046-sealed-trust-root-boundary-and-deferring-trackone-seal.md)

- `alpha.18` is currently focused on follow-on hardening beyond the current admitted-telemetry cut.

For release-level detail, use [`CHANGELOG.md`](CHANGELOG.md) rather than this README.

## Documentation

- `adr/` — architecture decisions and protocol boundaries
- `docs/` — supporting docs and operational notes
- `docs/evidence-bundle-roundtrip.md` — detached export/import verification flow
- Per-crate `README.md` files under `crates/` — crate-local purpose and usage
- `CHANGELOG.md` — workspace-level release notes

## Configuration knobs

Most demo defaults are set in `scripts/gateway/run_pipeline_demo.py`, and the
supported root workflow is exposed through the `justfile`.

- `PIPELINE_SITE` / `--site` (default: `an-001`)
- `PIPELINE_DATE` / `--date` (default: `2025-10-07`)
- `PIPELINE_DEVICE_ID` / `--device-id` (default: `pod-003`)
- `PIPELINE_FRAME_COUNT` / `--frame-count` (default: `7`)
- `PIPELINE_OUT_DIR` / `--out-dir` (default: `out/site_demo`)

You can also pass CLI flags to individual scripts (see `--help` on each):

- `frame_verifier.py` supports `--window`, `--device-table`, etc.
- `merkle_batcher.py` supports `--facts`, `--out`, `--site`, `--date`, `--validate-schemas`.
- `verify_cli.py` supports `--root` and `--facts`.

## OpenTimestamps configuration

The gateway uses OpenTimestamps (OTS) to anchor daily Merkle roots. There are three environment variables that control how the OTS client behaves:

- `OTS_STATIONARY_STUB`

  - When set to `1`, `scripts/gateway/ots_anchor.py` does **not** call the real `ots` binary. Instead it writes a deterministic stub proof (`STATIONARY-OTS:<sha256(day.cbor)>`) and day-local OTS metadata into the `day/` evidence set. This mode is used by the test suite to avoid slow or flaky network calls.

  - Default in tests (via `tests/conftest.py`): `OTS_STATIONARY_STUB=1`.

  - To exercise the real OTS client, unset or override this variable:

    ```bash
    OTS_STATIONARY_STUB=0 pytest -m real_ots
    ```

- `OTS_CALENDARS`

  - Optional comma-separated list of calendar URLs that is forwarded to the underlying `ots` client via the `OTS_CALENDARS` environment variable.

  - Example (local real calendar first, then public):

    ```bash
    export OTS_CALENDARS="http://127.0.0.1:8468,https://a.pool.opentimestamps.org"
    python scripts/gateway/ots_anchor.py out/site_demo/day/2025-10-07.cbor
    ```

- `RUN_REAL_OTS`

  - Used by a small set of integration tests (marked `real_ots`) to control whether they should exercise the real `ots` client.

  - These tests are **skipped by default**. To run them (for example against a locally running OTS calendar), use:

    ```bash
    export OTS_STATIONARY_STUB=0
    export OTS_CALENDARS="http://127.0.0.1:8468"
    export RUN_REAL_OTS=1
    pytest -m real_ots tests/integration/test_ots_integration.py
    ```

In day-to-day development and CI, you do not need to configure anything: tests run in stationary stub mode and still enforce the `ots_meta` + artifact hashing contract without talking to external calendaring services.

## Testing

We use pytest, tox, and `just`:

```bash
# Fast local run
pytest -q

# Multi-env via tox (3.12, 3.13, 3.14)
tox -e py312,py313,py314

# Coverage reports
tox -e coverage

# Lint and type-check
tox -e lint
tox -e type

# End-to-end tests
tox -e e2e

# Supported corpus-backed benchmark run
just bench
```

Real OTS integration tests require `RUN_REAL_OTS=1` and an `ots` binary in PATH:

```bash
RUN_REAL_OTS=1 tox -e slow
```

## Legacy Makefile shortcuts

Useful targets (run `make help` for the full list):

- `make install` — install runtime dependencies
- `make dev-setup` — install dev dependencies (lint, typing, tests, security)
- `make export-requirements` — export pinned `out/requirements*.txt` from `uv.lock`
- `make run` — run the end-to-end pipeline via tox
- `make test` — run the test suite
- `make tox-readme` — format/validate README and ADR index
- `make tox-security` — Bandit and pip-audit
- `make bench` — run pytest-benchmark suite

The supported root workflow for local demo/verify/benchmark paths is now the
`justfile`; keep using the Makefile for older compatibility flows and targeted
tox wrappers.

## Security notes

- Cryptographic randomness and nonce policy are documented in ADR-018; we standardize on OS-backed CSPRNGs.
- AEAD is XChaCha20-Poly1305 with a 24-byte nonce (salt||fc||rand) per ADR-002.
- OTS verification uses a validated full path to `ots` and avoids shells; tests include placeholder paths and mocks.
- For production use, run security scans and audits:

```bash
tox -e security
```

## Project status

TrackOne is currently in an **alpha** phase.

That means:

- APIs and release boundaries may still tighten
- Crate surfaces are stabilizing, but not yet final
- Deployment and verification workflows are actively being refined
- Changelogs and ADRs should be treated as the source of truth for current release behavior

## Contributing

Contributions are welcome! Please read `CONTRIBUTING.md`, file or reference ADRs for significant changes, and keep tests green. We follow a forward-only schema policy (ADR-006) and document major decisions as ADRs.

Schema notes:

- JSON artifact contracts live under `toolset/unified/schemas/`.
- Shared reusable JSON Schema definitions live in `toolset/unified/schemas/common.schema.json`.
- Runtime schema loading and cross-file `$ref` resolution are centralized in `scripts/gateway/schema_validation.py`.
- New schema work should use JSON Schema draft 2020-12 and prefer `$defs` / `$ref` reuse over copy-pasted inline fragments.

## License

MIT — see `LICENSE`.

## Links

- Repository: https://github.com/bilalobe/trackone
- ADR index: `adr/README.md`
- Changelog: `CHANGELOG.md`
