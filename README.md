# TrackOne — Ultra‑Low‑Power, Verifiable Telemetry

Secure ingestion, canonicalization, Merkle batching, and public anchoring of sensor telemetry. TrackOne produces an auditable, append‑only ledger of daily telemetry “facts” and anchors each day’s digest to public time via OpenTimestamps (OTS). Auditors can independently recompute Merkle roots and verify proofs without trusting the gateway operator.

Project status: active R&D with a Python‑first reference gateway. See ADRs for design decisions and roadmap.

## Highlights

- Modern cryptography (per ADR‑001):
  - X25519 + HKDF key derivation
  - XChaCha20‑Poly1305 AEAD (24‑byte nonce)
  - Ed25519 signatures
  - SHA‑256 Merkle trees
- Deterministic data model (ADR‑003): canonical JSON, schema validation, hash‑sorted leaves, day chaining.
- Verifiable daily anchoring with OTS, plus CLI to verify roots and proofs end‑to‑end.
- Forward‑only schema/policy (ADR‑006).
- Extensive tests, benchmarks, and ADRs documenting decisions.

## How it works (pipeline)

End‑to‑end (see `scripts/gateway/run_pipeline.sh`):

1. Pod simulator emits framed telemetry (`pod_sim.py --framed`).
1. Gateway verifies frames, enforces replay window, emits canonical facts (`frame_verifier.py`).
1. Facts are batched into a daily Merkle tree and persisted with headers (`merkle_batcher.py`).
1. Day blob is anchored with OpenTimestamps (`ots_anchor.py`).
1. Independent verification recomputes the Merkle root and checks the OTS proof (`verify_cli.py`).

Outputs live under `out/site_demo/` by default:

- `facts/` canonical JSON facts
- `blocks/` block headers that record the authoritative daily Merkle root
- `day/YYYY-MM-DD.bin` the day blob, with `*.ots` proof

## Quick start

Prereqs:

- Python 3.12+ (project tests target 3.12–3.14)
- A virtualenv (recommended)
- Optional: `ots` CLI in your PATH for real OTS verification (tests fall back to placeholders)

Install dependencies (recommended, lockfile-first):

```bash
make dev-setup
```

This installs the full developer toolchain via focused extras:
`.[lint,type,security,test,anchoring]`.

Run the demo pipeline via Make:

```bash
make run
```

Or directly via the script:

```bash
bash scripts/gateway/run_pipeline.sh
```

This generates frames, extracts canonical facts, builds the Merkle day, anchors it, and verifies the result.

## Verify a day manually

The verifier recomputes the Merkle root from facts and checks the OTS proof:

```bash
python scripts/gateway/verify_cli.py \
  --root out/site_demo \
  --facts out/site_demo/facts
```

Optional: verify RFC 3161 TSA timestamps and peer co-signatures:

```bash
# Warn-only mode (default)
python scripts/gateway/verify_cli.py \
  --root out/site_demo \
  --facts out/site_demo/facts \
  --verify-tsa \
  --verify-peers

# Strict mode (fail on missing/invalid TSA or peer artifacts)
python scripts/gateway/verify_cli.py \
  --root out/site_demo \
  --facts out/site_demo/facts \
  --verify-tsa --tsa-strict \
  --verify-peers --peers-strict --peers-min 2
```

Exit codes: 0=OK, 1=missing/invalid block header, 2=Merkle mismatch, 3=missing OTS file, 4=proof failed, 5=TSA failed (strict), 6=peer failed (strict).

If `ots` is not installed, tests and demos can use a placeholder `.ots` proof written by the pipeline script; the verifier treats the string `OTS_PROOF_PLACEHOLDER` as success for local runs.

## Makefile shortcuts

Useful targets (run `make help` for the full list):

- `make install` — install runtime dependencies
- `make dev-setup` — install dev dependencies (lint, typing, tests, security)
- `make export-requirements` — export pinned `out/requirements*.txt` from `uv.lock`
- `make run` — run the end‑to‑end pipeline via tox
- `make test` — run the test suite
- `make tox-readme` — format/validate README and ADR index
- `make tox-security` — Bandit and pip‑audit
- `make bench` — run pytest‑benchmark suite

## Testing

We use pytest and tox:

```bash
# Fast local run
pytest -q

# Multi‑env via tox (3.12, 3.13, 3.14)
tox -e py312,py313,py314

# Coverage reports
tox -e coverage

# Lint and type‑check
tox -e lint
tox -e type

# End‑to‑end tests
tox -e e2e
```

Real OTS integration tests require `RUN_REAL_OTS=1` and an `ots` binary in PATH:

```bash
RUN_REAL_OTS=1 tox -e slow
```

## Configuration knobs

Most demo defaults are set in `scripts/gateway/run_pipeline.sh` and the `Makefile`:

- `SITE` (default: `an-001`)
- `DATE` (default: `2025-10-07`)
- `DEVICE` (default: `pod-003`)
- `COUNT` (default: `10`) — frames to emit
- `OUT_DIR` (default: `out/site_demo`)

You can also pass CLI flags to individual scripts (see `--help` on each):

- `frame_verifier.py` supports `--window`, `--device-table`, etc.
- `merkle_batcher.py` supports `--facts`, `--out`, `--site`, `--date`, `--validate-schemas`.
- `verify_cli.py` supports `--root` and `--facts`.

## OpenTimestamps configuration

The gateway uses OpenTimestamps (OTS) to anchor daily Merkle roots. There are
three environment variables that control how the OTS client behaves:

- `OTS_STATIONARY_STUB`

  - When set to `1`, `scripts/gateway/ots_anchor.py` does **not** call the real
    `ots` binary. Instead it writes a deterministic stub proof
    (`STATIONARY-OTS:<sha256(day.bin)>`) and an `ots_meta` sidecar. This mode is
    used by the test suite to avoid slow or flaky network calls.

  - Default in tests (via `tests/conftest.py`): `OTS_STATIONARY_STUB=1`.

  - To exercise the real OTS client, unset or override this variable:

    ```bash
    OTS_STATIONARY_STUB=0 pytest -m real_ots
    ```

- `OTS_CALENDARS`

  - Optional comma-separated list of calendar URLs that is forwarded to the
    underlying `ots` client via the `OTS_CALENDARS` environment variable.

  - Example (local real calendar first, then public):

    ```bash
    export OTS_CALENDARS="http://127.0.0.1:8468,https://a.pool.opentimestamps.org"
    python scripts/gateway/ots_anchor.py out/site_demo/day/2025-10-07.bin
    ```

- `RUN_REAL_OTS`

  - Used by a small set of integration tests (marked `real_ots`) to control
    whether they should exercise the real `ots` client.

  - These tests are **skipped by default**. To run them (for example against a
    locally running OTS calendar), use:

    ```bash
    export OTS_STATIONARY_STUB=0
    export OTS_CALENDARS="http://127.0.0.1:8468"
    export RUN_REAL_OTS=1
    pytest -m real_ots tests/integration/test_ots_integration.py
    ```

In day-to-day development and CI, you do not need to configure anything: tests
run in stationary stub mode and still enforce the `ots_meta` + artifact hashing
contract without talking to external calendaring services.

## Rust core and PyO3 gateway

TrackOne now includes a Rust workspace used to host the shared core logic and a
Python-facing gateway extension (ADR-017):

- `crates/trackone-core` — platform-agnostic Rust crate for protocol and crypto
  primitives (currently a stub, intended home for Merkle, crypto, and protocol
  invariants).
- `crates/trackone-gateway` — Rust `cdylib` crate exposed to Python via PyO3 and
  built with `maturin`. This crate will gradually wrap `trackone-core` and
  surface optimized operations to Python.
- `crates/trackone-pod-fw` — Rust crate for future pod/firmware logic, depending
  on `trackone-core`.

Python packaging uses `maturin` as the build backend in `pyproject.toml`. Wheels
are built from the `trackone-gateway` crate and installed alongside the
`scripts` package. For most contributors, the Rust layer is optional:

- To build the wheel locally:

  ```bash
  make build-wheel
  # or
  tox -e maturin-build
  ```

- To run Rust tests and checks:

  ```bash
  make cargo-test      # cargo test --workspace
  make cargo-check     # cargo check --workspace --all-targets
  make cargo-fmt       # cargo fmt --all
  make cargo-clippy    # cargo clippy --workspace --all-targets -- -D warnings
  ```

The Python API and CLI remain the canonical interface; Rust is an internal
implementation detail used to accelerate hot paths and to support future
firmware/pod work.

## Project layout

- `scripts/`
  - `pod_sim/` — simulator for framed telemetry (`pod_sim.py`)
  - `gateway/` — gateway components: `frame_verifier.py`, `merkle_batcher.py`, `ots_anchor.py`, `verify_cli.py`, `run_pipeline.sh`
- `crates/`
  - `trackone-core/` — shared Rust core (protocol + crypto, ADR-017)
  - `trackone-gateway/` — PyO3/maturin gateway extension crate
  - `trackone-pod-fw/` — future pod/firmware crate depending on `trackone-core`
- `toolset/` — examples and test vectors (e.g., `toolset/unified/examples/`)
- `tests/` — unit, integration, e2e, and benchmark suites
- `adr/` — Architecture Decision Records and index
- `docs/` — additional documentation (if present)
- `out/` — generated artifacts (git-ignored)

See `adr/README.md` for the full ADR index and implementation status.

## Security notes

- Cryptographic randomness and nonce policy are documented in ADR‑018; we standardize on OS‑backed CSPRNGs.
- AEAD is XChaCha20‑Poly1305 with a 24‑byte nonce (salt||fc||rand) per ADR‑002.
- OTS verification uses a validated full path to `ots` and avoids shells; tests include placeholder paths and mocks.
- For production use, run security scans and audits:

```bash
tox -e security
```

## Contributing

Contributions are welcome! Please read `CONTRIBUTING.md`, file or reference ADRs for significant changes, and keep tests green. We follow a forward‑only schema policy (ADR‑006) and document major decisions as ADRs.

## License

MIT — see `LICENSE`.

## Links

- Repository: https://github.com/bilalobe/trackone
- ADR index: `adr/README.md`
- Changelog: `CHANGELOG.md`

## Setup

### Python environment

TrackOne uses `pyproject.toml` for dependency declarations and commits `uv.lock` for deterministic resolution.

Recommended (developer toolchain):

```bash
make dev-setup
# or (equivalent)
uv pip install -e ".[lint,type,security,test,anchoring]"
```

Notes:

- `tox` is used to run the test matrix and checks; tox installs dependencies via focused extras.
- When you change dependency constraints in `pyproject.toml`, regenerate the lockfile:

```bash
uv lock
```
