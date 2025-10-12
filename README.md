# Track1 — Ultra–Low‑Power, Verifiable Telemetry (Barnacle Sentinel)

This repository contains the code and documents for Track1: secure pod→gateway telemetry with daily, publicly verifiable
timestamp proofs (OpenTimestamps), plus deterministic batching and schemas.

**Current Milestone**: M#1 — Framed Telemetry Ingest (v0.0.1-m1)

## Quick start (Milestone#1 — framed ingest)

Run the complete end-to-end pipeline with one command:

```bash
bash scripts/gateway/run_pipeline.sh
```

This demonstrates the full M#1 workflow:

1. **pod_sim --framed** → generates framed telemetry (NDJSON with `{hdr, nonce, ct, tag}`)
2. **frame_verifier.py** → parses frames, enforces replay window, stub-decrypts, emits canonical facts
3. **merkle_batcher.py** → builds Merkle tree, creates block header + day blob
4. **ots_anchor.py** → timestamps day blob via OpenTimestamps
5. **verify_cli.py** → recomputes root, verifies proof

Outputs land in `out/site_demo/`:

- `frames.ndjson` — framed telemetry records
- `facts/*.json` — canonical fact files (one per frame)
- `blocks/*.block.json` — signed-ready block header
- `day/*.bin` — canonical day blob (for OTS)
- `day/*.bin.ots` — OTS proof
- `day/*.json` — human‑readable day record

## Manual step-by-step (M#1)

Run each pipeline step individually:

```bash
# 1) Generate framed telemetry (10 frames from pod-003)
python scripts/pod_sim/pod_sim.py \
  --framed \
  --device-id pod-003 \
  --count 10 \
  --out out/site_demo/frames.ndjson

# 2) Verify frames and extract facts (with replay window=64)
python scripts/gateway/frame_verifier.py \
  --in out/site_demo/frames.ndjson \
  --out-facts out/site_demo/facts \
  --device-table out/site_demo/device_table.json \
  --window 64

# 3) Batch facts into Merkle tree
python scripts/gateway/merkle_batcher.py \
  --facts out/site_demo/facts \
  --out out/site_demo \
  --site an-001 \
  --date 2025-10-07 \
  --validate-schemas

# 4) Anchor the day blob
python scripts/gateway/ots_anchor.py out/site_demo/day/2025-10-07.bin

# 5) Verify Merkle root and OTS proof
python scripts/gateway/verify_cli.py --root out/site_demo
```

## Quick demo (Milestone#0 — canonical batching)

Run the deterministic batch → anchor → verify loop with example facts:

```bash
# 1) Batch example facts → block header + day blob
python scripts/gateway/merkle_batcher.py \
  --facts toolset/unified/examples \
  --out out/site_demo \
  --site an-001 \
  --date 2025-10-07 \
  --validate-schemas

# 2) Anchor the day blob (requires OpenTimestamps client)
python scripts/gateway/ots_anchor.py out/site_demo/day/2025-10-07.bin

# 3) Verify recomputed root matches and OTS proof verifies
python scripts/gateway/verify_cli.py --root out/site_demo
```

## What's in here

### Gateway Scripts (`scripts/gateway/`)

- **frame_verifier.py** — M#1: Framed ingest + replay window protection
    - Parses NDJSON frames with header validation
    - Enforces replay window (default: 64, configurable)
    - Stub decryption (base64 JSON for M#1; real AEAD in M#2)
    - Emits canonical fact JSON files
    - References: ADR-002 (Telemetry Framing, Nonce/Replay Policy)

- **merkle_batcher.py** — Canonicalization → Merkle → block/day files
    - Reads facts/*.json, computes canonical JSON bytes
    - Hash-sorted Merkle leaves (order-independent)
    - Day chaining via prev_day_root (32 zero bytes for day 1)
    - Outputs: blocks/*.block.json, day/*.bin, day/*.json
    - Schema validation with --validate-schemas
    - References: ADR-003 (Canonicalization, Merkle Policy)

- **ots_anchor.py** — OpenTimestamps integration
    - Stamps day.bin → day.bin.ots
    - Graceful fallback (placeholder) if OTS client missing
    - Supports upgrade workflow for pending proofs

- **verify_cli.py** — Root recomputation and OTS verification
    - Recomputes Merkle root from facts/
    - Compares against block header and day record
    - Verifies OTS proof (or placeholder)
    - Exit 0 on success, non-zero on failure

- **run_pipeline.sh** — M#1 end-to-end automation
    - One-command demonstration of complete framed workflow
    - Configurable parameters (site, date, device, count)

### Pod Simulator (`scripts/pod_sim/`)

- **pod_sim.py** — Device telemetry simulator
    - Plain mode: emits NDJSON facts (M#0)
    - Framed mode (`--framed`): emits `{hdr, nonce, ct, tag}` (M#1)
    - Optional `--facts-out` for cross-check plain facts
    - Configurable device ID, count, sleep interval

- **crypto_test_vectors.json** — Fixed test vectors for AEAD (M#2)

### Schemas (`toolset/unified/schemas/`)

- **fact.schema.json** — Device telemetry fact format
- **block_header.schema.json** — Merkle block header format
- **day_record.schema.json** — Daily record format (with prev_day_root)

### Documentation

- **adr/** — Architecture Decision Records (see index below)
- **src/** — LaTeX manuscript/report files
- **CHANGELOG.md** — Version history and milestone deliverables
- **CONTRIBUTING.md** — PR guidelines, ADR process, CI workflow

### Build Artifacts (git‑ignored)

- **out/** — Pipeline outputs (frames, facts, blocks, day blobs, OTS proofs)

## Design decisions (ADRs)

- **ADR‑001** — Cryptographic Primitives and Framing
    - X25519 + HKDF + XChaCha20‑Poly1305 for AEAD
    - Ed25519 for identity/config/firmware
    - SHA‑256 for Merkle trees

- **ADR‑002** — Telemetry Framing, Nonce/Replay Policy, Device Table
    - Compact frame layout: dev_id(u16), msg_type(u8), fc(u32), flags(u8)
    - 24‑byte XChaCha nonce: salt(8)||fc(8)||rand(8)
    - Gateway replay window with configurable size

- **ADR‑003** — Canonicalization, Merkle Policy, Daily OTS Anchoring
    - Canonical JSON: sorted keys, UTF-8, no whitespace
    - Hash-sorted Merkle leaves for order independence
    - Day chaining via prev_day_root
    - Daily OTS anchoring for public verifiability

See `adr/README.md` for summaries and guidance.

## Tests

Run all tests:

```bash
pytest -q
```

Current test coverage:

### M#0 Tests (Canonical Batching)

- **Canonical JSON determinism**: Byte-identical output across runs
- **Merkle root computation**: Empty, single, odd, power-of-2, order independence
- **Schema validation**: fact, block_header, day_record
- **Day chaining**: prev_day_root linkage
- **End‑to‑end batch/verify**: Complete M#0 workflow

### M#1 Tests (Framed Ingest)

- **Frame parsing**: Valid/invalid frame structure, header validation
- **Replay window**: Accepts increasing fc, rejects duplicates and out-of-window
- **Stub decryption**: Base64-encoded JSON payload handling
- **End‑to‑end pipeline**: pod_sim → frame_verifier → merkle_batcher → verify_cli

### Skipped Tests (M#2 Scope)

- Real AEAD encryption/decryption with test vectors
- Device table key lookup
- Nonce construction from frame counter
- Tag verification

## Frame Format (M#1)

For M#1, frames use NDJSON with JSON objects containing:

```json
{
  "hdr": {
    "dev_id": 3,
    // u16: device ID
    "msg_type": 1,
    // u8: message type (1=measurement)
    "fc": 0,
    // u32: frame counter
    "flags": 0
    // u8: flags (reserved)
  },
  "nonce": "base64...",
  // 24 bytes (XChaCha20 nonce)
  "ct": "base64...",
  // ciphertext (JSON payload for M#1 stub)
  "tag": "base64..."
  // 16 bytes (Poly1305 tag placeholder)
}
```

**M#1 Stub Behavior**:

- `ct` field contains base64-encoded JSON payload (no real encryption)
- `tag` field is a random 16-byte placeholder (not verified)
- Real AEAD (XChaCha20-Poly1305) will be added in M#2

## Determinism Rules

To ensure reproducible Merkle roots and day blobs:

1. **Canonical JSON**: Sorted keys, UTF-8, no whitespace
2. **Hash-sorted leaves**: Merkle tree built from sorted leaf hashes (order-independent)
3. **Fixed number format**: Integers as integers, scaled ints for precision
4. **Day chaining**: Include prev_day_root (32 zero bytes for genesis day)
5. **Consistent timestamps**: Use ISO 8601 UTC format

Running `merkle_batcher.py` twice on the same facts/ yields:

- Identical block header (same merkle_root)
- Byte-identical day.bin (same SHA-256)

## Roadmap

- **M#0** ✅ (v0.0.1-m0): Canonical schemas, deterministic batching, OTS anchoring
- **M#1** ✅ (v0.0.1-m1): Frame verifier stub + pod simulator v2 → framed ingest
- **M#2** (1–2 weeks): Real AEAD (XChaCha20‑Poly1305) with test vectors
- **M#3** (2–3 weeks): Gateway "Ledger" tab JSON, outage logger
- **Continuous**: Daily OTS anchor/upgrade automation, CLI polish

## Requirements

- **Python**: 3.11 or later
- **Required packages**: pytest, jsonschema
- **Optional**: OpenTimestamps client (`ots`) for real proof anchoring

Install dependencies:

```bash
# Production dependencies
pip install -r requirements.txt

# Development dependencies (includes linting tools)
pip install -r requirements-dev.txt

# Or using uv (recommended)
pip install uv
uv pip install -r requirements.txt
uv pip install -r requirements-dev.txt
```

## Development Workflow

### Linting and Formatting

Before committing code, run linting checks:

```bash
# Check code quality and formatting
make lint

# Auto-format code with black
make format

# Auto-fix linting issues
make lint-fix
```

The CI will automatically run these checks on every push/PR.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Pull request guidelines
- ADR process (Proposed → Accepted)
- Code style and testing requirements
- CI workflow and release process

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Citation

If you use this work in your research, please cite:

```bibtex
@software{trackone2025,
    author = {BILAL},
    title = {Track1: Ultra-Low-Power, Verifiable Telemetry (Barnacle Sentinel)},
    year = {2025},
    url = {https://github.com/bilalobe/trackone},
    version = {0.0.1-m1}
}
```

## Contact

- **Author**: BILAL
- **Repository**: https://github.com/bilalobe/trackone
- **Issues**: https://github.com/bilalobe/trackone/issues

For questions about the cryptographic design or OpenTimestamps integration, please open an issue or discussion on
GitHub.
