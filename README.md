# Track1 — Ultra–Low‑Power, Verifiable Telemetry (Barnacle Sentinel)

This repository contains the code and documents for Track1: secure pod→gateway telemetry with daily, publicly verifiable
timestamp proofs (OpenTimestamps), plus deterministic batching and schemas.

## Quick demo (Milestone#0)

Run the deterministic batch → anchor → verify loop:

```bash  
1) Batch example facts → block header + day blob  
python scripts/gateway/merkle_batcher.py \  
--facts toolset/unified/examples \  
--out out/site_demo \  
--site an-001 \  
--date 2025-10-07 \  
--validate-schemas  
2) Anchor the day blob (requires OpenTimestamps client)  
python scripts/gateway/ots_anchor.py out/site_demo/day/2025-10-07.bin  
3) Verify recomputed root matches and OTS proof verifies  
python scripts/gateway/verify_cli.py --root out/site_demo  
```

Artifacts:

- `out/site_demo/blocks/2025-10-07-00.block.json` — signed-ready block header
- `out/site_demo/day/2025-10-07.bin` — canonical day blob (for OTS)
- `out/site_demo/day/2025-10-07.bin.ots` — OTS proof
- `out/site_demo/day/2025-10-07.json` — human‑readable day record

## Quick start (Milestone#1 — framed ingest)

Simulate framed telemetry, verify/decrypt (stub), batch, anchor, and verify in one go:

```bash
bash scripts/gateway/run_pipeline.sh
```

This runs:
- `pod_sim --framed` to produce NDJSON frames with `{hdr, nonce, ct, tag}` fields
- `frame_verifier.py` to enforce a replay window and emit canonical facts
- `merkle_batcher.py --validate-schemas` to build Merkle/Day artifacts
- `ots_anchor.py` to create an OTS proof (placeholder if client missing)
- `verify_cli.py --facts` to recompute and check the Merkle root and proof

Outputs land in `out/site_demo/`.

## What’s in here

- `scripts/gateway/`
  - `frame_verifier.py` — framed ingest + replay window (stub decrypt)
  - `merkle_batcher.py` — canonicalization → Merkle → block/day files
  - `ots_anchor.py` — stamps day blob via OpenTimestamps
  - `verify_cli.py` — recompute root and verify OTS proof
- `scripts/pod_sim/` — simulators and crypto test vectors (M#1 adds `--framed`)
- `toolset/unified/schemas/` — JSON Schemas for facts, block headers, day records
- `adr/` — Architecture Decision Records (see index below)
- `src/` — report/manuscript files (if applicable)
- `out/` — build artifacts (git‑ignored)

## Design decisions (ADRs)

- ADR‑001 — Cryptographic Primitives and Framing: X25519 + HKDF + XChaCha20‑Poly1305; Ed25519; SHA‑256
- ADR‑002 — Telemetry Framing, Nonce/Replay Policy, Device Table
- ADR‑003 — Canonicalization, Merkle Policy, Daily OTS Anchoring

See `adr/README.md` for summaries and guidance.

## Tests

```bash
pytest -q
```

Current coverage includes:

- Canonical JSON determinism
- Merkle root computation (empty/single/odd/power-of-2, order independence)
- Schema validation (fact, block, day)
- Day chaining (prev_day_root)
- End‑to‑end batch/verify workflow
- Framed ingest: parsing, replay windowing, and E2E pipeline

## Roadmap

- M#1 (1–2 weeks): Frame verifier stub + pod simulator v2 → end‑to‑end framed ingest
- M#2: Real AEAD (XChaCha20‑Poly1305) with vectors, replay window enforcement
- M#3: Gateway “Ledger” tab JSON and outage logger
- Continuous: Daily OTS anchor/upgrade automation and CLI polish

## Requirements

- Python 3.11.x
- Pytest, jsonschema, OpenTimestamps client (optional for real proofs)

Install:

```bash
uv pip install -r requirements.txt || true
uv pip install jsonschema pytest
```

OpenTimestamps client (system package or pip):

```bash
pip install opentimestamps-client
```

## Contributing

- Use feature branches and small PRs (tests passing).
- Reference ADR IDs in PRs.
- Keep generated artifacts (`out/`, `*.bin`, `*.bin.ots`, `*.sha256`) out of git.

## License

See `LICENSE`.
