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

## What’s in here

- `scripts/gateway/`
- `merkle_batcher.py` — canonicalization → Merkle → block/day files
- `ots_anchor.py` — stamps day blob via OpenTimestamps
- `verify_cli.py` — recompute root and verify OTS proof
- `scripts/pod_sim/` — simulators and crypto test vectors (to be expanded in M#1)
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

## Roadmap

- M#1 (1–2 weeks): Frame verifier stub + pod simulator v2 → end‑to‑end framed ingest
- M#2: Real AEAD (XChaCha20‑Poly1305) with vectors, replay window enforcement
- M#3: Gateway “Ledger” tab JSON and outage logger
- Continuous: Daily OTS anchor/upgrade automation and CLI polish

## Requirements

- Python 3.13+
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
