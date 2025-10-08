# Changelog

All notable changes to this project will be documented in this file.

## [v0.0.1-m1] - 2025-10-08

Milestone #1: Framed ingest stub and end-to-end pipeline.

Added

- Pod simulator v2 (`scripts/pod_sim/pod_sim.py`): `--framed` NDJSON output with header `{dev_id,msg_type,fc,flags}`,
  base64 nonce/tag placeholders, and `ct` as base64(JSON payload bytes). Also writes plain facts for cross-check when
  `--facts-out` is provided.
- Gateway frame verifier (`scripts/gateway/frame_verifier.py`): parses frames, enforces replay window, stub-decrypts
  payload, validates against `fact.schema.json`, writes canonical facts, persists `device_table.json`.
- One-shot pipeline: `scripts/gateway/run_pipeline.sh` and Makefile `run`/`run-m1` target to run
  `pod_sim → frame_verifier → merkle_batcher --validate-schemas → ots_anchor → verify_cli`.
- Tests: `scripts/tests/test_framed_ingest.py` covering parser, windowing, and end-to-end framed ingest.
- CI: GitHub Actions workflow running `pytest` and `make run` (asserts verify_cli success).

Changed

- `scripts/gateway/verify_cli.py`: supports `--facts` to specify the facts directory for recomputation.
- README: added Milestone #1 quick start; documented Makefile targets.
- Pinned Python to 3.11 (pyproject `requires-python = ">=3.11,<3.12"`).

Notes

- AEAD remains stubbed in M#1 (ct is JSON bytes, tag placeholder). OTS anchoring uses a placeholder proof if the OTS
  client isn’t installed. These will be upgraded in M#2.


