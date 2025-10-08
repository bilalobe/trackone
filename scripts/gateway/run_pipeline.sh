#!/usr/bin/env bash
set -euo pipefail

# One-shot pipeline: pod_sim -> frame_verifier -> merkle_batcher --validate-schemas -> ots_anchor -> verify_cli

SITE="an-001"
DAY="2025-10-07"
ROOT_DIR="out/site_demo"
FRAMES="${ROOT_DIR}/frames.ndjson"
FACTS_OUT="${ROOT_DIR}/facts"
DEVICE_TABLE="${ROOT_DIR}/device_table.json"

mkdir -p "${ROOT_DIR}"

# 1) Simulate framed telemetry and also write plain facts for cross-check
python3 scripts/pod_sim/pod_sim.py --device-id pod-001 --count 10 --framed --out "${FRAMES}" --facts-out "${ROOT_DIR}/plain_facts"

# 2) Verify frames and emit canonical facts
python3 scripts/gateway/frame_verifier.py --in "${FRAMES}" --out-facts "${FACTS_OUT}" --device-table "${DEVICE_TABLE}" --window 64

# 3) Batch facts into Merkle structures
python3 scripts/gateway/merkle_batcher.py --facts "${FACTS_OUT}" --out "${ROOT_DIR}" --site "${SITE}" --date "${DAY}" --validate-schemas

# 4) Anchor the day blob (stub if ots missing)
python3 scripts/gateway/ots_anchor.py "${ROOT_DIR}/day/${DAY}.bin"

# 5) Verify
python3 scripts/gateway/verify_cli.py --root "${ROOT_DIR}" --facts "${FACTS_OUT}"

