#!/usr/bin/env bash
# run_pipeline.sh
#
# M#1 end-to-end pipeline:
#   pod_sim --framed → frame_verifier → merkle_batcher → ots_anchor → verify_cli
#
# This demonstrates the complete framed telemetry ingestion, batching, anchoring,
# and verification workflow.

set -euo pipefail

# Configuration
SITE="an-001"
DATE="2025-10-07"
OUT_DIR="out/site_demo"
DEVICE_ID="pod-003"
NUM_FRAMES=10

# Derived paths
FRAMES_FILE="${OUT_DIR}/frames.ndjson"
FACTS_DIR="${OUT_DIR}/facts"
DEVICE_TABLE="${OUT_DIR}/device_table.json"
DAY_BIN="${OUT_DIR}/day/${DATE}.bin"

echo "[pipeline] Starting M#1 end-to-end pipeline"
echo "[pipeline] Site: ${SITE}, Date: ${DATE}, Device: ${DEVICE_ID}"
echo ""

# Create output directories
mkdir -p "${OUT_DIR}"
mkdir -p "${FACTS_DIR}"

# Create minimal device table (for M#2 key lookup)
echo "[pipeline] Creating device table..."
cat > "${DEVICE_TABLE}" <<EOF
{
  "devices": {
    "pod-003": {
      "device_id": "pod-003",
      "pubkey": "placeholder_for_m2"
    }
  }
}
EOF

# Step 1: Generate framed telemetry
echo "[pipeline] Step 1: Generating framed telemetry (${NUM_FRAMES} frames)..."
python scripts/pod_sim/pod_sim.py \
  --framed \
  --device-id "${DEVICE_ID}" \
  --count "${NUM_FRAMES}" \
  --out "${FRAMES_FILE}"

echo "[pipeline] Generated: ${FRAMES_FILE}"
echo ""

# Step 2: Verify frames and extract facts
echo "[pipeline] Step 2: Verifying frames and extracting facts..."
python scripts/gateway/frame_verifier.py \
  --in "${FRAMES_FILE}" \
  --out-facts "${FACTS_DIR}" \
  --device-table "${DEVICE_TABLE}" \
  --window 64

echo ""

# Step 3: Batch facts into Merkle tree
echo "[pipeline] Step 3: Batching facts into Merkle tree..."
python scripts/gateway/merkle_batcher.py \
  --facts "${FACTS_DIR}" \
  --out "${OUT_DIR}" \
  --site "${SITE}" \
  --date "${DATE}" \
  --validate-schemas

echo ""

# Step 4: Anchor day blob with OTS
echo "[pipeline] Step 4: Anchoring day blob with OpenTimestamps..."
python scripts/gateway/ots_anchor.py "${DAY_BIN}"

echo ""

# Step 5: Verify Merkle root and OTS proof
echo "[pipeline] Step 5: Verifying Merkle root and OTS proof..."
python scripts/gateway/verify_cli.py \
  --root "${OUT_DIR}" \
  --facts "${FACTS_DIR}"

echo ""
echo "[pipeline] ✓ Pipeline completed successfully!"
echo "[pipeline] Outputs:"
echo "[pipeline]   - Frames: ${FRAMES_FILE}"
echo "[pipeline]   - Facts: ${FACTS_DIR}/"
echo "[pipeline]   - Blocks: ${OUT_DIR}/blocks/"
echo "[pipeline]   - Day: ${OUT_DIR}/day/"
echo "[pipeline]   - OTS proof: ${DAY_BIN}.ots"
