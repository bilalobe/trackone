#!/usr/bin/env bash
# run_pipeline.sh
#
# Track1 end-to-end pipeline (v1.0):
#   rust_framed_fixture_emitter (rust-postcard-v1) → frame_verifier → merkle_batcher → ots_anchor → verify_cli
#
# This demonstrates the Rust-native framed telemetry path. The public commitment
# authority remains the post-projection canonical CBOR artifact.

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
DAY_ARTIFACT="${OUT_DIR}/day/${DATE}.cbor"

echo "[pipeline] Starting Track1 pipeline (v1.0)"
echo "[pipeline] Site: ${SITE}, Date: ${DATE}, Device: ${DEVICE_ID}"
echo "[pipeline] AEAD: XChaCha20-Poly1305 (24-byte nonce)"

# Create output directories
mkdir -p "${OUT_DIR}"
mkdir -p "${FACTS_DIR}"

# Ensure fresh state for facts (avoid counting stale files)
rm -f "${FACTS_DIR}"/*.json "${FACTS_DIR}"/*.cbor 2>/dev/null || true

# Step 1: Generate framed telemetry (emitter persists device_table with per-device salts/keys)
echo "[pipeline] Step 1: Generating framed telemetry (${NUM_FRAMES} frames)..."
python scripts/gateway/rust_framed_fixture_emitter.py \
  --device-id "${DEVICE_ID}" \
  --count "${NUM_FRAMES}" \
  --site "${SITE}" \
  --device-table "${DEVICE_TABLE}" \
  --out "${FRAMES_FILE}"

echo "[pipeline] Generated: ${FRAMES_FILE}"

# Step 2: Verify frames and extract facts
echo ""
echo "[pipeline] Step 2: Verifying frames and extracting facts..."
python scripts/gateway/frame_verifier.py \
  --in "${FRAMES_FILE}" \
  --out-facts "${FACTS_DIR}" \
  --device-table "${DEVICE_TABLE}" \
  --ingest-profile rust-postcard-v1 \
  --window 64

# Step 3: Batch facts into Merkle tree
echo ""
echo "[pipeline] Step 3: Batching facts into Merkle tree..."
python scripts/gateway/merkle_batcher.py \
  --facts "${FACTS_DIR}" \
  --out "${OUT_DIR}" \
  --site "${SITE}" \
  --date "${DATE}" \
  --validate-schemas

# Step 4: Anchor day artifact with OTS
echo ""
echo "[pipeline] Step 4: Anchoring day artifact with OpenTimestamps..."
python scripts/gateway/ots_anchor.py "${DAY_ARTIFACT}"

# Step 5: Verify Merkle root and OTS proof
echo ""
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
echo "[pipeline]   - OTS proof: ${DAY_ARTIFACT}.ots"
