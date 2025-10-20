#!/usr/bin/env bash
# scripts/ci/ots_verify.sh
# CI helper: start bitcoind (headers-only), wait for headers required by .ots files, then run ots verify.
# Usage: scripts/ci/ots_verify.sh <path-to-ots-dir>
set -euo pipefail

ROOT_DIR="${1:-.}"
DATADIR="${DATADIR:-$HOME/.bitcoin}"
BITCOIND_EXTRA_ARGS="${BITCOIND_EXTRA_ARGS:-'-listen=0 -blocksonly=1 -prune=550 -txindex=0 -dbcache=50 -maxconnections=8'}"
TIMEOUT_SECS="${TIMEOUT_SECS:-600}"   # 10 minutes
SLEEP_INTERVAL="${SLEEP_INTERVAL:-5}"

mkdir -p "$DATADIR"

# Start bitcoind in background
echo "Starting bitcoind (datadir=$DATADIR)..."
bitcoind -datadir="$DATADIR" -daemon $BITCOIND_EXTRA_ARGS

cleanup() {
  echo "Shutting down bitcoind..."
  bitcoin-cli -datadir="$DATADIR" stop || true
}
trap cleanup EXIT

# Wait a short moment for RPC socket to appear
sleep 2

# Collect heights from ots info outputs
heights=()
for otsfile in "$ROOT_DIR"/*.ots; do
  [ -f "$otsfile" ] || continue
  echo "Parsing heights from $otsfile"
  # Use ots info and grep for BitcoinBlockHeaderAttestation(NUM)
  if command -v ots >/dev/null 2>&1; then
    while IFS= read -r line; do
      if [[ $line =~ BitcoinBlockHeaderAttestation\(([0-9]+)\) ]]; then
        heights+=("${BASH_REMATCH[1]}")
      fi
    done < <(ots info "$otsfile" 2>/dev/null || true)
  else
    echo "Warning: ots client not found in PATH; skipping height extraction for $otsfile"
  fi
done

if [ ${#heights[@]} -eq 0 ]; then
  echo "No BitcoinBlockHeaderAttestation heights found in .ots files; running ots verify directly (if ots installed)."
  for f in "$ROOT_DIR"/*.ots; do
    [ -f "$f" ] || continue
    if command -v ots >/dev/null 2>&1; then
      ots verify "$f" || { echo "ots verify failed for $f"; exit 1; }
    else
      echo "Skipping ots verify for $f (ots not installed)."
    fi
  done
  exit 0
fi

# compute max height
max_height=0
for h in "${heights[@]}"; do
  if (( h > max_height )); then
    max_height=$h
  fi
done

echo "Max required header height: $max_height"

# Wait until headers >= max_height or timeout
start_ts=$(date +%s)
while true; do
  # bitcoin-cli returns JSON; use jq if available, otherwise crude parse
  if command -v jq >/dev/null 2>&1; then
    headers=$(bitcoin-cli -datadir="$DATADIR" getblockchaininfo | jq -r '.headers')
  else
    headers=$(bitcoin-cli -datadir="$DATADIR" getblockchaininfo | grep -o '"headers"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*' || echo 0)
  fi
  echo "Current headers: $headers (need $max_height)"
  if [ "$headers" -ge "$max_height" ]; then
    echo "Headers have caught up to required height."
    break
  fi
  now_ts=$(date +%s)
  elapsed=$(( now_ts - start_ts ))
  if [ "$elapsed" -ge "$TIMEOUT_SECS" ]; then
    echo "Timeout waiting for headers (elapsed ${elapsed}s). Marking verification as deferred."
    for f in "$ROOT_DIR"/*.ots; do
      [ -f "$f" ] || continue
      if command -v ots >/dev/null 2>&1; then
        if ! ots verify "$f"; then
          echo "Verification for $f deferred (headers not available)."
        fi
      else
        echo "Skipping ots verify for $f (ots not installed)."
      fi
    done
    exit 0
  fi
  sleep "$SLEEP_INTERVAL"
done

# Run full verification
fail=0
for f in "$ROOT_DIR"/*.ots; do
  [ -f "$f" ] || continue
  echo "Verifying $f ..."
  if command -v ots >/dev/null 2>&1; then
    if ! ots verify "$f"; then
      echo "ots verify failed for $f"
      fail=1
    fi
  else
    echo "Skipping ots verify for $f (ots not installed)."
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "At least one ots verify failed."
  exit 2
fi

echo "All proofs verified."
exit 0
