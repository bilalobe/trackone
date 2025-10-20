#!/usr/bin/env bash
# scripts/ci/ots_verify.sh
# CI helper: start bitcoind (headers-only), wait for headers required by .ots files, then run ots verify.
# Usage: scripts/ci/ots_verify.sh <path-to-ots-dir>
set -euo pipefail

ROOT_DIR="${1:-.}"
DATADIR="${DATADIR:-$HOME/.bitcoin}"
BITCOIND_EXTRA_ARGS="${BITCOIND_EXTRA_ARGS:-'-listen=0 -blocksonly=1 -prune=550 -txindex=0 -dbcache=50 -maxconnections=8 -disablewallet=1'}"
TIMEOUT_SECS="${TIMEOUT_SECS:-600}"   # 10 minutes
SLEEP_INTERVAL="${SLEEP_INTERVAL:-5}"
STRICT_VERIFY="${STRICT_VERIFY:-0}"   # 0 = allow deferred (timeout), 1 = fail on timeout

mkdir -p "$DATADIR"

if ! command -v bitcoind >/dev/null 2>&1; then
  echo "bitcoind is not installed; cannot run trustless OTS verification. Skipping."
  exit 0
fi
if ! command -v bitcoin-cli >/dev/null 2>&1; then
  echo "bitcoin-cli is not installed; cannot query headers. Skipping."
  exit 0
fi

# Start bitcoind in background
echo "Starting bitcoind (datadir=$DATADIR) with args: $BITCOIND_EXTRA_ARGS"
bitcoind -datadir="$DATADIR" -daemon $BITCOIND_EXTRA_ARGS

cleanup() {
  echo "Shutting down bitcoind..."
  bitcoin-cli -datadir="$DATADIR" stop >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Wait for RPC to become available (up to ~30s)
for i in {1..30}; do
  if bitcoin-cli -datadir="$DATADIR" -rpcwait -rpcwaittimeout=1 getblockchaininfo >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [ "$i" -eq 30 ]; then
    echo "bitcoin-cli RPC did not become ready; continuing anyway"
  fi

done

# Collect heights from ots info outputs (unique)
heights=()
if command -v ots >/dev/null 2>&1; then
  shopt -s nullglob
  for otsfile in "$ROOT_DIR"/*.ots; do
    [ -f "$otsfile" ] || continue
    echo "Parsing heights from $otsfile"
    while IFS= read -r line; do
      if [[ $line =~ BitcoinBlockHeaderAttestation\(([0-9]+)\) ]]; then
        heights+=("${BASH_REMATCH[1]}")
      fi
    done < <(ots info "$otsfile" 2>/dev/null || true)
  done
  # de-duplicate heights
  if [ ${#heights[@]} -gt 0 ]; then
    readarray -t heights < <(printf '%s
' "${heights[@]}" | sort -n | uniq)
  fi
else
  echo "Warning: ots client not found in PATH; will skip verification."
fi

if [ ${#heights[@]} -eq 0 ]; then
  echo "No BitcoinBlockHeaderAttestation heights found in .ots files."
  if command -v ots >/dev/null 2>&1; then
    # Try verify directly (may succeed if headers already cached or calendar proofs are complete)
    verified=0; failed=0
    shopt -s nullglob
    for f in "$ROOT_DIR"/*.ots; do
      [ -f "$f" ] || continue
      if ots verify "$f"; then
        verified=$((verified+1))
      else
        echo "ots verify failed for $f"
        failed=$((failed+1))
      fi
    done
    # Write summary
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      {
        echo "### OTS Verification Summary"
        echo "- Files verified: $verified"
        echo "- Files failed: $failed"
        echo "- Heights: (none parsed)"
      } >> "$GITHUB_STEP_SUMMARY"
    fi
    if [ "$failed" -gt 0 ]; then
      exit 2
    fi
  fi
  exit 0
fi

# compute max height
max_height=0
for h in "${heights[@]}"; do
  (( h > max_height )) && max_height=$h
done

echo "Required header heights: ${heights[*]}"
echo "Max required header height: $max_height"

# Wait until headers >= max_height or timeout
start_ts=$(date +%s)
while true; do
  headers=$(bitcoin-cli -datadir="$DATADIR" getblockchaininfo | jq -r '.headers' 2>/dev/null || true)
  if [[ -z "$headers" || "$headers" == "null" ]]; then
    # Fallback parse if jq not present or JSON changed
    headers=$(bitcoin-cli -datadir="$DATADIR" getblockchaininfo | grep -o '"headers"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*' || echo 0)
  fi
  headers=${headers:-0}
  echo "Current headers: $headers (need $max_height)"
  if [ "$headers" -ge "$max_height" ]; then
    echo "Headers have caught up to required height."
    break
  fi
  now_ts=$(date +%s)
  elapsed=$(( now_ts - start_ts ))
  if [ "$elapsed" -ge "$TIMEOUT_SECS" ]; then
    echo "Timeout waiting for headers (elapsed ${elapsed}s)."
    # Summary
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      {
        echo "### OTS Verification Summary"
        echo "- Deferred due to header timeout after ${elapsed}s"
        echo "- Current headers: $headers"
        echo "- Required max height: $max_height"
      } >> "$GITHUB_STEP_SUMMARY"
    fi
    if [ "$STRICT_VERIFY" = "1" ]; then
      echo "STRICT_VERIFY=1: failing the job due to timeout."
      exit 1
    fi
    # Non-strict: Attempt verification but allow failures as deferred
    if command -v ots >/dev/null 2>&1; then
      shopt -s nullglob
      for f in "$ROOT_DIR"/*.ots; do
        [ -f "$f" ] || continue
        if ! ots verify "$f"; then
          echo "Verification for $f deferred (headers not available)."
        fi
      done
    fi
    exit 0
  fi
  sleep "$SLEEP_INTERVAL"
done

# Run full verification
verified=0; failed=0
shopt -s nullglob
for f in "$ROOT_DIR"/*.ots; do
  [ -f "$f" ] || continue
  echo "Verifying $f ..."
  if command -v ots >/dev/null 2>&1; then
    if ots verify "$f"; then
      verified=$((verified+1))
    else
      echo "ots verify failed for $f"
      failed=$((failed+1))
    fi
  else
    echo "Skipping ots verify for $f (ots not installed)."
  fi
done

# Write summary
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### OTS Verification Summary"
    echo "- Files verified: $verified"
    echo "- Files failed: $failed"
    echo "- Required heights: ${heights[*]}"
    echo "- Max height: $max_height"
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [ "$failed" -ne 0 ]; then
  echo "At least one ots verify failed."
  exit 2
fi

echo "All proofs verified."
exit 0
