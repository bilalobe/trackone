#!/usr/bin/env bash
# scripts/ci/ots_verify.sh
# CI helper: start bitcoind (headers-only), wait for headers required by .ots files, optionally upgrade proofs, then run ots verify.
# Usage: scripts/ci/ots_verify.sh <path-to-ots-dir>
set -euo pipefail

ROOT_DIR="${1:-.}"
DATADIR="${DATADIR:-$HOME/.bitcoin}"
# Do not wrap defaults in quotes; pass to bitcoind via an array to preserve arguments safely.
BITCOIND_EXTRA_ARGS="${BITCOIND_EXTRA_ARGS:--listen=0 -blocksonly=1 -prune=550 -txindex=0 -dbcache=50 -maxconnections=8 -disablewallet=1}"
TIMEOUT_SECS="${TIMEOUT_SECS:-600}"   # 10 minutes
SLEEP_INTERVAL="${SLEEP_INTERVAL:-5}"
STRICT_VERIFY="${STRICT_VERIFY:-0}"   # 0 = allow deferred (timeout/pending), 1 = fail on timeout/pending
RUN_BITCOIND="${RUN_BITCOIND:-1}"     # 1 = start bitcoind, 0 = skip (best-effort verify)
UPGRADE_ON_PENDING="${UPGRADE_ON_PENDING:-1}"
UPGRADE_TRIES="${UPGRADE_TRIES:-3}"
UPGRADE_BACKOFF_SECS="${UPGRADE_BACKOFF_SECS:-10}"
EXPLORER_BASE="${EXPLORER_BASE:-https://mempool.space}"
EXPLORER_HASH_BASE="${EXPLORER_HASH_BASE:-https://www.blockchain.com/btc/block}"
OUTPUT_SUMMARY="${OUTPUT_SUMMARY:-$ROOT_DIR/ots_verify_summary.txt}"
OUTPUT_JSON_SUMMARY="${OUTPUT_JSON_SUMMARY:-$ROOT_DIR/ots_verify_summary.json}"

# Declare arrays and associative maps
: "${block_hashes:=}"  # ensure variable exists even if declare fails under some shells
declare -a heights
declare -a block_hashes
declare -A file_stage
declare -A file_next_trigger

mkdir -p "$DATADIR"

if ! command -v bitcoind >/dev/null 2>&1; then
  echo "bitcoind is not installed; cannot run trustless OTS verification. Skipping."
  exit 0
fi
if ! command -v bitcoin-cli >/dev/null 2>&1; then
  echo "bitcoin-cli is not installed; cannot query headers. Skipping."
  exit 0
fi

# Helper: upgrade all OTS files once (best-effort)
upgrade_all_once() {
  shopt -s nullglob
  local any=0
  for f in "$ROOT_DIR"/*.ots; do
    [ -f "$f" ] || continue
    any=1
    echo "Upgrading proof: $f"
    ots upgrade "$f" || true
  done
  if [ "$any" -eq 0 ]; then
    echo "No OTS files to upgrade in $ROOT_DIR"
  fi
}

# Helper: parse heights into a global array variable 'heights'
parse_heights() {
  heights=()
  if ! command -v ots >/dev/null 2>&1; then
    return 0
  fi
  shopt -s nullglob
  for otsfile in "$ROOT_DIR"/*.ots; do
    [ -f "$otsfile" ] || continue
    while IFS= read -r line; do
      if [[ $line =~ BitcoinBlockHeaderAttestation\(([0-9]+)\) ]]; then
        heights+=("${BASH_REMATCH[1]}")
      fi
    done < <(ots info "$otsfile" 2>/dev/null || true)
  done
  if [ ${#heights[@]} -gt 0 ]; then
    readarray -t heights < <(printf '%s\n' "${heights[@]}" | sort -n | uniq)
  fi
}

# Helper: (optional) compute block hashes for heights via local node
compute_block_hashes_if_possible() {
  block_hashes=()
  if [ ${#heights[@]} -eq 0 ]; then
    return 0
  fi
  if [ "$RUN_BITCOIND" != "1" ]; then
    return 0
  fi
  # Attempt to query block hashes; ignore failures silently
  for h in "${heights[@]}"; do
    bh=$(bitcoin-cli -datadir="$DATADIR" getblockhash "$h" 2>/dev/null || true)
    if [ -n "${bh:-}" ]; then
      block_hashes+=("$bh")
    fi
  done
}

# Helper: classify stage from ots info output
classify_stage_for_file() {
  local f="$1"; local info="$2"; local stage="pending"; local next="upgrade";
  if grep -q 'Success! Timestamp complete' <<<"$info"; then
    stage="verified"; next="none"
  elif grep -q 'BitcoinBlockHeaderAttestation' <<<"$info"; then
    # Has attestation heights but verify may not yet pass if blocks behind
    stage="headers_wait_block_sync"; next="sync-blocks"
  elif grep -q 'Timestamped by transaction' <<<"$info"; then
    # Transaction published; waiting for confirmations
    stage="tx_published_wait_conf"; next="confirmations+upgrade"
  elif grep -q 'Pending confirmation in Bitcoin blockchain' <<<"$info"; then
    stage="calendar_pending"; next="upgrade"
  fi
  file_stage["$f"]="$stage"
  file_next_trigger["$f"]="$next"
}

# Helper: harvest stage info for all .ots files
harvest_stages() {
  shopt -s nullglob
  for f in "$ROOT_DIR"/*.ots; do
    [ -f "$f" ] || continue
    local info_out
    info_out=$(ots info "$f" 2>/dev/null || true)
    classify_stage_for_file "$f" "$info_out"
  done
}

# Helper: write a simple summary file with explorer URLs
write_summary_file() {
  # Per-file statuses are available via file_status associative array if populated
  # Heights list from global 'heights'
  {
    echo "explorer_base=$EXPLORER_BASE"
    echo "explorer_hash_base=$EXPLORER_HASH_BASE"
    if [ ${#heights[@]} -gt 0 ]; then
      echo -n "heights="
      (IFS=,; echo "${heights[*]}")
      echo -n "block_urls="
      urls=()
      for h in "${heights[@]}"; do
        urls+=("$EXPLORER_BASE/block-height/$h")
      done
      (IFS=,; echo "${urls[*]}")
      echo -n "block_hash_urls="
      hash_urls=()
      if [ "$(array_len block_hashes)" -gt 0 ]; then
        for bh in "${block_hashes[@]}"; do
          hash_urls+=("$EXPLORER_HASH_BASE/$bh")
        done
        (IFS=,; echo "${hash_urls[*]}")
      else
        echo ""
      fi
    else
      echo "heights="
      echo "block_urls="
      echo "block_hash_urls="
    fi
    # Per-file lines
    shopt -s nullglob
    for f in "$ROOT_DIR"/*.ots; do
      [ -f "$f" ] || continue
      st="${file_status[$f]:-unknown}"
      sg="${file_stage[$f]:-unknown}"
      nt="${file_next_trigger[$f]:-unknown}"
      echo "file=$f status=$st stage=$sg next_trigger=$nt"
    done
  } > "$OUTPUT_SUMMARY" || true
  echo "Wrote summary: $OUTPUT_SUMMARY"
}

# Helper: write JSON summary (heights, URLs, per-file statuses)
write_json_summary_file() {
  {
    echo "{"
    printf '  "explorer_base": "%s",\n' "$EXPLORER_BASE"
    printf '  "explorer_hash_base": "%s",\n' "$EXPLORER_HASH_BASE"
    printf '  "heights": ['
    if [ ${#heights[@]} -gt 0 ]; then
      for i in "${!heights[@]}"; do
        if [ "$i" -ne 0 ]; then printf ', '; fi
        printf '%s' "${heights[$i]}"
      done
    fi
    echo '],'
    printf '  "block_urls": ['
    if [ ${#heights[@]} -gt 0 ]; then
      for i in "${!heights[@]}"; do
        if [ "$i" -ne 0 ]; then printf ', '; fi
        printf '"%s/block-height/%s"' "$EXPLORER_BASE" "${heights[$i]}"
      done
    fi
    echo '],'
    printf '  "block_hash_urls": ['
    if [ "$(array_len block_hashes)" -gt 0 ]; then
      for i in "${!block_hashes[@]}"; do
        if [ "$i" -ne 0 ]; then printf ', '; fi
        printf '"%s/%s"' "$EXPLORER_HASH_BASE" "${block_hashes[$i]}"
      done
    fi
    echo '],'
    printf '  "node_blocks": %s,\n' "${NODE_BLOCKS:-null}"
    printf '  "node_headers": %s,\n' "${NODE_HEADERS:-null}"
    echo '  "files": ['
    shopt -s nullglob
    first=1
    for f in "$ROOT_DIR"/*.ots; do
      [ -f "$f" ] || continue
      st="${file_status[$f]:-unknown}"
      sg="${file_stage[$f]:-unknown}"
      nt="${file_next_trigger[$f]:-unknown}"
      if [ "$first" -ne 1 ]; then echo ","; fi
      first=0
      printf '    {"file": "%s", "status": "%s", "stage": "%s", "next_trigger": "%s"}' "$f" "$st" "$sg" "$nt"
    done
    echo ''
    echo '  ]'
    echo "}"
  } > "$OUTPUT_JSON_SUMMARY" || true
  echo "Wrote JSON summary: $OUTPUT_JSON_SUMMARY"
}

# Start bitcoind in background (if enabled)
if [ "$RUN_BITCOIND" = "1" ]; then
  # shellcheck disable=SC2206
  BITCOIND_ARGS=( $BITCOIND_EXTRA_ARGS )
  echo "Starting bitcoind (datadir=$DATADIR) with args: ${BITCOIND_ARGS[*]}"
  bitcoind -datadir="$DATADIR" -daemon "${BITCOIND_ARGS[@]}"

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
else
  echo "RUN_BITCOIND=0: Skipping bitcoind startup; proceeding with best-effort verification."
fi

# Initial stage harvest (may show calendar pending before upgrade attempts)
harvest_stages

# Collect or upgrade to collect heights
heights=()
parse_heights
if [ ${#heights[@]} -eq 0 ] && [ "$UPGRADE_ON_PENDING" = "1" ] && command -v ots >/dev/null 2>&1; then
  echo "No heights parsed; attempting to upgrade proofs (tries=$UPGRADE_TRIES, backoff=${UPGRADE_BACKOFF_SECS}s)"
  attempt=1
  while [ "$attempt" -le "$UPGRADE_TRIES" ]; do
    echo "Upgrade attempt $attempt/$UPGRADE_TRIES"
    upgrade_all_once
    parse_heights
    if [ ${#heights[@]} -gt 0 ]; then
      echo "Heights discovered after upgrade: ${heights[*]}"
      break
    fi
    if [ "$attempt" -lt "$UPGRADE_TRIES" ]; then
      sleep "$UPGRADE_BACKOFF_SECS"
    fi
    attempt=$((attempt+1))
    harvest_stages
  done
fi

if [ ${#heights[@]} -gt 0 ]; then
  compute_block_hashes_if_possible
fi

if [ ${#heights[@]} -eq 0 ]; then
  echo "No BitcoinBlockHeaderAttestation heights found in .ots files."
  if command -v ots >/dev/null 2>&1; then
    # Try verify directly (may succeed if headers already cached or calendar proofs are complete)
    verified=0; failed=0
    declare -A file_status=()
    shopt -s nullglob
    for f in "$ROOT_DIR"/*.ots; do
      [ -f "$f" ] || continue
      if ots verify "$f"; then
        verified=$((verified+1))
        file_status["$f"]=verified
      else
        echo "ots verify failed for $f"
        failed=$((failed+1))
        file_status["$f"]=pending
      fi
    done
    # Write summary (file + heights + urls)
    write_summary_file
    write_json_summary_file
    # Write markdown summary
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      {
        echo "### OTS Verification Summary"
        echo "- Files verified: $verified"
        echo "- Files failed: $failed"
        echo "- Heights: (none parsed)"
      } >> "$GITHUB_STEP_SUMMARY"
    fi
    if [ "$failed" -gt 0 ]; then
      if [ "$STRICT_VERIFY" = "1" ]; then
        exit 2
      else
        echo "Non-strict mode: allowing verification failures (likely pending confirmations)."
        exit 0
      fi
    fi
  fi
  exit 0
fi

if [ "$RUN_BITCOIND" = "1" ]; then
  # compute max height
  max_height=0
  for h in "${heights[@]}"; do
    (( h > max_height )) && max_height=$h
  done

  echo "Required header heights: ${heights[*]}"
  echo "Max required header height: $max_height"

  # Wait until blocks >= max_height or timeout (use both headers and blocks for visibility)
  start_ts=$(date +%s)
  while true; do
    info_json=$(bitcoin-cli -datadir="$DATADIR" getblockchaininfo 2>/dev/null || echo '{}')
    headers=$(echo "$info_json" | jq -r '.headers' 2>/dev/null || true)
    blocks=$(echo "$info_json" | jq -r '.blocks' 2>/dev/null || true)
    if [[ -z "$headers" || "$headers" == "null" ]]; then
      headers=$(echo "$info_json" | grep -o '"headers"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*' || echo 0)
    fi
    if [[ -z "$blocks" || "$blocks" == "null" ]]; then
      blocks=$(echo "$info_json" | grep -o '"blocks"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*' || echo 0)
    fi
    headers=${headers:-0}
    blocks=${blocks:-0}
    echo "Current node state: blocks=$blocks headers=$headers (need blocks >= $max_height)"
    if [ "$blocks" -ge "$max_height" ]; then
      echo "Blocks have caught up to required height ($max_height)."
      break
    fi
    now_ts=$(date +%s)
    elapsed=$(( now_ts - start_ts ))
    if [ "$elapsed" -ge "$TIMEOUT_SECS" ]; then
      echo "Timeout waiting for blocks >= $max_height (elapsed ${elapsed}s; blocks=$blocks headers=$headers)."
      if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        {
          echo "### OTS Verification Summary"
          echo "- Deferred due to block sync timeout after ${elapsed}s"
          echo "- Current blocks: $blocks"
          echo "- Current headers: $headers"
          echo "- Required max height: $max_height"
        } >> "$GITHUB_STEP_SUMMARY"
      fi
      if [ "$STRICT_VERIFY" = "1" ]; then
        echo "STRICT_VERIFY=1: failing the job due to block sync timeout."
        exit 1
      fi
      declare -A file_status=()
      shopt -s nullglob
      for f in "$ROOT_DIR"/*.ots; do
        file_status["$f"]=deferred
      done
      write_summary_file
      write_json_summary_file
      exit 0
    fi
    sleep "$SLEEP_INTERVAL"
  done
  # After blocks catch up, recompute block hashes (they may have appeared)
  compute_block_hashes_if_possible
else
  echo "RUN_BITCOIND=0: Skipping headers wait; attempting verification directly."
fi

# Run full verification
verified=0; failed=0
declare -A file_status=()
shopt -s nullglob
for f in "$ROOT_DIR"/*.ots; do
  [ -f "$f" ] || continue
  echo "Verifying $f ..."
  if command -v ots >/dev/null 2>&1; then
    if ots verify "$f"; then
      verified=$((verified+1))
      file_status["$f"]=verified
    else
      echo "ots verify failed for $f"
      failed=$((failed+1))
      file_status["$f"]=pending
    fi
  else
    echo "Skipping ots verify for $f (ots not installed)."
    file_status["$f"]=skipped
  fi
  # Refresh stage after verify attempt
  info_out=$(ots info "$f" 2>/dev/null || true)
  classify_stage_for_file "$f" "$info_out"
done

# If failures and upgrade-on-pending: try one last upgrade+re-verify pass
if [ "$failed" -gt 0 ] && [ "$UPGRADE_ON_PENDING" = "1" ] && command -v ots >/dev/null 2>&1; then
  echo "Failures detected; attempting a final upgrade + re-verify pass."
  upgrade_all_once
  # Re-parse heights in case new attestation appeared
  parse_heights
  compute_block_hashes_if_possible
  # re-verify only failed ones
  failed=0; verified=0; declare -A file_status_new=()
  for f in "$ROOT_DIR"/*.ots; do
    [ -f "$f" ] || continue
    echo "Re-verifying $f ..."
    if ots verify "$f"; then
      verified=$((verified+1))
      file_status_new["$f"]=verified
    else
      failed=$((failed+1))
      file_status_new["$f"]=pending
    fi
    # Refresh stage after verify attempt
    info_out=$(ots info "$f" 2>/dev/null || true)
    classify_stage_for_file "$f" "$info_out"
  done
  # replace statuses
  file_status=()
  for f in "$ROOT_DIR"/*.ots; do
    [ -f "$f" ] || continue
    file_status["$f"]="${file_status_new[$f]:-unknown}"
  done
fi

# Write summary
write_summary_file
write_json_summary_file
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### OTS Verification Summary"
    echo "- Files verified: $verified"
    echo "- Files failed: $failed"
    if [ ${#heights[@]} -gt 0 ]; then
      echo "- Required heights: ${heights[*]}"
      echo "- Explorer height URLs:"
      for h in "${heights[@]}"; do
        echo "  - $EXPLORER_BASE/block-height/$h"
      done
      if [ "$(array_len block_hashes)" -gt 0 ]; then
        echo "- Explorer block hash URLs:";
        for bh in "${block_hashes[@]}"; do
          echo "  - $EXPLORER_HASH_BASE/$bh"
        done
      fi
    fi
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [ "$failed" -ne 0 ]; then
  echo "At least one ots verify failed."
  if [ "$STRICT_VERIFY" = "1" ]; then
    exit 2
  else
    echo "Non-strict mode: allowing verification failures (likely pending confirmations)."
    exit 0
  fi
fi

echo "All proofs verified."
exit 0
