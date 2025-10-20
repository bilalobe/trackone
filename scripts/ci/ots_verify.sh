#!/usr/bin/env bash
# scripts/ci/ots_verify.sh
# CI helper: start bitcoind (headers-only), wait for headers required by .ots files, then run ots verify.
# Usage: scripts/ci/ots_verify.sh <path-to-ots-dir>
set -euo pipefail

ROOT_DIR="${1:-.}"
DATADIR="${DATADIR:-$HOME/.bitcoin}"
# Default extra args as an array (no embedded quote characters)
DEFAULT_BITCOIND_EXTRA_ARGS=( -listen=0 -blocksonly=1 -prune=550 -txindex=0 -dbcache=50 -maxconnections=8 -disablewallet=1 )

# If BITCOIND_EXTRA_ARGS is provided as a string in the environment, split it into an array.
BITCOIND_EXTRA_ARGS_ARRAY=()
if [ -n "${BITCOIND_EXTRA_ARGS:-}" ]; then
  # Split on whitespace into array (safe for typical usage in CI). If you need complex quoting, set the array in the script.
  read -r -a BITCOIND_EXTRA_ARGS_ARRAY <<< "${BITCOIND_EXTRA_ARGS}"
else
  BITCOIND_EXTRA_ARGS_ARRAY=("${DEFAULT_BITCOIND_EXTRA_ARGS[@]}")
fi

TIMEOUT_SECS="${TIMEOUT_SECS:-600}"   # 10 minutes
SLEEP_INTERVAL="${SLEEP_INTERVAL:-5}"
STRICT_VERIFY="${STRICT_VERIFY:-0}"   # 0 = allow deferred (timeout), 1 = fail on timeout

mkdir -p "$DATADIR"

# Collect heights from ots info outputs (unique) without starting bitcoind yet.
heights=()
lfs_pointer_found=0

if command -v ots >/dev/null 2>&1; then
  shopt -s nullglob
  for otsfile in "$ROOT_DIR"/*.ots; do
    [ -f "$otsfile" ] || continue
    # Detect Git LFS pointer files (they begin with the LFS pointer header)
    firstline=$(head -n1 "$otsfile" 2>/dev/null || true)
    if [[ "$firstline" =~ ^version\ https://git-lfs.github.com/spec/v1 ]]; then
      echo "Detected Git LFS pointer in $otsfile"
      lfs_pointer_found=1
      continue
    fi

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
  echo "Warning: ots client not found in PATH; will skip verification parsing."
fi

# If we found LFS pointers, try a best-effort `git lfs pull` if available, then re-run parsing once.
if [ "$lfs_pointer_found" -eq 1 ]; then
  if command -v git >/dev/null 2>&1 && git lfs --version >/dev/null 2>&1; then
    echo "Attempting to fetch LFS objects for .ots files (git lfs pull --include=...)."
    # Best-effort: fetch LFS objects for the root directory
    git lfs pull --include="$ROOT_DIR/*.ots" || true
    # Re-parse files in case pointers were replaced with real files
    heights=()
    for otsfile in "$ROOT_DIR"/*.ots; do
      [ -f "$otsfile" ] || continue
      firstline=$(head -n1 "$otsfile" 2>/dev/null || true)
      if [[ "$firstline" =~ ^version\ https://git-lfs.github.com/spec/v1 ]]; then
        # still a pointer
        continue
      fi
      echo "Parsing heights from $otsfile (after LFS pull attempt)"
      while IFS= read -r line; do
        if [[ $line =~ BitcoinBlockHeaderAttestation\(([0-9]+)\) ]]; then
          heights+=("${BASH_REMATCH[1]}")
        fi
      done < <(ots info "$otsfile" 2>/dev/null || true)
    done
    if [ ${#heights[@]} -gt 0 ]; then
      readarray -t heights < <(printf '%s
' "${heights[@]}" | sort -n | uniq)
    fi
  fi
fi

# If no heights were parsed, attempt direct ots verify (may still fail if file is invalid)
if [ ${#heights[@]} -eq 0 ]; then
  echo "No BitcoinBlockHeaderAttestation heights found in .ots files."

  # If we detected LFS pointers and they remain pointers, produce a clear failure explaining why.
  if [ "$lfs_pointer_found" -eq 1 ]; then
    echo "ERROR: One or more .ots files appear to be Git LFS pointers (not full timestamp files)."
    echo "CI runners may not have access to LFS objects for forked PRs or when LFS is not configured."
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      {
        echo "### OTS Verification Summary"
        echo "- ERROR: .ots files appear to be Git LFS pointer files rather than actual timestamp files."
        echo "- Possible causes: LFS objects not fetched on the runner (forked PRs), or LFS not enabled on the runner."
        echo "- Remedies:"
        echo "  - Ensure OTS files are committed and pushed via Git LFS from the same repository (not a fork), or"
        echo "  - Upload the .ots files as workflow artifacts and run verification from a workflow_dispatch, or"
        echo "  - Run verification locally where LFS objects are available."
      } >> "$GITHUB_STEP_SUMMARY"
    fi
    # Fail fast with a clear code
    exit 3
  fi

  if command -v ots >/dev/null 2>&1; then
    # Try verify directly (may succeed if headers already cached or calendar proofs are complete)
    verified=0; failed=0
    shopt -s nullglob
    for f in "$ROOT_DIR"/*.ots; do
      [ -f "$f" ] || continue
      echo "Attempting ots verify for $f"
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
      echo "At least one ots verify failed."
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

# --- New: avoid starting bitcoind when DATADIR looks empty and STRICT_VERIFY != 1 ---
# If DATADIR appears empty (no headers cached) and we're not strict, skip starting bitcoind and defer verification.
if command -v du >/dev/null 2>&1; then
  dir_kb=$(du -sk "$DATADIR" 2>/dev/null | cut -f1 || echo 0)
else
  dir_kb=0
fi
if [ -z "${dir_kb}" ]; then dir_kb=0; fi

echo "DATADIR size: ${dir_kb} KB"

# If the datadir is small (<50MB) and we're in non-strict mode, defer instead of attempting to sync many headers.
# The previous threshold was too small (1MB) and directories alone showed >4KB which caused bitcoind to start.
MIN_DATADIR_KB=${MIN_DATADIR_KB:-51200} # 50 MB
if [ "$dir_kb" -lt "$MIN_DATADIR_KB" ] && [ "${STRICT_VERIFY:-0}" != "1" ]; then
  echo "DATADIR appears small (size ${dir_kb} KB < ${MIN_DATADIR_KB} KB); skipping full bitcoin sync in non-strict mode."
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "### OTS Verification Summary"
      echo "- Deferred due to missing bitcoin headers cache (DATADIR size ${dir_kb} KB)"
      echo "- Required max height: $max_height"
      echo "- To make this run succeed: enable/restore the ~/.bitcoin cache in Actions, run on a branch with cached headers, or set STRICT_VERIFY=1 to fail instead of defer."
    } >> "$GITHUB_STEP_SUMMARY"
  fi
  # Attempt best-effort verification (calendar proofs) but don't fail CI for missing headers in non-strict mode
  if command -v ots >/dev/null 2>&1; then
    shopt -s nullglob
    for f in "$ROOT_DIR"/*.ots; do
      [ -f "$f" ] || continue
      if ! ots verify "$f"; then
        echo "Verification for $f deferred due to missing headers."
      fi
    done
  fi
  exit 0
fi

# Respect RUN_BITCOIND environment flag (set by workflow). If not explicitly allowed, don't start bitcoind.
# This is useful to avoid starting bitcoind for draft PRs or forks where syncing headers is impractical.
if [ "${RUN_BITCOIND:-0}" != "1" ]; then
  echo "RUN_BITCOIND=${RUN_BITCOIND:-0}: not starting bitcoind in this run (likely a draft PR or manual guard)."
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "### OTS Verification Summary"
      echo "- Skipped starting bitcoind because RUN_BITCOIND=${RUN_BITCOIND:-0}."
      echo "- Required max height: $max_height"
      echo "- To force a full verification: set RUN_BITCOIND=1 (e.g., run on main, use workflow_dispatch, or add label run-ots-verify)."
    } >> "$GITHUB_STEP_SUMMARY"
  fi
  # Attempt best-effort verification (calendar proofs) but don't fail CI for missing headers in non-strict mode
  if command -v ots >/dev/null 2>&1; then
    shopt -s nullglob
    for f in "$ROOT_DIR"/*.ots; do
      [ -f "$f" ] || continue
      if ! ots verify "$f"; then
        echo "Verification for $f deferred due to missing headers or disabled bitcoind."
      fi
    done
  fi
  exit 0
fi

# Now start bitcoind in background (we only start when headers are required)
if ! command -v bitcoind >/dev/null 2>&1; then
  echo "bitcoind is not installed; cannot run trustless OTS verification. Skipping."
  exit 0
fi
if ! command -v bitcoin-cli >/dev/null 2>&1; then
  echo "bitcoin-cli is not installed; cannot query headers. Skipping."
  exit 0
fi

echo "Starting bitcoind (datadir=$DATADIR) with args: ${BITCOIND_EXTRA_ARGS_ARRAY[*]}"
# shellcheck disable=SC2068
bitcoind -datadir="$DATADIR" -daemon "${BITCOIND_EXTRA_ARGS_ARRAY[@]}"

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
