# OpenTimestamps Verification (ADR-007)

This guide explains how we verify OpenTimestamps (OTS) proofs locally and in CI using Bitcoin Core headers-only mode.

References: ADR-003 (anchoring policy), ADR-007 (CI headers policy).

## Local verification

Prerequisites:
- OpenTimestamps client: `pip install opentimestamps-client`
- Bitcoin Core (bitcoind/bitcoin-cli) installed and on PATH

Start headers-only/pruned node and verify:

```bash
# Start bitcoind in headers-only mode
bitcoind -daemon \
  -listen=0 \
  -blocksonly=1 \
  -prune=550 \
  -txindex=0 \
  -dbcache=50 \
  -maxconnections=8

# Verify a proof (once headers have reached required heights)
ots verify out/site_demo/day/2025-10-07.bin.ots
```

Alternatively, use the helper target (wraps our CI script):

```bash
# Default: lenient; timeout defers verification without failing
make ots-verify

# Strict: fail if headers don’t catch up within TIMEOUT_SECS
STRICT_VERIFY=1 TIMEOUT_SECS=900 make ots-verify
```

## CI verification (GitHub Actions)

Workflow: `.github/workflows/ots-verify.yml`

Key points (ADR-007):
- Downloads Bitcoin Core from bitcoincore.org and runs headers-only.
- Caches `~/.bitcoin` across runs for fast re-verification.
- Parses required block heights from `.ots` files with `ots info`.
- Waits until headers reach the highest required height (timeout configurable).
- Policy: strict on `main` (timeouts fail), lenient on PRs (timeouts defer).
- Uploads `~/.bitcoin/debug.log` on failure for debugging.

Path filters: This workflow runs only when OTS-related files change (workflow, helper script, ADR-007, gateway OTS tools, or these docs).

## Troubleshooting
- `bitcoind: command not found`: Ensure Bitcoin Core is installed and on PATH. In CI, the workflow exports PATH within the install step before invoking `bitcoind`.
- `Could not connect to Bitcoin node`: Wait for headers to sync or increase timeout. Use the lenient mode on PRs to avoid failing reviews.
- `ots verify` still fails after headers: Run `ots info <file.ots>` and confirm the `BitcoinBlockHeaderAttestation(<height>)` is ≤ current headers (`bitcoin-cli -getinfo`).

## Notes
- For air-gapped deployments, verification must be performed on a machine with up-to-date headers or via trusted header bundles.
- Do not commit upgraded `.ots` proofs from CI; prefer to upload as artifacts if needed.
