# OpenTimestamps Verification (ADR-007)

This guide explains how we verify OpenTimestamps (OTS) proofs locally and in CI using Bitcoin Core headers-only mode, plus optional RFC 3161 TSA and peer co-signature verification per ADR-015.

References: ADR-003 (anchoring policy), ADR-007 (CI headers policy), ADR-015 (parallel anchoring).

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

# Strict: fail if headers don't catch up within TIMEOUT_SECS
STRICT_VERIFY=1 TIMEOUT_SECS=900 make ots-verify
```

## Parallel anchoring (TSA + Peer Signatures)

Per ADR-015, TrackOne supports parallel anchoring via RFC 3161 TSA and peer co-signatures alongside OTS.

### TSA verification

If TSA artifacts exist (`YYYY-MM-DD.tsr` and `YYYY-MM-DD.tsr.json`), verify with:

```bash
python scripts/gateway/verify_cli.py \
  --root out/site_demo \
  --facts out/site_demo/facts \
  --verify-tsa
```

Strict mode (fail if TSA missing or invalid):

```bash
python scripts/gateway/verify_cli.py \
  --root out/site_demo \
  --facts out/site_demo/facts \
  --verify-tsa --tsa-strict
```

### Peer signature verification

If peer attestations exist (`day/peers/YYYY-MM-DD.peers.json`), verify with:

```bash
python scripts/gateway/verify_cli.py \
  --root out/site_demo \
  --facts out/site_demo/facts \
  --verify-peers --peers-min 2
```

Strict mode (fail if peer signatures missing or insufficient):

```bash
python scripts/gateway/verify_cli.py \
  --root out/site_demo \
  --facts out/site_demo/facts \
  --verify-peers --peers-strict --peers-min 2
```

### Combined verification (all channels)

```bash
python scripts/gateway/verify_cli.py \
  --root out/site_demo \
  --facts out/site_demo/facts \
  --verify-tsa --tsa-strict \
  --verify-peers --peers-strict --peers-min 2
```

This requires OTS, TSA, and at least 2 valid peer signatures for success.

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

## Advanced: Testing a third-party TSA with `tsa_http_client.py`

For manual experiments with an RFC 3161 TSA endpoint ("bring your own TSA"), TrackOne ships a small helper CLI: `scripts/gateway/tsa_http_client.py`.

> This is intentionally **not** wired into the Makefile or CI. Use it only when you
> have a TSA URL you are allowed to send test requests to, and keep usage manual.

### What it does

Given a blob (typically a day record such as `out/site_demo/day/YYYY-MM-DD.bin`) and a TSA URL, the helper will:

1. Compute a hash of the blob (default: SHA-256).
1. Ask `openssl ts -query` to build a TSQ with that digest via the `-digest` option
   (no `-sha256` short flags; behavior matches OpenSSL 3.5.x `ts -query -help`).
1. POST the TSQ to the TSA endpoint with `Content-Type: application/timestamp-query`.
1. Save the binary TSR alongside the input (`YYYY-MM-DD.tsr`).
1. Optionally call `openssl ts -reply -text` and merge metadata into `YYYY-MM-DD.tsr.json`
   using the same parser as `tsa_stamp.py`.

Artifacts are written next to the blob by default:

- `YYYY-MM-DD.tsq` — timestamp query (DER)
- `YYYY-MM-DD.tsr` — timestamp response (DER)
- `YYYY-MM-DD.tsr.json` — parsed metadata (policy OID, timestamp, TSA name, imprint), if parsing is not skipped

### Usage

Run the demo pipeline first so a day blob exists:

```bash
python scripts/gateway/run_pipeline_demo.py --keep-existing
```

Then, with `TRACKONE_TSA_URL` pointing to a TSA endpoint you are entitled to use:

```bash
export TRACKONE_TSA_URL="https://your-tsa.example.com/tsa"

python scripts/gateway/tsa_http_client.py \
  out/site_demo/day/2025-10-07.bin \
  "$TRACKONE_TSA_URL" \
  --out-dir out/site_demo/day
```

You should see output like:

```text
TSQ written: out/site_demo/day/2025-10-07.tsq
TSR written: out/site_demo/day/2025-10-07.tsr
Metadata written: out/site_demo/day/2025-10-07.tsr.json
```

You can then ask the verifier to include TSA checks (warn-only by default):

```bash
python scripts/gateway/verify_cli.py \
  --root out/site_demo \
  --facts out/site_demo/facts \
  --verify-tsa
```

Typical outcomes:

- If TSA verification succeeds (correct chain and policy configured), you will see a
  success message and exit code `0` (assuming OTS and Merkle checks also pass).

- If TSA verification fails, you will see a warning such as:

  ```text
  WARN: TSA verification failed: out/site_demo/day/2025-10-07.tsr
  OK: root matches and OTS verified
  ```

  The pipeline still relies on OTS as the primary decentralized anchor; TSA is
  additive and failure is non-fatal unless you pass `--tsa-strict` to `verify_cli`.

### Notes and caveats

- **No Makefile target:** TSA stamping is deliberately not exposed as a Make target
  or used in CI. Operators are expected to run `tsa_http_client.py` manually when
  they have a valid TSA relationship and want an extra timestamp channel.
- **Trust configuration:** For real deployments, you will typically need to provide
  TSA CA/chain material and adjust verification logic to treat successful TSA
  checks as first-class. The current helper focuses on validating the request/response
  flow and generating artifacts; trust decisions remain environment-specific.
- **Do not rely on public TSAs by default:** The endpoint URL is not hard-coded.
  Always review the terms of use for any third-party TSA before sending requests,
  and avoid using arbitrary public TSAs in automated tests or CI.
