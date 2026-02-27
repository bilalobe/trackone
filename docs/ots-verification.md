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
ots verify out/site_demo/day/2025-10-07.cbor.ots
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

## Running a real OTS calendar locally

For local development and CI-style testing against a real OTS calendar (instead
of the stationary stub), you can run the official OTS calendar in Docker.

A minimal compose file is provided as `docker-compose.ots.yml`:

```yaml
version: '3.8'

services:
  ots-calendar:
    image: ots/calendar:latest
    container_name: ots-calendar
    restart: unless-stopped
    ports:
      - "8468:8468"
    environment:
      OTS_LOG_LEVEL: info
    volumes:
      - ./data/ots-calendar:/var/lib/ots-calendar
```

To start the calendar locally:

```bash
docker compose -f docker-compose.ots.yml up -d ots-calendar
```

Then point the gateway tools at this calendar via `OTS_CALENDARS` and disable
stub mode when you want real OTS behavior:

```bash
export OTS_STATIONARY_STUB=0
export OTS_CALENDARS="http://127.0.0.1:8468"

# Anchor a day blob against the local calendar
python scripts/gateway/ots_anchor.py out/site_demo/day/2025-10-07.cbor

# Run the real-OTS integration tests
RUN_REAL_OTS=1 pytest -m real_ots tests/integration/test_ots_integration.py
```

The `tox -e ots-cal` environment and `.github/workflows/ots-cal.yml` workflow
use the same pattern: start a local `ots-calendar` container, set
`OTS_STATIONARY_STUB=0` and `OTS_CALENDARS` to `http://127.0.0.1:8468`, then run
only the `real_ots` tests. This gives ADR-014 a concrete, reproducible path
from the stationary stub in unit tests to a real calendar in CI.

## Local OTS calendar sidecar (stationary calendar)

For CI-conscious real-OTS testing we provide a lightweight Docker sidecar that
runs a long-lived HTTP health endpoint and validates the `opentimestamps`
client stack without depending on public calendars during test bring-up.

- Image: `ots/calendar:latest` (built from `docker/calendar/Dockerfile`).
- Entry point: `run_calendar.py`.
- Port: `8468` (configurable via `OTS_CAL_PORT`).
- Health: responds `200 OK` with body `OK\n` on `/`, `/health`, `/ready`.

The sidecar does **not** implement a full OTS calendar protocol; instead it:

1. Optionally probes the `ots` client (`ots --help`) on startup, to ensure the
   binary and libraries are wired correctly.
1. Exposes a stable HTTP endpoint so CI and local tests can wait for readiness
   (no race with container startup).
1. Keeps the container process alive so real-OTS tests can treat it as a
   stationary calendar for integration and ratcheting.

### Running the stationary calendar locally

To build and run the local calendar on a developer machine:

```bash
cd /path/to/trackone

# Build the image
docker build -t ots/calendar:latest docker/calendar

# Start the container (detached)
cid=$(docker run -d -p 8468:8468 --name trackone_ots_calendar ots/calendar:latest)

# Wait for it to be ready
for i in $(seq 1 15); do
  if curl -fsS http://127.0.0.1:8468/ >/dev/null 2>&1; then
    echo "OK: calendar ready"
    break
  fi
  sleep 2
done

# Inspect logs (optional)
docker logs "$cid" | head

# Stop and remove when done
docker stop "$cid" && docker rm "$cid"
```

Set `OTS_CALENDARS` to prefer the local calendar during tests:

```bash
export OTS_CALENDARS="http://127.0.0.1:8468,https://a.pool.opentimestamps.org,https://b.pool.opentimestamps.org"
export OTS_STATIONARY_STUB=0  # ensure real-OTS mode for ratchets
```

### CI profiles and stationary calendar

We use three main CI profiles around OTS:

- `ots-cal` (see `.github/workflows/ots-cal.yml`):
  - Builds `ots/calendar:latest`.
  - Starts the container locally on the runner.
  - Runs `tox -e ots-cal` with `OTS_CALENDARS` pointing at the local calendar
    (plus public pools as a secondary).
- `ots-verify` (see `.github/workflows/ots-verify.yml`):
  - Generates real OTS proofs for `out/site_demo/day/*.cbor` and verifies them
    against Bitcoin headers using `bitcoind` / `bitcoin-cli`.
  - Uses `scripts/ci/ots_verify.sh` as the orchestrator.
- Weekly ratchet (`weekly-ratchet.yml`):
  - Builds and runs the local calendar sidecar.
  - Executes `tox -e ots-cal`, `tox -e ots`, and `tox -e slow` with
    `RUN_REAL_OTS=1` and `OTS_STATIONARY_STUB=0`.
  - Parses tox logs to ensure real-OTS tests actually ran and that no
    `Failed! Timestamp not complete` messages slipped by when `STRICT_REAL_OTS=1`.

The stationary calendar fits into this picture as a **deterministic local
anchor** used to:

- Avoid flakiness from public calendars during CI bring-up.
- Ensure the OTS client paths are exercised regularly (even when public
  calendars are slow or unreachable).
- Provide a clear upgrade path toward ADR-020 (stationary OTS calendar) while
  keeping tests fast and reproducible.

### Stationary vs. placeholder behavior in verification

`verify_cli` now treats OTS proofs as immutable sidecars:

- The day record (`*.json`) and day blob (`*.cbor`) are hashed into a Merkle
  tree; only the blob affects the `day_root`.
- OTS proofs live in separate `*.cbor.ots` files, with metadata in
  `proofs/<day>.ots.meta.json` describing:
  - the artifact path (`artifact`),
  - its SHA-256 (`artifact_sha256`),
  - and the proof path (`ots_proof`).
- During verification, `verify_cli`:
  - recomputes `sha256(day.cbor)` and compares it to `artifact_sha256`;
  - ensures `artifact` and `ots_proof` paths point at the expected files;
  - passes `artifact_sha256` into `verify_ots` so that even stationary stubs
    must match the recorded artifact hash.

This guarantees that mutating `.ots` files alone does not change `day_root`,
while mutating `*.cbor` will break verification — exactly the "Mutable Proof
Trap" we wanted to avoid.

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

Given a blob (typically a day record such as `out/site_demo/day/YYYY-MM-DD.cbor`) and a TSA URL, the helper will:

1. Compute a hash of the blob (default: SHA-256).
1. Ask `openssl ts -query` to build a TSQ with that digest via the `-digest` option
   (no `-sha256` short flags; behavior matches OpenSSL 3.x `ts -query -help`).
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
  out/site_demo/day/2025-10-07.cbor \
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
