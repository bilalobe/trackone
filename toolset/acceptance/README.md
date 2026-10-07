# VTL HTTPS acceptance exchange

This controlled run joins the real PostgreSQL-backed gateway producer, RFC 3161
issuance, immutable export, HTTPS retrieval and two verification implementations.
Read the [acceptance walkthrough](../../docs/vtl-https-acceptance.md) for the
concrete audit exchange and limits of the claim.

## Fresh run

Prerequisites: Linux (the exporter uses a same-filesystem no-replace rename),
Python 3.10 or later, Rust/Cargo supporting the workspace's edition and MSRV,
OpenSSL 3, curl built with TLS 1.3, and a running Docker daemon accessible to the
current user. Cargo dependencies and `postgres:17-alpine` must be cached or
downloadable. Local loopback listeners and temporary disk space are required.

From the repository root:

```bash
python3 toolset/acceptance/run_vtl_https_exchange.py --output /tmp/vtl-audit-run/result
```

The output must not exist. The runner builds the gateway, exporter and verifier,
starts an isolated database and controlled HTTPS services, admits two segments
of five record occurrences, and exports timestamp-complete Class A/B/C evidence.
It removes its database container and stops its services on exit; evidence stays
in the requested output directory. No existing database is used.

Successful output ends with `acceptance exchange succeeded`. Inspect:

| Output | Purpose |
| --- | --- |
| `published/class-{a,b,c}/` | Exact immutable bundle objects for one segment, under three disclosure scopes. |
| `reports/*-independent.json`, `reports/*-trackone.json` | Matched artifact, scope, chain, overall and TSA conclusions. |
| `reports/wire-coverage.json` | 24 required scenarios run against both implementations; 48 checks total, with explicit pending and undisclosed-predecessor conclusions. |
| `verification-inputs.json` | Explicit segment digest, scope selections, TSA policy/pin and evaluation time for replay. |
| `tsa-exchange/` | Exact DER requests and responses plus controlled service request log. |
| `https-evidence/` | Original evidence-host request log. |
| `trust-inputs/` | Public HTTPS/TSA certificates and TSA CRLs; no private keys. |
| `tool-versions.json`, `source-sha256.json`, `SHA256SUMS` | Tools, resolved database image identity, source hashes held constant during the run, and complete evidence inventory. |

Class A fetches five record occurrences in nine object requests. Class B fetches
the two occurrences in batch 0; Class C fetches no records. Duplicate record
occurrences remain separate commitment leaves and disclosure entries.

The negative matrix injects untrusted web trust, redirect, 206, 404, persistent
503, truncation, conflicting lengths, Transfer-Encoding plus Content-Length,
unexpected content encoding, HTTP/1.0, unsafe path, wrong expected digest,
altered record bytes, scope downgrade, and wrong TSA imprint/policy/pin. Positive
controls exercise special filename encoding and anchor/batch-only retrieval.
Each failure must have a matching diagnostic, not merely a nonzero exit status.
The wrong-imprint response is selected by the predecessor request's imprint,
independently of issuance order, and its response imprint is checked before use.
Additional cases cover pending/unavailable TSA and missing/bad predecessor
evidence. Rust permits a missing predecessor and reports
`predecessor_not_disclosed`; the independent HTTPS checker requires the immediate
predecessor. Pending TSA is explicitly `incomplete`, never successful verification.
The corpus builder requires the exact named case inventory for both implementations.
The report lists requirements by draft anchor and names untested areas. It does
not establish complete Appendix E or full RFC 3161 rejection coverage.

If Docker access fails, enable daemon access before rerunning. If Cargo or image
downloads fail, restore network access or populate caches. A failed output is
retained for diagnosis; rerun with a different output path. A certificate error
on an old fixture is not a reason to disable validation: use corpus replay below
or perform a fresh run.

## Freeze and publish

After a successful run, choose a unique UTC release timestamp and build:

```bash
python3 toolset/acceptance/build_corpus.py \
  --result /tmp/vtl-audit-run/result \
  --release vtl-https-acceptance-20260909T220000Z \
  --output /tmp/vtl-https-acceptance-20260909T220000Z.tar.gz
```

The timestamp above is an example identifier. The builder verifies the complete
result inventory and passing reports, includes the actual source snapshot and
base commit in provenance, and normalizes archive metadata. Repeating packaging
with unchanged inputs yields identical bytes; fresh live runs do not.
Source bytes in the archive are authoritative when worktree changes are present.
The release tag alone is not a claim that its commit contains those changes.

Publish the archive and adjacent `.sha256` file as assets in a dedicated GitHub
prerelease using `corpus-` followed by that identifier as its tag, without marking
it the latest product release. The prefix avoids the product workflow's `v*`
tag trigger. Preserve existing assets; never clobber an identifier. The release
description must identify the controlled services, source snapshot, demonstrated
claims, gaps, checksum and replay command. Download and replay the public asset
before announcing completion.

## Detached replay

Download both assets from the selected dedicated release under
[TrackOne releases](https://github.com/bilalobe/trackone/releases). Verify the
external checksum, extract to a new directory, then follow the archive's
[top-level instructions](CORPUS.md). Python and OpenSSL suffice; no Cargo,
Docker, production TSA, or TrackOne binary is required for historical replay.

The provisioned digest and policy in this controlled corpus are selected by the
publisher. In an actual audit, the relying party must authenticate those inputs
through its own trusted mechanism; a checksum downloaded with an archive is an
integrity check, not independent authentication of its selection.

The first packaged run is
[vtl-https-acceptance-20260909T215444Z](https://github.com/bilalobe/trackone/releases/tag/corpus-vtl-https-acceptance-20260909T215444Z).

The fresh-run harness additionally uses a TLS proxy to exercise the gateway's
ledger-addressed disclosure API. It writes `class-{a,b,c}-http-bundle/` directories
and `class-{a,b,c}-gateway-{independent,trackone}.json` reports. Each bundle is
requested and downloaded by the detached independent client, then verified from
disk by `trackone-evidence`. All bytes must match the shared CLI exporter.
Scoped credentials live only in the temporary working directory.
