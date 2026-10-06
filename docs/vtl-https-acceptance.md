# VTL HTTPS acceptance and reproducibility

An implementer can start with an HTTPS bundle-root URL, an authenticated expected
segment digest, a required verification scope, and verifier policy; retrieve
evidence produced by the PostgreSQL-backed VTL producer; and independently
reproduce the artifact, record, chain, and timestamp conclusions within that scope.

## Audit workflow

The gateway admits already-formed canonical records, retains their exact bytes,
assigns occurrences to bounded segments, computes the deterministic commitment,
seals the authoritative segment artifact, and obtains an RFC 3161 timestamp over
the artifact digest.

Later, an auditor receives an immutable disclosure bundle containing the artifact,
timestamp evidence, immediate predecessor, and either all record batches (Class A)
or selected complete batches (Class B). Class C supports an anchor-only check.
Batches are slices of the sorted leaf-hash list, not time windows. Selecting a
complete batch can disclose records outside the auditor's original selection.

## Which process opens which connection

```mermaid
sequenceDiagram
    participant P as PostgreSQL-backed producer/exporter
    participant T as Configured test TSA
    participant H as Co-located static HTTPS host
    participant V as Verifier
    P->>P: Retain exact records; seal linked segment artifact
    P->>T: HTTPS POST: DER TimeStampReq, SHA-256(artifact)
    T-->>P: DER TimeStampResp
    P->>P: Validate and retain response
    P->>H: Local atomic no-replace publication of complete snapshot
    Note over H,V: Provision URL, expected digest, scope, web trust, TSA trust and policy
    V->>H: HTTPS GET manifest and exact segment artifact
    H-->>V: Complete HTTP 200 identity bodies
    V->>H: GET only evidence consumed by scope
    H-->>V: Predecessor, timestamp evidence, selected record openings
    V->>V: Check bytes, commitments, predecessor and timestamp locally
```

| Logical arrow | Concrete exchange |
| --- | --- |
| Producer → TSA | TCP/TLS to the configured HTTPS authority, then an RFC 3161 HTTP POST carrying a DER request with SHA-256 of the exact segment artifact. |
| TSA → verifier | There is no direct connection. The TSA returns a DER response to the producer; the verifier later retrieves those exact octets from the evidence host. |
| Producer → verifier | The exporter publishes an immutable filesystem snapshot. The verifier uses HTTPS GET for the manifest, exact CBOR artifact, and scope-consumed evidence. |
| Producer → publisher | No wire protocol in this deployment: publication uses a shared filesystem and an atomic no-replace visibility transition. |
| Verifier → TSA | None. Timestamp validation is local using separately provisioned TSA anchors, CRLs, policy OID, signer pin, and evaluation policy. |

The exporter keeps the staging tree private while writing it, then makes its
directories traversable and files readable by the HTTPS service account before
the atomic publication step. The independent checker bounds each complete
fetch by elapsed time, including connection setup, headers, body, and retries.
It checks disclosed CBOR payloads incrementally under an item budget, avoiding
decoded collections proportional to attacker-controlled array lengths.

The [full sequence](diagrams/vtl-wire-sequence.svg),
[protocol stack](diagrams/vtl-wire-stack.svg), and
[binding notes](diagrams/vtl-wire-sequence.md) provide supporting detail.

## Reproduce and inspect

The frozen corpus and checksum are available in the dedicated
[controlled acceptance release](https://github.com/bilalobe/trackone/releases/tag/corpus-vtl-https-acceptance-20260909T215444Z).
To create a fresh run from a checkout with Python 3.10+, Rust/Cargo, curl with
TLS 1.3, OpenSSL 3, and a running Docker daemon:

```bash
python3 toolset/acceptance/run_vtl_https_exchange.py --output /tmp/vtl-audit-run/result
```

The [acceptance README](../toolset/acceptance/README.md) describes prerequisites,
outputs, focused rejection coverage, corpus construction, and detached replay.
The Python checker does not import TrackOne verification code or use the Rust
verdict as an oracle; both implementations use OpenSSL cryptography. This is
implementation independence, not organizational review.

The result establishes scope-specific consistency between disclosed record bytes,
the committed roots, the exact segment artifact, its immediate predecessor, and
the validated timestamp under the configured policy. It does not establish source
measurement accuracy, admission completeness, global ledger uniqueness, or the
validity of unopened batches. The services in the corpus are controlled test
services. The focused rejection report lists remaining coverage gaps.
