# Authenticated VTL HTTP retrieval and disclosures

This is the gateway HTTP binding for issue #321. The service serves its configured
ledger. An independent verifier needs an HTTPS service URL, a scoped bearer
credential, an independently provisioned expected segment digest, a verification
scope, and separately provisioned TSA trust and policy. A digest obtained only
from this service is an integrity check, not independent authentication of the
intended segment. TLS termination belongs to the deployment.

## Standards used

The binding profiles [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html)
for methods, status codes, conditional requests, and ETags;
[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html) for HTTP problem details;
[RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) for `Content-Digest` and
`Repr-Digest`; and [RFC 8288](https://www.rfc-editor.org/rfc/rfc8288.html) for
manifest links. RFC 3161 remains the timestamp evidence format. These standards
supply the transport mechanisms; producer manifest v1 supplies the VTL-specific
ledger, segment, disclosure, and artifact bindings.

## Addressing and exact objects

The base is `/v2/ledgers/{ledger_id}/segments/{segment_number}`. Ledger IDs are
32 lowercase hexadecimal characters. Segment and batch numbers are canonical
uint64 decimal strings: `0` or a nonzero digit followed by digits, without a
sign or leading zero. Identifiers are validated before database access.

| Method and suffix | Representation |
| --- | --- |
| `GET /segment.verify.json` | Current Class C producer manifest v1; no record openings. |
| `GET /segment.cbor` | Exact stored authoritative segment CBOR. |
| `GET /predecessor.cbor` | Exact immediate predecessor; absent for segment zero. |
| `GET /timestamp.tsr` | Exact retained, verified RFC 3161 response. |
| `POST /disclosures` | Generate an authorized timestamp-complete disclosure. |
| `GET /disclosures/{manifest_sha256}/{path}` | Immutable manifest or manifest-listed object. |

Object GETs without a matching conditional return HTTP 200, `Content-Digest: sha-256=:BASE64:`,
a strong ETag containing the lowercase SHA-256 in quotes, and a `Link` with
`rel="describedby"` pointing to the producer manifest. The manifest links to
itself; its digest does not appear recursively inside it. Content types are
`application/json`, `application/cbor`, and `application/timestamp-reply`.
Bodies are complete identity representations; range requests receive the full
200 response. `If-Match` uses strong comparison and returns 412 on mismatch;
`If-None-Match` uses weak comparison and returns 304 on a match. Authentication
and authorization are enforced before either conditional result. `Repr-Digest`
carries the same SHA-256 for the complete selected representation. HEAD and 304
responses have no content digest because they carry no message content, while
retaining the representation digest and ETag. No CBOR or timestamp re-encoding
occurs.
Every evidence object is referenced by relative path and SHA-256 in producer
manifest v1. Access/availability errors and generation receipts are transport
metadata, not additional VTL evidence objects.

All evidence responses use `Cache-Control: private, no-store`. Every request
must authenticate, including individual record openings and manifests. A bundle
URL is not a bearer capability. Only paths listed by its stored manifest can be
retrieved; filesystem paths and arbitrary object listing are not exposed.

## Availability and immutability

| Condition | HTTP | JSON code | Additional behavior |
| --- | --- | --- | --- |
| Pending | 202 | `pending` | `Retry-After: 5`; poll again. |
| Unavailable | 503 | `unavailable` | `reason` distinguishes `timestamp`, `storage`, `capacity`, `integrity`, or `service`. |
| Absent | 404 | `absent` | Authorized resource lookup found no object. |
| Unauthorized | 401 | `unauthorized` | `WWW-Authenticate: Bearer`; missing, invalid, or ambiguous credential. |
| Policy denied | 403 | `policy_denied` | Valid credential lacks the requested permission. |

Error responses use RFC 9457 `application/problem+json` with `type`, `title`,
`status`, and `detail`. The `type` is the stable absolute documentation URI for
the problem; clients should identify problems using that URI. `code` is a
convenience extension, and unavailable also has a `reason` extension. Internal
PostgreSQL diagnostics and credentials never appear in responses. Pending is an
ordinary 202 `application/json` status representation with `code` and `message`,
`Retry-After`, and a `Location` pointing to the current manifest as its monitor.
The client must retry generation after the timestamp becomes available.

Invalid identifiers, JSON selections, duplicate batches, or unknown selection
fields return 400 `invalid_request`. Generation requires identity
`application/json` (415 otherwise) and a body no larger than 64 KiB (413
otherwise). These errors also use problem details.

Authentication precedes request-body extraction. Ledger authorization precedes
resource lookup; a ledger outside the grant returns 403 even if nonexistent.
An explicitly granted ledger that this service does not serve returns 404.
A missing bundle returns 404; an existing bundle outside the caller's class or
batch permissions returns 403. Class/batch authorization precedes object access.

The current manifest itself returns 200 while describing timestamp state:
`queued` → `pending`, `failed` → `unavailable`, `verified` → `present`.
`tsa_tsr` appears only in the present state. Timestamp GET and disclosure POST
return 202 while queued and 503 with reason `timestamp` after terminal failure.
Service/capacity outages are retryable; terminal timestamp failure needs an
operator intervention outside this API. No retry promise is attached to 503.

A live manifest is read from one repeatable-read database snapshot. Its bytes
and ETag may change when timestamp evidence progresses; segment bytes, segment
digest, and predecessor remain identical. Stored integrity inconsistencies fail
closed. Read the live manifest again if a previously missing timestamp becomes
available. Generated bundle manifests and objects never change.

### Unauthorized

Problem type `#unauthorized`: HTTP 401, credential missing or invalid.

### Policy denied

Problem type `#policy-denied`: HTTP 403, authenticated request exceeds its grant.

### Absent

Problem type `#absent`: HTTP 404, authorized resource lookup found no object.

### Unavailable

Problem type `#unavailable`: HTTP 503, material or service unavailable; inspect
`reason` to distinguish terminal timestamp failure from a transient outage.

### Invalid request

Problem type `#invalid-request`: HTTP 400, invalid identifier or selection.

### Payload too large

Problem type `#payload-too-large`: HTTP 413, generation request exceeds 64 KiB.

### Unsupported media type

Problem type `#unsupported-media-type`: HTTP 415, generation requires identity
JSON and does not accept a content encoding.

### Precondition failed

Problem type `#precondition-failed`: HTTP 412, the strong ETag precondition failed.

## Scoped grants and generation

Set `TRACKONE_DISCLOSURE_GRANTS_FILE` to a protected JSON file:

```json
[
  {
    "principal_id": "partner-auditor",
    "token": "replace-with-a-random-32-to-256-character-token",
    "grants": [
      {
        "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
        "read_segments": true,
        "classes": ["B", "C"],
        "batches": ["0", "2"]
      }
    ]
  }
]
```

`read_segments` authorizes the four current-object routes. `classes` separately
authorizes generation and reads of complete disclosures. `batches` applies to
Class B only; use an explicit array or the string `"all"`. A Class A grant
explicitly authorizes all records regardless of the Class B batch restriction.
Class C grants authorize anchor-only bundles. Every object GET rechecks the
whole stored bundle's class and batch selection, including its manifest.
Multiple credentials can share a principal ID for rotation; duplicate tokens
and duplicate ledger grants within a credential are rejected. Tokens are
32–256 visible ASCII characters, retained as SHA-256 hashes and compared in
constant time. Malformed configuration fails startup. Omission disables access
to all new routes; ingestion credentials provide no implicit evidence access.
Changes and revocations take effect after restart, including for old bundles.

Generation accepts exactly these forms:

```json
{"class":"A"}
{"class":"B","batches":["0","2"]}
{"class":"C"}
```

Class A opens all batches. Class B opens a nonempty proper subset of complete
batches in global leaf-digest order. A batch may contain records outside the
caller's original record selection: authorization covers the entire batch.
Class C opens no records. Empty batch arrays are also accepted for A/C.
Every class carries the segment, immediate predecessor when applicable, and
timestamp response. Existing snapshot validation recomputes retained records
before publishing and preserves duplicate occurrences.

Publication inserts a manifest and its objects in one PostgreSQL transaction.
The URL contains the SHA-256 of the exact manifest bytes. First creation returns
201; a byte-identical repeated selection returns 200 with the same receipt:

```json
{
  "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
  "segment_number": "0",
  "class": "C",
  "manifest_sha256": "<64 lowercase hex characters>",
  "artifact_sha256": "<64 lowercase hex characters>",
  "bundle_url": "/v2/ledgers/b7a1d5e40c6f438e9a75db27c96f31aa/segments/0/disclosures/<manifest_sha256>/"
}
```

`Location` identifies that bundle's `segment.verify.json`. The shared CLI/HTTP
builder gives identical bytes for identical inputs. Publication survives service
restarts. The additive migration does not change sealed artifacts or the queue.
There is no deletion/retention API. Evidence work uses independent connections
and four shared request slots; excess requests receive 503 `capacity` without
blocking the producer mutex.

For Helm, set `gateway.disclosure.existingSecret` to a Secret containing
`grants.json`. The chart mounts it read-only and sets the environment variable.
The existing admission API, timestamp-status endpoint, and CLI exporter retain
their interfaces.

## Independent retrieval and verification

The Python client uses published HTTP and manifest formats and imports no
gateway runtime code. Its HTTPS client rejects redirects, bounds reads and
request duration, checks digest headers when supplied, and sends credentials
only to the configured origin. Generation accepts only the expected descendant
bundle URL. Credential file contents are excluded from reports.

```bash
python3 toolset/independent-verifier/verify_https_bundle.py \
  --bundle-url "https://gateway.example/v2/ledgers/$LEDGER/segments/0/" \
  --generate-class B --batch 0 --scope disclosed_batch_recompute \
  --bearer-token-file /run/secrets/auditor-token \
  --expected-segment-sha256 "$EXPECTED_SEGMENT_SHA256" \
  --https-ca-file https-root.pem \
  --tsa-ca-file tsa-root.pem --tsa-crls-file tsa-crls.pem \
  --tsa-policy "$TSA_POLICY" --tsa-signer-cert-sha256 "$TSA_SIGNER_SHA256" \
  --download-dir /tmp/disclosure

cargo run --locked -p trackone-evidence -- verify --root /tmp/disclosure \
  --tsa-ca-file tsa-root.pem --tsa-crls-file tsa-crls.pem \
  --tsa-policy "$TSA_POLICY" --tsa-signer-cert-sha256 "$TSA_SIGNER_SHA256" \
  --json
```

The output directory must not exist. The downloader checks every referenced
object, including objects outside a deliberately narrowed verification scope.
Downloading all references does not expand the verifier's reported scope.
SCITT remains optional extension material; it neither gates retrieval nor
participates in baseline VTL verification. No SCITT service is required.

## Acceptance mapping

| #321 criterion | Executable coverage |
| --- | --- |
| Ledger/segment addressing and exact bytes/digest | `evidence_binding` PostgreSQL tests; checked-in HTTP exchanges and digest tests. |
| Immutable artifact as timestamp progresses | `states_authentication_and_immutable_artifact`; existing timestamp-worker tests. |
| Five response states | PostgreSQL state/authentication tests and `fixture_errors_match_contract`. |
| Authenticated A/B/C and complete-batch permissions | `complete_snapshots_replay_authorization_and_integrity`; configuration tests. |
| Producer-manifest binding | `checked_in_http_bundles_match_shared_builder`; every-object digest checks and substitution rejection. |
| Request/response fixtures | `toolset/vectors/vtl-http-binding/exchanges.json` and exact byte fixtures; offline manifest schema validation. |
| Export verified with trackone-evidence | HTTPS acceptance generates and downloads all three classes and verifies each directory with the Rust CLI. |
| Independent client | Detached Python checker authenticates directly to the HTTPS gateway and compares CLI/HTTP exports byte for byte. |
| SCITT optional | All baseline fixtures and gateway acceptance bundles omit SCITT. |

Run `python3 toolset/acceptance/run_vtl_https_exchange.py --output /tmp/vtl-http-run`
with Docker, Cargo, OpenSSL, and curl available. PostgreSQL integration tests use
`TRACKONE_TEST_DATABASE_URL`; CI requires this variable. The existing static
HTTPS and focused rejection scenarios remain part of the same acceptance run.
