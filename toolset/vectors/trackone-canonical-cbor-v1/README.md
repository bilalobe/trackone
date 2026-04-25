# TrackOne Canonical CBOR Vector Corpus v1

This directory is the public conformance corpus for
`trackone-canonical-cbor-v1`.

External verifiers should start from `manifest.json`. The manifest names the
CDDL profile, vector-manifest schema, CBOR encoding profile, fact/day CBOR
shapes, artifact paths, artifact digests, and ADR-003 Merkle policy. A verifier
does not need TrackOne source code to recompute the fact digests, sorted leaf
hashes, Merkle root, or day-record digest.

The fact leaves in this corpus are deterministic CBOR encodings of the
canonical JSON fact projection (`fact-json-projection-v1`). The lower-level
Rust `fact-v1` positional array in the CDDL is the framed/runtime payload shape;
it is not the published Merkle leaf shape for this corpus.

The deterministic JSON-to-CBOR profile uses shortest-form integer encoding,
shortest exact finite-float encoding (`float16`, then `float32`, otherwise
`float64`), and text map keys sorted by encoded key length then bytewise UTF-8
order. Non-finite floats are invalid.

The corpus fact JSON files use `commitment_fact_projection.schema.json`, not
the runtime `fact.schema.json` operational shape. The audited profile rules
are:

- JSON integers are valid only in signed-`i64` or unsigned-`u64` range;
  out-of-range integers are invalid profile inputs.
- Top-level fact fields are closed by schema. Payload keys are open, but values
  must be JSON values accepted by the deterministic JSON-to-CBOR profile.
- `ingest_time` and `pod_time` in corpus facts are RFC3339 UTC text with a `Z`
  suffix; `pod_time` is required and may be explicit `null`.
- Optional fields are omitted when unset. Absent and `null` are not equivalent.
- Artifact files are raw bytes. Digest and root fields in JSON are lowercase
  hexadecimal text. JSON projection payloads do not encode arbitrary bytes.
- Day and block versions are version `1`; unknown top-level fields are rejected
  by the public schemas.

The Merkle policy is:

- `leaf_hash = SHA-256(leaf_cbor_bytes)`
- sort leaf hashes lexicographically as raw 32-byte values
- `parent_hash = SHA-256(left || right)`
- duplicate the last hash at odd levels
- empty tree root is `SHA-256(b"")`

The profile identifier is claim-bound, not embedded into every commitment
preimage. This corpus carries `commitment_profile_id` in `manifest.json`, but
the fact hashes, Merkle root, and day-record digest are computed over the
artifact bytes and Merkle policy above. A verifier must select and check the
explicit profile claim before interpreting the committed bytes.
