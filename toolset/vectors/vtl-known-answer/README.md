# VTL normative known-answer vector

`vector.json` transcribes the complete record, Merkle, aligned-batch, segment
CBOR, length, and digest values from Appendix A of the externally published
profile source. Rust and detached archive tests reproduce these
values rather than treating the transcription as an implementation oracle.

The profile's normative appendix is reproduced in full, so the transcription covers every
value it fixes:

- `records_cbor_hex`, `leaf_hashes`, `sorted_leaf_hashes`, `batch_roots`, and
  `segment_root` — the three-record compact segment at `batch_record_limit` 2.
- `segment_cbor_hex` with its 462-octet length and digest — the epoch artifact
  (`segment_number` 0, all-zero `prev_segment_sha256`).
- `distinct_encoding_cases` — integer `1`, float `1.0`, and positive and
  negative floating-point zero, which must retain distinct deterministic
  encodings and therefore distinct leaf hashes.
- `duplicate_occurrence_roots` — segment roots for three and four occurrences
  of the same record bytes, independent of `batch_record_limit`.
- `empty_shutdown_suppress` — the 394-octet empty successor artifact that
  exercises the lifecycle exception where an empty `shutdown` artifact retains
  `empty_mode` equal to `suppress`, with `segment_root` equal to SHA-256 over
  zero octets and `prev_segment_sha256` chaining to the artifact above.
