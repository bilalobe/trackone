# VTL HTTP binding fixtures

`exchanges.json` gives request methods, paths, headers, JSON bodies, status codes,
and response headers. Binary response bodies are stored as exact `.cbor` and
`.tsr` files, referenced by `body_file`. `FIXTURE_CREDENTIAL` is a placeholder,
not a usable bearer token. Each error exchange specifies its required state in
`precondition`; `absent` means the requested segment is missing.

Class A/B/C directories reuse the normative known-answer segment and records,
and the archived RFC 3161 response from `../vtl-interoperability/tsa/`.
The manifest bytes match the shared gateway snapshot builder, including path
ordering and duplicate-preserving occurrence positions. The timestamp fixture
requires the archived trust/policy/evaluation inputs documented in that corpus;
fresh acceptance runs create their own TSA and trust archive.

The three adjacent manifests show timestamp-state progression with the same
segment reference. They describe live views, not generated complete disclosures.
The producer manifest binds every evidence object; JSON availability and access
errors are transport results, not verification evidence. No SCITT is required.
