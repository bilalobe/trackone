# VTL conformance boundary

The current profile source is [Verifiable Telemetry Ledgers on the
IETF Datatracker](https://datatracker.ietf.org/doc/draft-elkhatabi-verifiable-telemetry-ledgers/).
It is an externally published Independent Submission Internet-Draft. Copies
of generated Internet-Draft source and renderings are deliberately not tracked
in this repository.

The implementation targets the profile identified by commitment-profile UUID
`c08ade4e-1785-4eb6-9648-b7003d76288d`. The checked-in conformance material
covers the following bounded surface:

- deterministic canonical-record and version-one segment-artifact encoding;
- hash-sorted Merkle commitments and aligned batch subtrees;
- segment lifecycle, empty-interval, chaining, and close-reason rules;
- producer-manifest version 1 and the three disclosure classes;
- the unversioned verifier-result shape identified by `verifier_policy_id`;
- RFC 3161 request/response, nonce, signer-certificate, and future-skew checks;
- the explicitly named `vtl-known-answer` and `vtl-interoperability` vectors; and
- deterministic archive packaging, offline schema resolution, and detached
  verifier replay.

Expanded conformance archives execute 16 named evidence cases: the three
disclosure scopes with historical TSA validation, integrity and scope failures,
TSA policy/pin/imprint failures, pending/unavailable issuance states, request and
nonce correlation, and the three documented TSA structural mutations. Reports
identify every executed case; the two additional manifest claims describe
disclosure fixture replay and TSA fixture rejection replay. The original claim
set remains readable with its original coverage.

CI also requires the fresh PostgreSQL-backed HTTPS exchange before archive
assembly. Its 24 scenarios run against both implementations, including transport
faults and predecessor continuity. This live gate uses controlled local services;
it does not claim production service availability or exhaustive HTTPS coverage.

These checks are implementation and archive claims, not a claim of unscoped
conformance to every aspect of the Internet-Draft. The archive builder does not
package the externally published profile source; it retains the checked-in
schemas, CDDL, vectors, packaged crates, Helm chart, and verifier binary. The
profile source remains the external document linked above.
