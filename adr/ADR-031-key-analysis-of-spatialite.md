Here is a concise proposal for `ADR 031` based on your context (SpatiaLite, threat model, crypto/network/systems/geometry angle, and earlier question about "key analysis of spatialite").

You can adapt wording to your repo’s ADR template.

______________________________________________________________________

# ADR 031 – Key Analysis of SpatiaLite for Geospatial Storage and Query

## Status

Proposed

## Context

The project evolved through several problem spaces:

- Initially framed as a cybersecurity / cryptography problem (data integrity, authenticity, provenance).
- Then as a networking problem (distributed exchange, synchronization, timestamps).
- Then as a systems-engineering problem (architecture, performance, deployment).
- Finally as a spatial geometry / geodata problem (geometric operations, spatial indexing, coordinate handling).

At this stage, we need to make an explicit architectural decision about using SpatiaLite as the primary geospatial storage and query engine for the project’s analytical workflows.

Key questions:

- Is SpatiaLite an acceptable tradeoff between functionality, reliability, and complexity versus alternatives (PostGIS, custom formats, Parquet+geometry extensions, flat files, or other embedded engines)?
- Does SpatiaLite integrate cleanly with our existing Python and Rust code, tooling (pip, cargo), and deployment targets?
- Are SpatiaLite’s security posture and attack surface acceptable within our threat model, given our use of external inputs and potentially untrusted geometry?
- How does this decision interact with our integrity mechanisms (e.g. OpenTimestamps), secure coding practices (e.g. OWASP guidance), and auditability requirements?

## Decision

We decide to:

1. **Adopt SpatiaLite** as the primary embedded geospatial storage and query engine for the project’s core analytical workflows.
1. **Standardize on a minimal, well-defined SpatiaLite profile**:
   - Constrained subset of geometry types and SRIDs.
   - Explicitly documented SQL patterns for spatial queries.
   - Controlled loading and enabling of SpatiaLite extensions.
1. **Treat SpatiaLite as a semi-trusted component** under the threat model:
   - All external inputs (including geometries) are validated and normalized before being persisted.
   - Query construction follows strict, parameterized patterns; dynamic SQL is forbidden or tightly constrained.
   - The SpatiaLite engine is kept up-to-date, and its version is pinned and documented.
1. **Integrate SpatiaLite with the integrity and provenance layer**:
   - Database artifacts that are part of the “evidence set” are hashed and, where applicable, anchored using OpenTimestamps (or equivalent).
   - We maintain a mapping from higher-level domain artifacts (reports, datasets) to their underlying SpatiaLite sources.
1. **Document SpatiaLite’s role and limitations in the threat model**:
   - Clarify what attacks SpatiaLite *does not* mitigate (e.g. compromise of the host, malicious extensions).
   - Clarify what mitigations we rely on from the broader stack (OS hardening, sandboxing, backups, etc.).

## Alternatives Considered

1. **PostGIS on a full PostgreSQL server**

   - Pros: Richest geospatial feature set, mature ecosystem, strong operational story.
   - Cons: Higher operational complexity, heavier runtime footprint, not ideal for embedded or offline analysis scenarios, diverges from the “self-contained artifact” goal.

1. **Parquet (or similar columnar format) with geometry encodings**

   - Pros: Strong analytics ecosystem, good compression, interop with big-data tooling.
   - Cons: More work to model robust geometry operations and spatial indexing; requires additional layers for spatial predicates; increases implementation complexity in both Python and Rust.

1. **Custom binary or JSON-based geometry storage**

   - Pros: Maximum control, minimal dependencies.
   - Cons: Re-implements substantial geospatial logic (indexing, predicates, transformations); high risk of subtle correctness and security issues; long-term maintenance burden.

1. **Other embedded databases with geospatial extensions (e.g. DuckDB + extensions, others)**

   - Pros: Modern engines, potentially better analytical performance.
   - Cons: Less mature geospatial support compared to SpatiaLite; less predictable availability across environments; more volatile extension ecosystem.

Given the project’s emphasis on:

- Repeatable, portable, *auditable* analysis artifacts;
- Strong but pragmatic threat modeling;
- A balance between security, correctness, and maintainability;

SpatiaLite offers a better compromise than the alternatives for this phase of the project.

## Consequences

### Positive

- **Portability and reproducibility**: Analysis artifacts can be exchanged as single-file databases, simplifying audits and offline review.
- **Rich spatial functionality** without re-implementing core geometry algorithms.
- **Tighter integration with integrity layers**: Easy to hash and timestamp complete analysis states.
- **Clearer threat model boundaries**: We can explicitly reason about SpatiaLite as a delimited component with defined inputs and outputs.

### Negative / Risks

- **Dependency and supply-chain exposure**: We now rely on SpatiaLite and its transitive dependencies; vulnerabilities here affect the project.
- **Complexity of spatial SQL**: Misuse of spatial functions can lead to subtle correctness and performance issues.
- **Limited multi-user concurrency** compared to a full DB server; suitable for our use case, but not for high-concurrency deployments.
- **Version skew**: Different environments may ship different SpatiaLite/SQLite versions; we must pin, document, and test specific versions.

### Mitigations

- Pin and document exact versions of SpatiaLite and SQLite in `requirements` / `Cargo.toml` / packaging docs.
- Maintain regression tests and property-based tests for critical spatial operations in both Python and Rust bindings.
- Follow relevant OWASP guidance for:
  - Input validation and canonicalization (especially geometry and SRID handling).
  - Safe database usage (parameterization, least privilege).
  - Logging and error handling (avoiding sensitive data leakage).
- Use OpenTimestamps (or equivalent) to anchor:
  - Critical SpatiaLite database snapshots.
  - Derived reports and threat-model artifacts tied to these databases.
- Periodically review SpatiaLite’s CVEs and update the dependency as part of security maintenance.
