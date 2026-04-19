# Architecture Decision Records (ADRs)

This directory contains the key design decisions for Track1 (secure telemetry + verifiable ledger).
Each ADR captures context, the decision, consequences, and alternatives.

## Index (Project)

- [ADR-001: Cryptographic Primitives and Framing](ADR-001-primitives-x25519-hkdf-xchacha.md)
- [ADR-002: Telemetry Framing, Nonce/Replay Policy, and Device Table](ADR-002-telemetry-framing-and-replay-policy.md)
- [ADR-003: Canonicalization, Merkle Policy, and Daily OpenTimestamps Anchoring](ADR-003-merkle-canonicalization-and-ots-anchoring.md)
- [ADR-004: Framed Ingest Stub for M#1 (Plaintext CT for Pipeline Bring-up)](ADR-004-framed-ingest-stub.md)
- [ADR-005: Migrate to PyNaCl for All Cryptographic Primitives](ADR-005-pynacl-migration.md)
- [ADR-006: Forward-only schema policy and deprecating `salt4`](ADR-006-forward-only-schema-and-salt8.md)
- [ADR-007: OTS Verification in CI and Bitcoin Headers Policy](ADR-007-ots-ci-verification-and-bitcoin-headers.md)
- [ADR-008: Milestone M#4 Completion and OTS Verification Workflow](ADR-008-m4-completion-ots-workflow.md)
- [ADR-009: Bandit findings remediation and decisions](ADR-009-bandit-remediation.md)
- [ADR-010: Test suite refactor (structure and naming)](ADR-010-test-suite-refactor-structure-naming.md)
- [ADR-011: Benchmarking Strategy for TrackOne](ADR-011-benchmarking-strategy.md)
- [ADR-012: Parquet Export for Telemetry Facts and Columnar Storage](ADR-012-parquet-export-and-columnar-storage.md)
- [ADR-013: Python Version Support Policy (Last Three Minors)](ADR-013-python-version-support-policy.md)
- [ADR-014: Stationary OpenTimestamps Calendar for Deterministic Anchoring](ADR-014-stationary-ots-calendar.md)
- [ADR-015: Parallel Anchoring with OpenTimestamps and RFC 3161 TSA](ADR-015-parallel-anchoring-ots-rfc3161-tsa.md)
- [ADR-016: Changelog Policy and Automation with git-cliff](ADR-016-changelog-policy-git-cliff.md)
- [ADR-017: Rust Core and PyO3 Integration Strategy](ADR-017-rust-core-and-pyo3-integration.md)
- [ADR-018: Cryptographic randomness and nonce policy](ADR-018-cryptographic-randomness-and-nonce-policy.md)
- [ADR-019: Rust Gateway and End-to-End Chain of Trust for Stationary OTS Calendar](ADR-019-rust-gateway-chain-of-trust.md)
- [ADR-020: Follow-up on Stationary OTS Calendar (ADR-014)](ADR-020-stationary-ots-calendar-followup.md)
- [ADR-021: Safety net for OTS pipeline and verification](ADR-021-safety-net-ots-pipeline-verification.md)
- [ADR-022: First-party stationary OTS calendar service in CI](ADR-022-first-party-stationary-ots-calendar-service.md)
- [ADR-023: Prefer OTS for integrity and time anchoring over Git plumbing tools](ADR-023-ots-vs-git-integrity.md)
- [ADR-024: Anti-replay and OTS-backed ledger semantics](ADR-024-anti-replay-and-ots-backed-ledger.md)
- [ADR-025: Adaptive Uplink Cadence via Authenticated LoRa Downlink Policy](ADR-025-adaptive-uplink-cadence-over-lora.md)
- [ADR-026: Future OTA Firmware Updates over LoRa (Signed, Chunked, Dual-Slot)](ADR-026-ota-firmware-updates-over-lora.md)
- [ADR-027: Representation of SHTC3-Class Sensors and Environmental Readings](ADR-027-sensorthings-shtc3-representation.md)
- [ADR-028: Mapping TrackOne Canonical Facts to OGC SensorThings API](ADR-028-sensorthings-projection-mapping.md)
- [ADR-029: Environmental Sensing Use-Cases and Daily Summary Metrics](ADR-029-env-daily-summaries-and-usecases.md)
- [ADR-030: Environmental Evidence Model, Projections, and Duty-Cycled Anchoring](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)
- [ADR-031: Key Analysis of SpatiaLite for Geospatial Storage and Query](ADR-031-key-analysis-of-spatialite.md)
- [ADR-032: Proposing an Informational RFC for Verifiable Telemetry Ledgers](ADR-032-informational-rfc-verifiable-telemetry-ledger.md)
- [ADR-033: Virtual Fleet for Verifiable Telemetry and End-to-End Validation](ADR-033-virtual-fleet-verifiable-telemetry.md)
- [ADR-034: Serialization Boundaries - Transport vs Commitment Encodings](ADR-034-serialization-boundaries-transport-vs-commitments.md)
- [ADR-035: Workspace Versioning and Release Visibility (Umbrella vs Per-Crate)](ADR-035-workspace-versioning-and-release-visibility.md)
- [ADR-036: Post-Quantum Hybrid Provisioning (X25519 + ML-KEM/Kyber)](ADR-036-post-quantum-kem.md)
- [ADR-037: Signature Roles and Verification Boundaries (Who Signs What)](ADR-037-signature-roles-and-verification-boundaries.md)
- [ADR-038: Surface Tooling Boundaries and `abi3` Wheel Strategy](ADR-038-surface-tooling-and-abi3-wheel-strategy.md)
- [ADR-039: CBOR-First Commitment Profile and Artifact Authority](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md)
- [ADR-040: Commitment Test Vectors and Cross-Implementation Conformance Gates](ADR-040-commitment-test-vectors-and-conformance-gates.md)
- [ADR-041: Verification Disclosure Bundles and Privacy Tiers](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md)
- [ADR-042: Hardware Watchdog & Liveness-Registry Policy](ADR-042-hardware-watchdog-and-liveness-registry.md)
- [ADR-043: Phased Bundle-Manifest Maturity for the I-D](ADR-043-phased-bundle-manifest-maturity-for-id.md)
- [ADR-044: JSON Schema Modularity and Authoritative Contract Artifacts](ADR-044-json-schema-modularity-and-authoritative-contract-artifacts.md)
- [ADR-045: Git-Signed Evidence Distribution Plane for Release and Small Authoritative Artifacts](ADR-045-git-signed-evidence-distribution-plane.md)
- [ADR-046: Sealed Trust-Root Boundary and Deferring a Dedicated `trackone-seal` Crate](ADR-046-sealed-trust-root-boundary-and-deferring-trackone-seal.md)
- [ADR-047: TrackOne as the Evidence Plane Within a Broader Device Lifecycle System](ADR-047-trackone-evidence-plane-within-device-lifecycle.md)
- [ADR-048: Separate SCITT Publication Profile from the Base Telemetry-Ledger Draft](ADR-048-separate-scitt-publication-profile.md)
- [ADR-049: Native Evidence-Plane Crypto Boundary and PyNaCl Demotion](ADR-049-native-evidence-plane-crypto-boundary-and-pynacl-demotion.md)
- [ADR-050: Fiftieth ADR Milestone and Record Stewardship](ADR-050-fiftieth-adr-milestone-and-record-stewardship.md)

## Index Conventions

Entries list **Status** and **Summary**. Related references are grouped under **See also**.

### Core Cryptography & Framing

- **[ADR-001](ADR-001-primitives-x25519-hkdf-xchacha.md): Cryptographic Primitives and Framing**
  **Status**: Accepted
  **Summary**: Establishes modern, efficient primitives for provisioning and AEAD telemetry:

  - X25519 + HKDF for key derivation
  - XChaCha20-Poly1305 for AEAD (M#2 implementation)
  - Ed25519 for identity/config/firmware signatures
  - SHA-256 for Merkle trees and hashing

- **[ADR-002](ADR-002-telemetry-framing-and-replay-policy.md): Telemetry Framing, Nonce/Replay Policy, and Device Table**
  **Status**: Accepted
  **Summary**: Defines compact frame layout and gateway security policies:

  - Frame header: dev_id(u16), msg_type(u8), fc(u32), flags(u8)
  - 24-byte XChaCha nonce construction: salt(8)||fc(8)||rand(8)
  - Gateway replay window with configurable size (default: 64)
  - Device table for per-device state tracking (highest_fc_seen, last_seen)
  - M#1 implementation: stub decryption (base64 JSON), real AEAD in M#2
  - **See also**: [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md), [ADR-025](ADR-025-adaptive-uplink-cadence-over-lora.md), [ADR-026](ADR-026-ota-firmware-updates-over-lora.md)

- **[ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md): Canonicalization, Merkle Policy, and Daily OpenTimestamps Anchoring**
  **Status**: Accepted
  **Summary**: Ensures deterministic, verifiable data integrity:

  - Canonical commitment discipline (historically JSON-first; commitment authority now profiled by [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md))
  - Hash-sorted Merkle leaves for order independence
  - Day chaining via prev_day_root (32 zero bytes for genesis)
  - Daily OTS anchoring for public timestamp verification
  - Schema validation for facts, block headers, and day records
  - **See also**: [ADR-021](ADR-021-safety-net-ots-pipeline-verification.md), [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md), [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)

- **[ADR-004](ADR-004-framed-ingest-stub.md): Framed Ingest Stub for M#1 (Plaintext CT for Pipeline Bring-up)**
  **Status**: Superseded by ADR-001/002
  **Summary**: Documents the temporary plaintext-ciphertext stub used to bring up the end-to-end pipeline before real AEAD; replay window enforced; canonical facts emitted.

- **[ADR-005](ADR-005-pynacl-migration.md): PyNaCl Migration**
  **Status**: Superseded by [ADR-049](ADR-049-native-evidence-plane-crypto-boundary-and-pynacl-demotion.md)
  **Summary**: Historical Python-first consolidation of crypto operations to PyNaCl (libsodium):

  - Removed `cryptography` dependency
  - Unified API for X25519, HKDF, ChaCha/XChaCha AEAD, Ed25519
  - Regenerated test vectors with PyNaCl bindings
  - Superseded for primary runtime dependency strategy by `trackone_core`
    evidence-plane authority

- **[ADR-034](ADR-034-serialization-boundaries-transport-vs-commitments.md): Serialization Boundaries - Transport vs Commitment Encodings**
  **Status**: Accepted
  **Summary**: Separate transport encoding (Postcard) from commitment encoding to avoid accidental mixing of wire formats and hash commitments.

- **[ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md): CBOR-first commitment profile and artifact authority**
  **Status**: Accepted, Updated 2026-04-18
  **Summary**: Makes deterministic CBOR the canonical commitment path (RFC 8949 baseline + TrackOne profile constraints), defines `.cbor` artifacts as authoritative, and demotes JSON to projection-only views.

- **[ADR-049](ADR-049-native-evidence-plane-crypto-boundary-and-pynacl-demotion.md): Native evidence-plane crypto boundary and PyNaCl demotion**
  **Status**: Accepted
  **Summary**: Makes `trackone_core` the stable Python-facing authority for supported evidence-plane crypto/admission and commitment paths, demotes PyNaCl from base runtime dependency to optional/tooling scope, and keeps Python scripts as orchestration.

### Policy & Process

- **[ADR-006](ADR-006-forward-only-schema-and-salt8.md): Forward-only schema policy and deprecating `salt4`**
  **Status**: Accepted
  **Summary**: Adopt a forward-only policy. Standardize on `salt8` for XChaCha (24-byte nonce), drop `salt4` and migrations;
  the current milestone schema is the only valid runtime format. Older milestones are archived as references only.

- **[ADR-038](ADR-038-surface-tooling-and-abi3-wheel-strategy.md): Surface tooling boundaries and `abi3` wheel strategy**
  **Status**: Accepted
  **Summary**: Defines which Python components are surface tooling vs protocol-critical, keeps `trackone_core` as the stable native module name, targets `abi3` wheels to reduce the wheel matrix, and adopts two wheel test modes (locked required, pip-resolve gated).

- **[ADR-010](ADR-010-test-suite-refactor-structure-naming.md): Test suite refactor (structure and naming)**
  **Status**: Accepted
  **Summary**: Decompose monolith tests, move fixtures closer to submodules, and adopt clearer naming (drop `_edge_cases`, `_boost`); improves focus and iteration speed.

  - **See also**: [ADR-021](ADR-021-safety-net-ots-pipeline-verification.md)

- **[ADR-013](ADR-013-python-version-support-policy.md): Python Version Support Policy (Last Three Minors)**
  **Status**: Accepted
  **Summary**: Always support the last three CPython minors in CI/tox (currently 3.12, 3.13, 3.14); drop the oldest from defaults when a new minor releases; keep a dedicated env for explicit checks.

- **[ADR-016](ADR-016-changelog-policy-git-cliff.md): Changelog Policy and Automation with git-cliff**
  **Status**: Rejected
  **Summary**: Records and rejects `git-cliff` automation; TrackOne keeps a manually curated `CHANGELOG.md`.

- **[ADR-035](ADR-035-workspace-versioning-and-release-visibility.md): Workspace Versioning and Release Visibility (Umbrella vs Per-Crate)**
  **Status**: Accepted
  **Summary**: Use a single workspace version for tags and releases; keep crate-local changelogs only when crates become independently consumable.

- **[ADR-044](ADR-044-json-schema-modularity-and-authoritative-contract-artifacts.md): JSON Schema modularity and authoritative contract artifacts**
  **Status**: Accepted, Updated 2026-03-12
  **Summary**: Standardize unified schemas on JSON Schema 2020-12, prefer `$defs`/`$ref` reuse over ad hoc templating, and keep checked-in `.schema.json` files as the authoritative machine-readable contract.

- **[ADR-050](ADR-050-fiftieth-adr-milestone-and-record-stewardship.md): Fiftieth ADR milestone and record stewardship**
  **Status**: Accepted
  **Summary**: Marks the fiftieth ADR as a documentation-only milestone and treats the ADR corpus as an active release/review artifact without changing protocol, artifact, dependency, or runtime behavior.

### Verification, Integrity & OTS Pipeline

- **[ADR-007](ADR-007-ots-ci-verification-and-bitcoin-headers.md): OTS verification in CI and Bitcoin headers policy**
  **Status**: Accepted
  **Summary**: Trustless OTS verification in CI using Bitcoin Core in headers-only/pruned mode with cached datadir; parse
  required heights from `.ots` artifacts, wait for headers to catch up, then run `ots verify`. Skip non-blocking when
  headers are unavailable within timeout.

  - **See also**: [ADR-008](ADR-008-m4-completion-ots-workflow.md), [ADR-021](ADR-021-safety-net-ots-pipeline-verification.md), [ADR-022](ADR-022-first-party-stationary-ots-calendar-service.md)

- **[ADR-008](ADR-008-m4-completion-ots-workflow.md): Milestone M#4 Completion and OTS Verification Workflow**
  **Status**: Accepted
  **Summary**: Records the production OTS anchoring/verification of a day artifact, CLI verification modes, and Git LFS policy for `.ots` artifacts with associated metadata.

  - **See also**: [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md), [ADR-007](ADR-007-ots-ci-verification-and-bitcoin-headers.md), [ADR-021](ADR-021-safety-net-ots-pipeline-verification.md)

- **[ADR-009](ADR-009-bandit-remediation.md): Bandit findings remediation and decisions**
  **Status**: Accepted
  **Summary**: Hardens subprocess usage and exception handling around `ots` calls; documents selective `# nosec` justifications and CI policy to reduce false positives while keeping security signal.

- **[ADR-018](ADR-018-cryptographic-randomness-and-nonce-policy.md): Cryptographic randomness and nonce policy**
  **Status**: Accepted
  **Summary**: Standardize OS-backed CSPRNG usage across Python and Rust; prohibit non-CSPRNG APIs in crypto contexts; define AEAD nonce sizes and salt policy (16-32 bytes), provide `crypto_rng.py` helper, and require test fakes for deterministic tests.

  - **See also**: [ADR-001](ADR-001-primitives-x25519-hkdf-xchacha.md), [ADR-002](ADR-002-telemetry-framing-and-replay-policy.md), [ADR-025](ADR-025-adaptive-uplink-cadence-over-lora.md), [ADR-026](ADR-026-ota-firmware-updates-over-lora.md), [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)

- **[ADR-021](ADR-021-safety-net-ots-pipeline-verification.md): Safety net for the OTS pipeline**
  **Status**: Accepted
  **Summary**: Defines SIL-style impact levels for verification/anchoring components, mandates observability/logging for calendar selection, and ties CI/test coverage to OTS proof integrity so misconfigurations fail loudly.

  - **See also**: [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md), [ADR-007](ADR-007-ots-ci-verification-and-bitcoin-headers.md), [ADR-008](ADR-008-m4-completion-ots-workflow.md), [ADR-010](ADR-010-test-suite-refactor-structure-naming.md), [ADR-014](ADR-014-stationary-ots-calendar.md), [ADR-020](ADR-020-stationary-ots-calendar-followup.md), [ADR-022](ADR-022-first-party-stationary-ots-calendar-service.md), [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md), [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)

- **[ADR-023](ADR-023-ots-vs-git-integrity.md): Prefer OTS for integrity and time anchoring over Git plumbing tools**
  **Status**: Accepted
  **Summary**: Establishes OTS as the canonical source of truth for time-anchored integrity verification, avoiding Git-only workflows for audit/compliance contexts.

  - **See also**: [ADR-014](ADR-014-stationary-ots-calendar.md), [ADR-020](ADR-020-stationary-ots-calendar-followup.md), [ADR-021](ADR-021-safety-net-ots-pipeline-verification.md), [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md), [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)

- **[ADR-045](ADR-045-git-signed-evidence-distribution-plane.md): Git-signed evidence distribution plane for release and small authoritative artifacts**
  **Status**: Accepted, Updated 2026-03-13
  **Summary**: Allows Git to carry signed low-rate release/evidence sets and control artifacts as an optional distribution plane, while keeping OTS/TSA/peer proofs as the time/integrity authority, Buildx provenance as the OCI build authority, and detached verifier semantics independent from Git metadata.

  - **See also**: [ADR-023](ADR-023-ots-vs-git-integrity.md), [ADR-035](ADR-035-workspace-versioning-and-release-visibility.md), [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md), [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md), [ADR-043](ADR-043-phased-bundle-manifest-maturity-for-id.md)

- **[ADR-046](ADR-046-sealed-trust-root-boundary-and-deferring-trackone-seal.md): Sealed trust-root boundary and deferring a dedicated `trackone-seal` crate**
  **Status**: Accepted
  **Summary**: Defines the sealed trust-root boundary around mutable input state, verifier-visible binding, and publication gating; keeps deterministic seal primitives in `trackone-ledger`, keeps workflow policy in Python, and explicitly defers a separate `trackone-seal` crate until sealed-state artifacts become a stable reusable domain.

  - **See also**: [ADR-017](ADR-017-rust-core-and-pyo3-integration.md), [ADR-037](ADR-037-signature-roles-and-verification-boundaries.md), [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md), [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md), [ADR-043](ADR-043-phased-bundle-manifest-maturity-for-id.md), [ADR-045](ADR-045-git-signed-evidence-distribution-plane.md)

- **[ADR-047](ADR-047-trackone-evidence-plane-within-device-lifecycle.md): TrackOne as the evidence plane within a broader device lifecycle system**
  **Status**: Accepted
  **Summary**: Defines TrackOne's scope as the evidence plane: it owns gateway validation, anti-replay, canonical record admission, deterministic batching, artifact hashing/anchoring, and verifier-facing disclosure. It explicitly does not own manufacturer identity, network onboarding, fleet inventory, operational PKI, or firmware orchestration; those belong to an adjacent lifecycle/control plane. The handoff boundary is a known pod identity, successful domain admission, and accepted telemetry under the active gateway transport contract.

  - **See also**: [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md), [ADR-032](ADR-032-informational-rfc-verifiable-telemetry-ledger.md), [ADR-037](ADR-037-signature-roles-and-verification-boundaries.md), [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md), [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md), [ADR-046](ADR-046-sealed-trust-root-boundary-and-deferring-trackone-seal.md)

- **[ADR-048](ADR-048-separate-scitt-publication-profile.md): Separate SCITT publication profile from the base telemetry-ledger draft**
  **Status**: Accepted
  **Summary**: Keeps SCITT publication semantics out of the base telemetry-ledger draft. The base draft remains the source of truth for authoritative artifacts, commitment semantics, disclosure classes, and verifier scope; any later SCITT publication behavior should live in a separate companion profile and must not replace local TrackOne verification.

  - **See also**: [ADR-032](ADR-032-informational-rfc-verifiable-telemetry-ledger.md), [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md), [ADR-043](ADR-043-phased-bundle-manifest-maturity-for-id.md), [ADR-045](ADR-045-git-signed-evidence-distribution-plane.md), [ADR-047](ADR-047-trackone-evidence-plane-within-device-lifecycle.md)

### Stationary Calendar & Trust Chain

- **[ADR-014](ADR-014-stationary-ots-calendar.md): Stationary OpenTimestamps Calendar for Deterministic Anchoring**
  **Status**: Accepted
  **Summary**: Introduce a self-hosted OTS calendar for CI/local determinism with configurable fallback to public pools; outlines deployment and verification flow.

  - **See also**: [ADR-007](ADR-007-ots-ci-verification-and-bitcoin-headers.md), [ADR-020](ADR-020-stationary-ots-calendar-followup.md), [ADR-021](ADR-021-safety-net-ots-pipeline-verification.md), [ADR-022](ADR-022-first-party-stationary-ots-calendar-service.md), [ADR-023](ADR-023-ots-vs-git-integrity.md)

- **[ADR-015](ADR-015-parallel-anchoring-ots-rfc3161-tsa.md): Parallel Anchoring with OpenTimestamps and RFC 3161 TSA**
  **Status**: Accepted
  **Summary**: For each daily Merkle root, produce and store both an OTS proof and an RFC 3161 TSA response over the same digest; verify both in CI/CLI and treat dual success as strongest assurance while remaining backward-compatible with OTS-only.

  - **See also**: [ADR-022](ADR-022-first-party-stationary-ots-calendar-service.md)

- **[ADR-019](ADR-019-rust-gateway-chain-of-trust.md): Rust gateway chain of trust for the stationary calendar**
  **Status**: Accepted
  **Summary**: Treat the stationary calendar as a named component in the TrackOne chain of trust; move gateway logic into Rust, run OTS anchoring through the calendar + public pools, and document provable paths from pods to Bitcoin headers.

  - **See also**: [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md), [ADR-025](ADR-025-adaptive-uplink-cadence-over-lora.md), [ADR-026](ADR-026-ota-firmware-updates-over-lora.md)

- **[ADR-020](ADR-020-stationary-ots-calendar-followup.md): Stationary calendar follow-up**
  **Status**: Accepted
  **Summary**: Clarifies that the current `deploy/docker/calendar` container is a tooling sidecar, not a real HTTP calendar. `tox -e ots-cal` may exercise real-OTS client paths, but it is not protocol conformance for a first-party calendar.

  - **See also**: [ADR-014](ADR-014-stationary-ots-calendar.md), [ADR-021](ADR-021-safety-net-ots-pipeline-verification.md), [ADR-022](ADR-022-first-party-stationary-ots-calendar-service.md)

- **[ADR-022](ADR-022-first-party-stationary-ots-calendar-service.md): First-party stationary OTS calendar service in CI**
  **Status**: Proposed
  **Summary**: Proposes a minimal first-party HTTP calendar for CI/dev (hosted via `deploy/docker/calendar` and `tox -e ots-cal`), keeps production on public calendars, and outlines phased migration, config, and documentation requirements.

  - **See also**: [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md), [ADR-007](ADR-007-ots-ci-verification-and-bitcoin-headers.md), [ADR-008](ADR-008-m4-completion-ots-workflow.md), [ADR-014](ADR-014-stationary-ots-calendar.md), [ADR-020](ADR-020-stationary-ots-calendar-followup.md), [ADR-021](ADR-021-safety-net-ots-pipeline-verification.md), [ADR-015](ADR-015-parallel-anchoring-ots-rfc3161-tsa.md), [ADR-023](ADR-023-ots-vs-git-integrity.md), [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md), [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)

### Anti-Replay & Ledger Semantics

- **[ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md): Anti-replay and OTS-backed ledger semantics**
  **Status**: Accepted
  **Summary**: Formalizes anti-replay for the immutable ledger: pod monotonic counters, gateway verification, and OTS-backed facts as the canonical ledger state.
  - **See also**: [ADR-002](ADR-002-telemetry-framing-and-replay-policy.md), [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md), [ADR-006](ADR-006-forward-only-schema-and-salt8.md), [ADR-019](ADR-019-rust-gateway-chain-of-trust.md), [ADR-021](ADR-021-safety-net-ots-pipeline-verification.md), [ADR-023](ADR-023-ots-vs-git-integrity.md), [ADR-025](ADR-025-adaptive-uplink-cadence-over-lora.md), [ADR-026](ADR-026-ota-firmware-updates-over-lora.md), [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)

### LoRa Control Plane (Adaptive & Updates)

- **[ADR-025](ADR-025-adaptive-uplink-cadence-over-lora.md): Adaptive Uplink Cadence via Authenticated LoRa Downlink Policy**
  **Status**: Accepted
  **Summary**: Gateway delivers canonical cadence policies over authenticated LoRa downlink; pods confirm applied epochs via authenticated uplink, and the ledger distinguishes issued from applied policy facts.

  - **See also**: [ADR-001](ADR-001-primitives-x25519-hkdf-xchacha.md), [ADR-002](ADR-002-telemetry-framing-and-replay-policy.md), [ADR-018](ADR-018-cryptographic-randomness-and-nonce-policy.md), [ADR-019](ADR-019-rust-gateway-chain-of-trust.md), [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md), [ADR-026](ADR-026-ota-firmware-updates-over-lora.md), [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)

- **[ADR-026](ADR-026-ota-firmware-updates-over-lora.md): Operator-Driven OTA Firmware Distribution over LoRa (NTN-Aware, Signed, Chunked, Dual-Slot)**
  **Status**: Proposed
  **Summary**: Defines CBOR-first, signed firmware campaigns over the LoRa control plane with dual-slot rollback semantics, explicit pod confirmations, and an NTN transport profile that preserves the same trust model.

  - **See also**: [ADR-001](ADR-001-primitives-x25519-hkdf-xchacha.md), [ADR-002](ADR-002-telemetry-framing-and-replay-policy.md), [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md), [ADR-018](ADR-018-cryptographic-randomness-and-nonce-policy.md), [ADR-019](ADR-019-rust-gateway-chain-of-trust.md), [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md), [ADR-025](ADR-025-adaptive-uplink-cadence-over-lora.md), [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)

### Firmware Runtime & Recovery

- **[ADR-042](ADR-042-hardware-watchdog-and-liveness-registry.md): Hardware Watchdog & Liveness-Registry Policy**
  **Status**: Accepted
  **Summary**: Adds a pod-side hardware watchdog policy with quorum-based feeding, normalized reset-cause reporting, and deferred health-fact wiring so unattended pods recover from hangs without immediate cross-crate schema churn.

### Environmental Evidence & Projections

- **[ADR-027](ADR-027-sensorthings-shtc3-representation.md): Representation of SHTC3-Class Sensors and Environmental Readings**
  **Status**: Superseded by [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)
  **Summary**: Historical SHTC3-class capability and reading-shape proposal retained for link stability. ADR-030 now governs the canonical environmental evidence model.

  - **See also**: [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)

- **[ADR-028](ADR-028-sensorthings-projection-mapping.md): Mapping TrackOne Canonical Facts to OGC SensorThings API**
  **Status**: Superseded by [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)
  **Summary**: Historical SensorThings mapping proposal retained for link stability. ADR-030 now governs SensorThings as a deterministic read-only projection, not a commitment authority.

  - **See also**: [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)

- **[ADR-029](ADR-029-env-daily-summaries-and-usecases.md): Environmental Sensing Use-Cases and Daily Summary Metrics**
  **Status**: Superseded by [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)
  **Summary**: Historical environmental analytics/use-case proposal retained for link stability. ADR-030 now governs committed summary encoding; richer daily metrics remain derived analytics.

  - **See also**: [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)

- **[ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md): Environmental Evidence Model, Projections, and Duty-Cycled Anchoring**
  **Status**: Accepted
  **Summary**: Consolidates ADR-027, ADR-028, and ADR-029. Defines the active environmental `EnvFact` wire model, out-of-band sensor metadata posture, committed raw/summary encoding, read-only SensorThings projection boundary, and duty-cycled `day.cbor` anchoring.

  - **See also**: [ADR-001](ADR-001-primitives-x25519-hkdf-xchacha.md), [ADR-002](ADR-002-telemetry-framing-and-replay-policy.md), [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md), [ADR-006](ADR-006-forward-only-schema-and-salt8.md), [ADR-014](ADR-014-stationary-ots-calendar.md), [ADR-018](ADR-018-cryptographic-randomness-and-nonce-policy.md), [ADR-020](ADR-020-stationary-ots-calendar-followup.md), [ADR-021](ADR-021-safety-net-ots-pipeline-verification.md), [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md), [ADR-025](ADR-025-adaptive-uplink-cadence-over-lora.md), [ADR-034](ADR-034-serialization-boundaries-transport-vs-commitments.md), [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md), [ADR-047](ADR-047-trackone-evidence-plane-within-device-lifecycle.md)

### Data Storage & Analytics

- **[ADR-011](ADR-011-benchmarking-strategy.md): Benchmarking Strategy for TrackOne**
  **Status**: Accepted
  **Summary**: Introduces pytest-benchmark based micro/mid-level benchmarks for crypto and gateway primitives, optional CI artifacts, and conventions for running and comparing baselines.

- **[ADR-012](ADR-012-parquet-export-and-columnar-storage.md): Parquet Export for Telemetry Facts (0.2.0+)**
  **Status**: Proposed
  **Summary**: Add optional Parquet exporter (columnar, partitioned by day/site) derived from canonical facts; commitment source-of-truth follows the active commitment-profile ADRs, while Parquet remains derivative for analytics.

- **[ADR-031](ADR-031-key-analysis-of-spatialite.md): Key Analysis of SpatiaLite for Geospatial Storage and Query**
  **Status**: Proposed
  **Summary**: Introduces SpatiaLite as the geospatial extension for SQLite to enable efficient storage, indexing, and querying of spatial telemetry data, supporting advanced geospatial analytics and interoperability with OGC standards.

### Validation & Standards

- **[ADR-032](ADR-032-informational-rfc-verifiable-telemetry-ledger.md): Proposing an Informational RFC for Verifiable Telemetry Ledgers**
  **Status**: Accepted
  **Summary**: Draft an informational RFC to document TrackOne’s ledger model, dual anchoring, and canonical schemas for broader review and collaboration.

- **[ADR-033](ADR-033-virtual-fleet-verifiable-telemetry.md): Virtual Fleet for Verifiable Telemetry and End-to-End Validation**
  **Status**: Proposed
  **Summary**: Introduce a deterministic virtual fleet and scenario runner to validate ingestion → ledger → anchoring behavior without physical hardware.

- **[ADR-040](ADR-040-commitment-test-vectors-and-conformance-gates.md): Commitment test vectors and conformance gates**
  **Status**: Proposed
  **Summary**: Requires machine-readable canonical commitment vectors and mandatory Rust/Python parity checks in CI for commitment bytes and roots.

- **[ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md): Verification disclosure bundles and privacy tiers**
  **Status**: Accepted, Updated 2026-03-13
  **Summary**: Defines Tier A/B/C disclosure classes, minimum verification bundle requirements, and mandatory labeling of recomputation capability vs anchor-only evidence, with the manifest contract now explicit on the main pipeline/verifier path.

- **[ADR-043](ADR-043-phased-bundle-manifest-maturity-for-id.md): Phased bundle-manifest maturity for the I-D**
  **Status**: Accepted, Updated 2026-03-13
  **Summary**: Keeps the stronger I-D structure now, records that Phase B manifest emission/validation is implemented on the main pipeline/verifier path, and preserves a path to stricter universal manifest enforcement later.

### Future Roadmap

- **[ADR-017](ADR-017-rust-core-and-pyo3-integration.md): Rust Core and PyO3 Integration Strategy**
  **Status**: Accepted
  **Summary**: Introduce a Rust core crate with PyO3 bindings for canonicalization, hashing, Merkle, and eventually AEAD/signatures; ship wheels with `maturin`, keep Python API stable with fallbacks, and roll out in phases post-0.1.0.

- **[ADR-036](ADR-036-post-quantum-kem.md): Post-Quantum Hybrid Provisioning (X25519 + ML-KEM/Kyber)**
  **Status**: Proposed
  **Summary**: Introduce optional hybrid provisioning that combines X25519 and ML-KEM shared secrets while keeping telemetry framing and nonce rules unchanged.

- **[ADR-037](ADR-037-signature-roles-and-verification-boundaries.md): Signature Roles and Verification Boundaries (Who Signs What)**
  **Status**: Proposed
  **Summary**: Define canonical signature responsibilities and verification order for provisioning, policies, ledger headers, and optional peer attestations.

## Cross-Reference Matrix

**Cryptography & Framing**: [ADR-001](ADR-001-primitives-x25519-hkdf-xchacha.md) \<- [ADR-002](ADR-002-telemetry-framing-and-replay-policy.md), [ADR-005](ADR-005-pynacl-migration.md), [ADR-018](ADR-018-cryptographic-randomness-and-nonce-policy.md), [ADR-034](ADR-034-serialization-boundaries-transport-vs-commitments.md), [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md), [ADR-049](ADR-049-native-evidence-plane-crypto-boundary-and-pynacl-demotion.md)
**OTS Pipeline**: [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md) \<- [ADR-007](ADR-007-ots-ci-verification-and-bitcoin-headers.md), [ADR-008](ADR-008-m4-completion-ots-workflow.md), [ADR-021](ADR-021-safety-net-ots-pipeline-verification.md), [ADR-023](ADR-023-ots-vs-git-integrity.md)
**Calendar & Trust**: [ADR-014](ADR-014-stationary-ots-calendar.md) \<- [ADR-020](ADR-020-stationary-ots-calendar-followup.md), [ADR-022](ADR-022-first-party-stationary-ots-calendar-service.md); [ADR-019](ADR-019-rust-gateway-chain-of-trust.md) \<- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md), [ADR-025](ADR-025-adaptive-uplink-cadence-over-lora.md), [ADR-026](ADR-026-ota-firmware-updates-over-lora.md)
**Ledger & Anti-Replay**: [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md) \<- [ADR-002](ADR-002-telemetry-framing-and-replay-policy.md), [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md), [ADR-006](ADR-006-forward-only-schema-and-salt8.md), [ADR-025](ADR-025-adaptive-uplink-cadence-over-lora.md), [ADR-026](ADR-026-ota-firmware-updates-over-lora.md), [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md), [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md)
**Firmware Runtime & Recovery**: [ADR-042](ADR-042-hardware-watchdog-and-liveness-registry.md) \<- [ADR-021](ADR-021-safety-net-ots-pipeline-verification.md), [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md)
**Conformance & Interop**: [ADR-032](ADR-032-informational-rfc-verifiable-telemetry-ledger.md) \<- [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md), [ADR-040](ADR-040-commitment-test-vectors-and-conformance-gates.md), [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md), [ADR-043](ADR-043-phased-bundle-manifest-maturity-for-id.md)
**Environmental Evidence & Projections**: [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md) \<- [ADR-027](ADR-027-sensorthings-shtc3-representation.md), [ADR-028](ADR-028-sensorthings-projection-mapping.md), [ADR-029](ADR-029-env-daily-summaries-and-usecases.md)
**Future Roadmap**: [ADR-017](ADR-017-rust-core-and-pyo3-integration.md), [ADR-036](ADR-036-post-quantum-kem.md), [ADR-037](ADR-037-signature-roles-and-verification-boundaries.md)
**System Scope & Boundary**: [ADR-047](ADR-047-trackone-evidence-plane-within-device-lifecycle.md) \<- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md), [ADR-032](ADR-032-informational-rfc-verifiable-telemetry-ledger.md), [ADR-037](ADR-037-signature-roles-and-verification-boundaries.md), [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md), [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md), [ADR-046](ADR-046-sealed-trust-root-boundary-and-deferring-trackone-seal.md)
**Decision Record Stewardship**: [ADR-050](ADR-050-fiftieth-adr-milestone-and-record-stewardship.md) \<- [ADR-016](ADR-016-changelog-policy-git-cliff.md), [ADR-035](ADR-035-workspace-versioning-and-release-visibility.md), [ADR-038](ADR-038-surface-tooling-and-abi3-wheel-strategy.md)

## Usage

- **ADRs guide implementation**: Do not change code that contradicts an "Accepted" ADR without opening a new ADR
  (Status: Proposed).
- **Cross-reference in code**: Use ADR IDs in docstrings and comments (e.g., "implements ADR-002 nonce policy").
- **Review process**: Proposed → Discussed → Accepted → Implemented

## Template (for new ADRs)

```markdown
# ADR-XYZ: Title

**Status**: Proposed | Accepted | Superseded | Rejected
**Date**: YYYY-MM-DD
**Updated**: YYYY-MM-DD (optional)
**Owners**: Team/Owner (optional)

## Related ADRs (optional)

- ADR-ABC: Brief context (e.g., "foundational crypto primitives")
- ADR-DEF: Brief context

## Context

- Problem statement and constraints
- Why this decision is needed

## Decision

- The chosen approach and scope
- Key design elements

## Consequences

### Positive

- Benefits and advantages

### Negative

- Trade-offs and limitations
- Operational impact

## Alternatives Considered

- Brief notes on rejected options
- Why they were not chosen

## Testing & Migration

- How to validate the implementation
- Migration path if changing existing behavior
```

## Contributing

When proposing a new ADR:

1. Copy the template above
1. Number sequentially (ADR-038, etc.)
1. Mark as "Proposed" until discussed and accepted
1. Use `## Context`, `## Decision`, `## Consequences` headings and add `## Related ADRs` when there are dependencies
1. Update this README index when accepted (add entry + cross-references)
