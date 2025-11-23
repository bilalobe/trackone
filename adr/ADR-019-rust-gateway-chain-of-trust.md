## ADR‑019: Rust Gateway and End‑to‑End Chain of Trust for Stationary OTS Calendar

**Status**: Accepted
This ADR marks the transition from research prototype to an industrial‑grade, auditable platform.

**Relates to**: ADR‑014 (Stationary OTS Calendar), ADR‑015 (Parallel Anchoring), ADR‑007/008 (OTS verification)

### 1. Context

ADR‑014 proposes a stationary OpenTimestamps calendar to make anchoring more deterministic in CI and controlled environments.

For the "Rust era", we want to:

- Keep the original purpose: *télémétrie vérifiable à très faible consommation*.
- Strengthen the chain of trust from hardware/firmware up to anchored ledgers.
- Move critical gateway logic to Rust while preserving existing JSON/CBOR contracts.

Key drivers:

- Hardware/firmware work (pods, secure provisioning) needs a clear trust root that can be audited end‑to‑end.
- The current Python gateway is a reference; for long‑term robustness we want a Rust implementation for Merkle batching, anchoring, and verification.
- The stationary calendar becomes part of a broader, verifiable pipeline rather than just a CI optimization.

### 2. Decision

We will:

1. **Introduce a Rust gateway core** responsible for:

   - Fact ingestion, validation, and normalization.
   - Deterministic Merkle batching and daily `day_root` calculation.
   - OTS anchoring via the stationary calendar (preferred) with public calendars as fallback.
   - TSA / peer anchoring integrations as *optional* adjuncts, not as the source of truth.

1. **Define a hardware‑to‑ledger chain of trust**:

- **Provisioning (Birth Certificate)**:
  At manufacturing/provisioning time, a *Provisioning Record* (the pod's Birth Certificate) is created as a JSON/CBOR document containing:

  - `device_id`
  - Long‑term public key(s) (e.g. X25519)
  - `firmware_version`, `firmware_hash`
  - `hardware_rev` and allowed telemetry/profile
  - `created_at` (ISO8601)
    The Provisioning Record is signed by an offline Manufacturer Key and stored in the gateway's DB or registry. The gateway holds only the corresponding verification key.

  Operational linkage:

  - On each incoming AEAD‑verified frame (after anti‑replay checks), the Gateway resolves `device_id` → Provisioning Record and injects `firmware_version` and `firmware_hash` into the canonical telemetry Fact before Merkle batching. This binds runtime telemetry to build‑time artifacts and enables filtering (e.g. "exclude all data from v0.9‑beta").

- **Firmware integrity**:

  - Treat firmware image hashes and release manifests as anchorable facts.
  - Publish firmware manifests and optionally anchor their Merkle root so auditors can correlate `firmware_hash` with anchored releases.

- **Telemetry facts**:

  - Keep AEAD‑protected frames, anti‑replay, and low on‑air footprint.
  - Represent decrypted / verified telemetry as typed facts (CBOR/JSON) with explicit origin metadata (`device_id`, `firmware_hash`, `gateway_id`).

- **Ledger and anchoring**:

  - The Rust gateway produces Merkle trees and daily `day_root` values over facts.
  - `day_root` is anchored via:
    - Stationary OTS calendar (primary, deterministic).
    - Public OTS calendars (fallback).
    - Optional TSA / peer signatures (defense in depth).

3. **Treat the stationary OTS calendar as an internal, auditable service in the chain of trust**:

   - Document its deployment (container image, volume, configuration) as a *named component* in the architecture.
   - Require that all CI and "official" daily ledgers use a configured set of calendars, with the stationary calendar first.
   - Expose enough metadata (e.g. calendar URLs, proof acquisition time, commit hash of Rust gateway) in the day record or adjacent manifest so auditors can reconstruct the path from facts to Bitcoin headers.

1. **Preserve and version JSON/CBOR contracts**:

   - Keep existing `day_record`, `block_header`, and `fact` formats stable or evolve them via explicit schemas (`*.schema.json`).
   - Provide a minimal compatibility layer so Python tools can still verify Rust‑produced days (and vice versa), at least during the transition.

### 3. Scope

In scope (Rust era, ADR‑014 follow‑up):

- A Rust service or library that:

  - Reads verified telemetry facts (from LoRa gateway or a queue).
  - Writes canonical daily records and Merkle proofs.
  - Invokes `ots` (or a Rust OTS binding) against a configured calendar set.
  - Emits verification metadata (heights, calendar endpoints, proof status).

- A formal definition of the **chain of trust** including:

  - Root of trust at provisioning (keys, firmware measurement).
  - Proof that telemetry facts originate from a provisioned pod running approved firmware.
  - Proof that `day_root` is a deterministic function of facts.
  - Anchoring via the stationary calendar and, eventually, Bitcoin headers.

- CI / reproducibility:

  - CI uses the Rust gateway for Merkle + anchoring when validating test vectors and demo runs.
  - The stationary calendar is used in CI and optionally in controlled deployments.

- The stationary calendar is a *buffer*, not an island:

  - Policy: the stationary calendar MUST commit its internal day_root(s) to the public Bitcoin blockchain at a configured cadence (e.g. once every 24 hours).
  - Runtime check: the Rust gateway (or auxiliary verifier) periodically asks the stationary calendar for the Bitcoin block header(s) that corresponds to previously reported commitments (for example, "provide the Bitcoin header you used to anchor yesterday's day_root"). If the calendar cannot produce a matching Bitcoin header / OTS proof within a configured grace period, the gateway raises an _Integrity Alarm_ and marks affected day_roots as suspect in metadata.
  - Monitoring: expose calendar commit status, proof acquisition time, and any missing commitments so operators can act.

Out of scope (for this ADR, but possible future work):

- PQC for pod or gateway crypto (covered by separate roadmap items).
- Deep changes to the pod power model or LoRa framing.
- Hardware security modules (HSM/TPM) on gateways as the primary trust root (can be layered on later).

### 4. Technical Plan

High‑level steps:

1. **Rust gateway core**

   - Crate topology:
     - `crates/barnacle-core`:
       - Shared data types and serialization for ProvisioningRecord / Birth Certificate, Telemetry Fact types (including `firmware_version`, `firmware_hash`, `device_id`), Merkle leaf layout, and canonical hashing.
       - Prefer `no_std` compatibility where practical so serialization and canonical layouts can be reused by firmware tooling or embedded helpers.
     - `crates/barnacle-gateway`:
       - Gateway service/CLI: LoRa frame ingestion, AEAD + anti‑replay, provisioning record lookup, Fact construction, Merkle batching, OTS/calendar integration, verification reports.
   - Provide parity tests and JSON/CBOR schemas (`*.schema.json`) so Python tooling can interoperate during transition.

1. **OTS integration and stationary calendar**

   - Make calendar endpoints configurable (env, config file), mirroring ADR‑014:
     - `OTS_CALENDARS=https://calendar.local:8468,https://a.pool.opentimestamps.org:8443`.
   - Wrap `ots` operations (an external binary or a library) with:
     - Explicit timeouts.
     - Clear status: \`pending\`, \`complete\`, \`failed\`.
   - Ensure:
     - CI runs with the stationary calendar as first choice.
     - The Rust tool emits verification reports compatible with current `verify_cli` expectations.
   - Query the stationary calendar for corresponding Bitcoin headers for previously issued commitments and raise alerts on missing proofs.

1. **Hardware / firmware linkage**

   - Define a `provisioning_record` schema (CBOR/JSON) and anchor at least:
     - Device ID, public keys, firmware hash, issuance time.
   - For each pod:
     - Ensure the gateway stores provisioning records and can map incoming frames to an anchored provisioning record.
   - For firmware releases:
     - Publish a manifest (firmware hash, version, signing key) and optionally anchor its Merkle root via OTS as we anchor Provisioning Records (Birth Certificates) are signed by an offline Manufacturer Key. The Gateway possesses only the public verification key. A compromised Gateway cannot mint new fake devices; it can only accept or drop data from already‑provisioned devices.
   - On each frame, after AEAD verification and anti‑replay checks, the Gateway resolves device_id → Provisioning Record and attaches firmware_version and firmware_hash into the canonical Fact before Merkle batching.

1. **Chain‑of‑trust documentation and tooling**

   - Document, in prose and diagrams:
     - How a fact from a pod, at time (T), under firmware (F), ends up in a day record anchored by OTS via the stationary calendar.
   - Provide a Rust (or Python) verification tool that:
     - Starting from a fact ID or leaf hash, walks:
       - Fact -> Merkle path -> `day_root` -> OTS proof -> Bitcoin header(s).
       - Optionally: pod provisioning record and firmware manifest.

### 5. Alternatives Considered

- **Stay Python‑only and treat the stationary calendar as a pure CI optimization**:
  Simpler in the short term, but misses the opportunity to consolidate core logic in Rust and to make the chain of trust more explicit.

- **Tie trust directly to TSA or PKI, de‑emphasizing OTS**:
  Would complicate the story around independent timestamping and Bitcoin headers, and increase reliance on central authorities.

- **Hardware security modules (HSM/TPM) on gateways as the primary trust root**:
  Useful eventually, but adds operational complexity; can be layered on later once the Rust gateway and stationary calendar are stable.

### 6. Consequences

Positive:

- Stronger, auditable chain of trust from hardware/firmware through gateway and stationary calendar to public Bitcoin headers.
- More deterministic, reproducible anchoring in CI and controlled deployments.
- Rust implementation improves robustness and makes concurrency and resource management explicit.

Negative / costs:

- Added complexity: two implementations (Python + Rust) during transition.
- Operational overhead to run and monitor the stationary calendar and Rust gateway.
- Need for migration and compatibility tests to ensure schemas and semantics stay aligned.

### 7. Security and Operations

- Treat the stationary calendar and Rust gateway as untrusted from the pod’s perspective; do not weaken pod AEAD or anti‑replay guarantees.
- Run the calendar and Rust gateway with least privilege, resource limits, and monitoring.
- Keep clear separation between:
  - **Evidence** (facts, Merkle trees, OTS proofs),
  - **Policy** (who is allowed to provision devices, sign firmware, operate calendars).
- Provisioning Records are signed by an offline Manufacturer Key. The Gateway possesses only the public verification key; a compromised Gateway cannot mint new valid provisioning records.

### Small note on `requests` (Python dependency)

- Keep `requests` confined to legacy Python tooling or migration utilities (e.g. `tools/gateway_py` dependency group). For the Rust runtime path prefer native HTTP clients / bindings; Python verification scripts may continue to use `requests` without making it a core runtime dependency for the production gateway stack.
