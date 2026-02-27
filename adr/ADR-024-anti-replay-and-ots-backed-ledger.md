# ADR-024: Anti-replay and OTS-backed ledger semantics

**Status**: Accepted
**Date**: 2026-02-23

## Related ADRs

- [ADR-002](ADR-002-telemetry-framing-and-replay-policy.md): Replay window and device table (pod-side anti-replay)
- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md): Merkle canonicalization and OTS anchoring (ledger structure)
- [ADR-006](ADR-006-forward-only-schema-and-salt8.md): Forward-only schema and salt8 (schema discipline)
- [ADR-019](ADR-019-rust-gateway-chain-of-trust.md): Gateway chain of trust (operational chain)
- [ADR-021](ADR-021-safety-net-ots-pipeline-verification.md): Safety-net OTS pipeline verification (verification invariants)
- [ADR-023](ADR-023-ots-vs-git-integrity.md): Prefer OTS for integrity (trust hierarchy)
- [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md): EnvFact schema and duty-cycled day.cbor anchoring (schema instantiation)
- [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md): Disclosure tiers and verification-bundle semantics

## Context

TrackOne ingests telemetry frames from pods. Each frame is identified at least by a device identifier `dev_id` and a frame counter `fc`, plus payload and metadata.

On the gateway side:

- `frame_verifier` applies syntactic and semantic validation, including replay-window based checks.
- Valid frames are turned into canonical facts and written into a `facts/` directory.
- `merkle_batcher` consumes `facts/` and builds per-day Merkle trees and `day.cbor` artifacts, following ADR-003.
- `ots_anchor` (and `verify_cli`) anchor and verify `day.cbor` artifacts using OpenTimestamps (OTS), and track proofs in sidecar metadata.

ADR-002 specifies the replay window and device table model at the gateway. ADR-003 specifies Merkle canonicalization and OTS anchoring for day records.

What has not been written down explicitly is how **anti-replay semantics** interact with the **ledger/OTS** view:

- Which frames "count" for the on-chain / OTS-backed ledger.
- How `(dev_id, fc)` is treated as an accounting unit.
- What the presence or absence of a frame in a day blob implies about replays and window policy.

This ADR closes that gap.

## Decision

### 1. Invariant: `(dev_id, fc)` is consumed at most once by the ledger

For each device identifier `dev_id` and frame counter `fc`:

- The ingestion pipeline (pod → gateway → `frame_verifier` → `facts/` → `merkle_batcher`) **may accept at most one frame** with that `(dev_id, fc)` pair into the ledger.
- Subsequent occurrences of the same `(dev_id, fc)` are classified as *replays* or *duplicates* by the replay logic and **must not** produce additional facts that reach the Merkle batcher.

We treat `(dev_id, fc)` as the minimal **unit of account** for frames in the ledger. Payload and metadata can differ across retransmissions, but the pair `(dev_id, fc)` can only be debited once into the canonical set of facts that form a day’s Merkle tree.

### 2. What gets anchored

For a given calendar day `D`, the gateway constructs a canonical `day.cbor` (per ADR-003) and anchors it with OTS. The anchored object logically represents:

- A finite multiset of facts `F_D` derived from frames that passed gateway validation **including replay window checks**.
- Each fact `f in F_D` carries (directly or by derivation) a `(dev_id, fc)` pair.

The **anchored set** is therefore:

- The set of `(dev_id, fc)` pairs for which there exists an accepted fact in `F_D`, and
- The associated fact content at the time of batching.

By design:

- Only facts for frames that passed replay checks (`frame_verifier` using `ReplayWindow`) are included in `F_D`.
- Frames flagged as *replayed* (duplicate `(dev_id, fc)`) or *out-of-window* are *not* part of `F_D` and consequently *not* in the Merkle set for day `D`.

The Merkle root anchored with OTS is computed over `F_D` only.

### 3. Replay / out-of-window behavior

The replay policy (see ADR-002 and `ReplayWindow` implementation) is summarized as:

- Per `dev_id`, the gateway maintains highest-seen counter and a sliding window of recently accepted `fc` values.
- A new frame `(dev_id, fc)` is **accepted** if:
  - It has valid structure and signature (per existing validation), and
  - Its `fc` is within the configured replay window relative to the device’s state, and
  - `fc` is not already present in the device’s replay window set.
- A new frame `(dev_id, fc)` is **rejected** as a replay / out-of-window if:
  - `fc` has already been accepted for that `dev_id` (duplicate), or
  - `fc` is too far behind or too far ahead of the current window according to ADR-002 policy, or
  - Device state has been reset and `fc` is inconsistent with provisioning policy.

For the ledger and OTS:

- **Accepted frames** become facts in `facts/` and are eligible to be included in the Merkle tree and `day.cbor`.
- **Rejected frames** (duplicate or out-of-window) SHOULD be written to structured rejection evidence logs, metrics, or operator dashboards, and:
  - They **must not** produce canonical facts that `merkle_batcher` consumes for ledger construction.
  - They are never part of the Merkle set used for anchoring a day.

Current reference implementation:

- `scripts/gateway/frame_verifier.py` writes structured rejection evidence to
  `audit/rejections-<day>.ndjson` beside the `facts/` directory.
- These records are append-only per day and remain outside the Merkle/OTS path.

Wrap-around of `fc` (e.g. 32-bit counter crossing `2^32-1 → 0`) is currently treated as an **out-of-policy event** unless and until an explicit wrap-around policy is implemented:

- If a device wraps its frame counter, existing `ReplayWindow` behavior will typically classify the wrapped value as too far behind or otherwise out-of-window.

- Such frames are rejected from the ledger; device re-provisioning / epoch changes should be used to handle long-lived deployments.

- Practical justification: with a 32-bit counter transmitting at a plausible Barnacle cadence the expected time to wrap is astronomically large. Example calculation:

  - 6 frames per hour ~= 144 frames per day ~= 52,560 frames per year
  - 2^32 ~= 4.29 × 10^9 frames → 4.29e9 / 52,560 ~= 81,600 years to wrap

  Verdict: For Barnacle-style pods (minutes-scale frame cadence, modest lifetime), treating wrap-around as a provisioning/firmware error is acceptable and simpler than adding modulo semantics. This ADR can be revisited if deployment constraints change.

If we later introduce explicit modulo semantics for frame counters, ADR-024 must be updated accordingly and new tests added.

### 4. Meaning of an OTS timestamp

Given an OTS proof over the hash `H = SHA256(day.cbor_D)` for day `D`, and assuming correct operation of the gateway and Merkle batcher per ADR-003 and this ADR:

> The OTS proof asserts that, at or before the attested time, the gateway committed to exactly the set of *accepted, non-replayed* facts F_D for day D, as serialized into day.cbor_D.

This means:

- The OTS anchor is a statement about **accepted state** (post-replay filtering), not about all raw ingress traffic.
- The absence of a frame `(dev_id, fc)` from `F_D` / `day.cbor_D` has the following interpretations:
  - The frame was never observed, **or**
  - The frame was observed but rejected as invalid, replay, or out-of-window, and is therefore outside the anchored ledger; it may exist only in separate audit logs.

It does **not** mean that Datagram or radio delivery was perfect; only that the gateway’s replay and validation policy filtered what went into `day.cbor`.

### 5. Anchored-set immutability

Once a `day.cbor_D` has been anchored with a valid OTS proof and we retain that proof:

- Any mutation of `day.cbor_D` (including changing, adding, or removing facts or altering their serialization) changes its SHA-256 hash.

- The existing OTS proof can no longer be claimed to attest to the mutated blob.

- In particular, attempts to retrospectively:

  - Insert previously-replayed frames, or
  - Remove legitimately accepted frames,

  will result in a different `SHA256(day.cbor_D)` and thus require a **new** OTS anchor. This property is critical to prevent "ledger surgery" around replayed or out-of-window frames.

### 6. Rejection evidence policy (audit path requirements)

To avoid ambiguity in why a `(dev_id, fc)` did not appear in the anchored set,
the gateway SHOULD emit structured rejection evidence for each rejected frame.

Minimum recommended fields:

- `device_id`
- `fc`
- `reason` (`duplicate`, `out_of_window`, `invalid_frame`, etc.)
- `observed_at_utc`
- optional `frame_hash` or ingress correlation ID

This rejection evidence is part of the audit path (not the ledger path) and
MUST NOT be hashed into day commitments.

Current implementation shape:

- `frame_verifier` emits one NDJSON object per rejected frame with:
  - `device_id`
  - `fc`
  - `reason`
  - `observed_at_utc`
  - `frame_sha256`
  - `source` (`parse`, `replay`, `decrypt`)
- The default audit directory is a sibling `audit/` directory next to `facts/`.

### 7. Omission threat model

If rejection evidence is omitted, an operator can claim "frame never observed"
for data that was actually received and rejected, weakening accountability.
Therefore:

- production deployments SHOULD retain rejection evidence for at least the same
  retention period as day artifacts, or document a stricter operational policy;
- verifiers and reports SHOULD distinguish "not observed" from "observed but rejected"
  when evidence is available.

For deployed TrackOne gateways, the `audit/rejections-<day>.ndjson` retention
policy SHOULD be at least as long as the retention policy for `day.cbor`,
associated OTS proofs, and OTS sidecar metadata.

## Consequences

### Positive

- **Clear semantics:** We have a precise definition of what an OTS timestamp covers and how replay/out-of-window behavior relates to the ledger.
- **Auditability:** Operators can interpret day records and OTS proofs as commitments over post-filtered, non-replayed telemetry, and use separate audit logs for rejected frames.
- **Security model:** Replay protection is a first-class invariant of the ledger; `(dev_id, fc)` cannot be double-spent into the Merkle tree.

### Negative

- **Two data paths:** We must maintain both acceptance (ledger) and audit views of traffic and document their difference.
- **Wrap-around limitation:** Counter wrap-around is presently treated as out-of-policy unless ADR-024 is updated with explicit modulo behavior and corresponding tests.
- **Audit storage overhead:** Structured rejection evidence increases storage and operational complexity.

## The Ledger vs. Audit separation

This is the most important architectural consequence.

- The Ledger (`day.cbor`): Is the "Clean Room." It contains only Truth — canonical, accepted facts that survived validation and replay filtering.

- The Audit Log (syslog / metrics / operator dashboards): Is the "Emergency Room." It contains raw ingress noise: malformed frames, bad signatures, retransmissions, replays, and any evidence of attack or malfunction.

Why this matters: If you ever need to prove a sensor reading in court (or to a heritage committee), you hand them the Ledger. You don't want to explain why Frame #50 appears three times because of a radio retry loop. This ADR legally separates the signal from the noise.

## Testing and CI

To enforce this ADR, we use a combination of unit, integration, and end-to-end tests that exercise both the in-memory replay window and the on-disk ledger/OTS behavior.

1. **Replay-window and Merkle-set invariants**

   Integration tests under `tests/integration/test_replay_merkle_integration.py` drive `frame_verifier` and `merkle_batcher` end-to-end with streams that include duplicates, reordering, and out-of-window frames. They assert that:

   - The set of `(dev_id, fc)` pairs present in the facts actually consumed by `merkle_batcher` is:

     - Duplicate-free per `(dev_id, fc)`, and
     - Consistent with the configured sliding-window invariant (accepting valid out-of-order frames inside the window; rejecting duplicates and frames that are stale or outside the window).

   - On-disk artifacts in a temporary `facts/` and `out/` directory contain only the first accepted occurrence of each `(dev_id, fc)` pair. Replayed frames are visible only via structured audit evidence in `audit/rejections-<day>.ndjson` and do not result in extra fact artifacts/files (canonical CBOR artifacts with optional JSON projections, per ADR-039).

   - Rejected frames produce structured rejection evidence records with reason codes.

   One of these tests is explicitly scoped as a disk-level regression for ADR-024, e.g. `test_pipeline_rejects_duplicates_on_disk`, and is marked with `@pytest.mark.integration` (and, where relevant, `@pytest.mark.benchmark` for performance envelopes).

1. **OTS integration and mutation resistance**

   Where CI profiles permit real or stationary OTS interaction (see ADR-021 and calendar CI jobs), end-to-end tests:

   - Build a small synthetic `day.cbor` from an accepted, duplicate-free set of frames;
   - Stamp it with `ots_anchor` and record the resulting proof and meta JSON;
   - Mutate the set with replays or out-of-window frames and rebuild `day.cbor`;
   - Demonstrate that the mutated `day.cbor` has a different hash and cannot share the same OTS proof. Verification via `verify_cli` fails for the tampered artifact.

   These tests are marked with `@pytest.mark.integration` and additional markers such as `real_ots`, `slow`, or `requires_calendar` so that tox environments and CI workflows can select appropriate subsets (e.g. `tox -e ots-cal`, weekly ratchet jobs).

1. **Traceability into requirements**

   The requirements traceability section of the main report links ADR-024 to concrete requirements (FR-2, FR-3, FR-11, NFR-1, NFR-2) and to specific tests. The requirements file contains a traceability matrix that names the replay/ledger tests, ensuring that future changes to replay policy or ledger wiring must update both tests and documentation.

These tests live under `tests/integration` and `tests/e2e`, are wired into the tox matrix, and are exercised in CI profiles that cover both stubbed and real-OTS calendars (including the stationary calendar used by the weekly ratchet job).
