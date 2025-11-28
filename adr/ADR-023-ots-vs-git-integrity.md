### ADR-023: Prefer OTS for integrity and time anchoring over Git plumbing tools

**Status**: Accepted
**Date**: 2025‑11‑28

#### Context

TrackOne’s pipeline needs:

- Immutable, verifiable telemetry/proof artifacts.
- Explicit, auditable *time anchoring* for data (not just code).
- A safety‑net model where operators can independently re‑verify that:
  - A given `*.bin` / `*.bin.ots` / `*.ots.meta.json` set corresponds to a particular Merkle root.
  - This root is anchored to a public, append‑only time source.

Git already provides several non‑porcelain / plumbing features that superficially overlap:

- Object store of content‑addressed blobs (`sha1`/`sha256` depending on repo format).
- Signed commits/tags (`gpgsig`, `ssh`, `sigstore` integrations).
- Reflogs and commit dates.

There is a temptation to treat these Git features as the *primary* integrity and time‑anchoring mechanism for TrackOne artifacts, e.g.:

- Store day ledgers and `.ots` proofs directly as Git blobs and lean on commit history for ordering.
- Use signed tags as the “attestation” that a given Merkle root is final.
- Treat commit timestamps as a rough time source.

However, these collide with core requirements and design choices:

- Git’s timestamps are not a trustable time authority.
- Git history is *developer‑controlled*, not a neutral third‑party calendar.
- Git signatures attest to *repository state*, not to arbitrary external evidence like OTS proofs and calendars.

#### Decision

TrackOne will:

1. **Use OpenTimestamps (OTS) as the primary integrity and time‑anchoring mechanism** for telemetry/proof artifacts, and
1. **Use Git’s plumbing tools only as secondary devtools**, never as the canonical source of truth for:
   - Artifact immutability.
   - Time anchoring.
   - Cross‑system verification.

Concretely:

- The canonical evidence chain for a day ledger is:

  - `*.bin` → hashed into Merkle tree → root stored and referenced;
  - `*.bin.ots` → OTS proof anchoring that root to OTS calendars;
  - `*.ots.meta.json` → metadata binding proof, artifact SHA‑256, and calendar URLs.

- Git’s role is limited to:

  - Source code versioning for the verifier, stationary calendar, and CI workflows.
  - Storing *copies* of ledgers and proofs for convenience, not as the trust anchor.
  - Tagged releases, ADR history, and developer workflow.

- Git features we **explicitly do *not* treat as primary trust anchors**:

  - Commit / tag timestamps.
  - Signed commits/tags asserting repo state.
  - Object IDs as the “primary hash” of artifacts.

When Git and OTS disagree, **OTS wins** for artifact provenance, because its calendars and Bitcoin‑backed proofs form the independent time chain we care about.

#### Rationale

1. **Time authority vs. developer control**

   - Git dates (`authorDate`, `committerDate`) are editable and replayable.
   - OTS calendars and underlying Bitcoin anchors provide an external, append‑only notion of time.
   - TrackOne’s threat model assumes a possibly compromised or misconfigured Git environment; OTS must still enable independent validation from published proofs alone.

1. **Scope: code history vs. artifact/proof provenance**

   - Git is excellent for *code history* and developer workflow.
   - TrackOne’s critical artifacts are not just the code, but:
     - Telemetry ledgers, derived Merkle roots.
     - OTS proofs and meta.
   - OTS is designed precisely for “prove this digest existed no later than time T”, independent of any particular VCS.

1. **Safety‑net layering**

   - We want multiple layers:
     - Git: versioned verifier + CI config.
     - OTS: timestamped proofs of data.
     - (Later) Container provenance / attestations: how the verifier and calendar were built.
   - Collapsing everything into Git would remove an independent layer and conflate “the tool we use to store code” with “the system we rely on for evidence of time”.

1. **Non‑porcelain Git tools are powerful but not neutral**

   - Commands like `git hash-object`, `git update-ref`, low‑level object manipulation, and plumbing scripts can be part of dev tooling (e.g. ad‑hoc checks or debugging).
   - They run under developer credentials, in mutable repos, and depend on local configuration.
   - OTS proofs, once anchored, do not depend on the developer’s Git history remaining honest.

#### Consequences

- **Positive**

  - Clear separation of concerns:

    - Git = code and workflow history.
    - OTS = artifact/proof time anchoring.
    - (Optional) Container attestations = build provenance of tools used to verify data.

  - Operators can validate TrackOne outputs from published ledgers and `.ots` proofs *without* trusting the TrackOne Git history.

  - CI/ratchet design stays coherent: the stationary calendar and OTS proofs are the evidence; Git tags and logs are an index, not the root of trust.

- **Negative / trade‑offs**

  - We add another system (OTS calendars, proofs) that developers must understand and operate, instead of reusing Git exclusively.
  - Some Git‑centric workflows (e.g. “just sign a tag and be done”) are intentionally left on the table in favor of explicit OTS handling.
  - Tooling must ensure we do not accidentally treat Git metadata (timestamps, signatures) as authoritative in verification logic.

- **Use of Git non‑porcelain as devtools**

  - We may still:

    - Use `git hash-object` or object inspection during development to cross‑check hashes.
    - Script around Git plumbing for local diagnostics or developer UX.

  - But all such uses are **non‑normative**: they must not affect the core verification semantics or replace OTS proofs in any required check.

#### Related decisions

- ADR‑014: Stationary calendar sidecar for deterministic OTS behavior in CI.
- ADR‑020: Safety‑net design for Merkle/OTS verification and ratchet enforcement.
- Future ADR: Build and release provenance (container attestations) once GitHub attestation support is available for this repository.
