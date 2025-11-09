# ADR-006: Forward-only schema policy and deprecating `salt4`

Status: Accepted
Date: 2025-10-12

## Context

Earlier milestones (M#0/M#1) used ChaCha20-Poly1305 with a 96-bit nonce constructed as `salt4 || fc32 || rand4`.
Starting with M#2 we standardized on XChaCha20-Poly1305 with a 192-bit nonce `salt8 || fc64 || rand8` for stronger
nonce space, simpler replay management, and alignment with the primitives from ADR-001.

Maintaining both `salt4` (legacy) and `salt8` (current) complicates code paths, tests, schemas, and increases review
surface without bringing operational value in this repository.

## Decision

Adopt a forward-only policy for schemas and cryptographic metadata:

- Standardize on `salt8` for XChaCha20-Poly1305 (24-byte nonce).
- Treat `salt4` as legacy and do not carry it forward across milestones.
- No migrations: when we move to a new milestone, we remove old references instead of keeping backward-compatible code.
- The "active milestone" (M) is the only valid schema and code path in-repo. Older data is archived for reference, not
  executed.

## Rationale

- Reduce cognitive load and surface area: one AEAD mode and one nonce shape in active code.
- Lower risk: fewer branches to audit for correctness and security.
- Faster iteration: milestone boundaries are clean resets, enabling rapid evolution.
- Clearer testing: tests target the current M; vectors for prior milestones remain as static artifacts only when useful.

## Alternatives considered

1. Keep both `salt4` and `salt8` in production code

   - Pros: seamless interop with older deployments
   - Cons: increased complexity, larger attack surface, duplicated tests; not needed for this repo

1. Auto-derive `salt8` from `salt4` on load and persist both

   - Pros: soft transition
   - Cons: legacy handling lingers; mixed states to support; obscures clear-cut milestone boundary

## Scope and impact

- Schemas: the current device table schema should only require `salt8` and `ck_up`. Disallow `salt4`.
- Code: active codepaths should only construct 24-byte nonces from `salt8` and ignore/remove `salt4`.
- Tests: focus on current-M behavior. Prior-M vectors can be kept as static KATs if valuable, but not drive live
  codepaths.
- Pipelines: milestone-specific flows (e.g., M#1) are demonstration-only and will be removed or archived when advancing.

## Implementation notes (phased)

- Short term (documentation now): this ADR records the direction and policy.
- Enforcement (when flipping fully to forward-only):
  - Tighten device table schema to require `salt8` and reject `salt4`.
  - Remove any fallback that derives `salt8` from `salt4`.
  - Delete legacy flags/branches that enable 12-byte nonces.
  - Fail fast on older table versions and instruct to regenerate.

## Consequences

- Breaking changes are expected across milestones; regeneration of device tables and test fixtures is the standard path.
- Simpler codebase, fewer tests to maintain, clearer audits.

## Migration policy

- No migrations. We do not ship migration shims or support dual-running formats inside the repo.
- When a milestone changes the shape/protocol, we:
  1. Archive previous artifacts and ADRs as read-only references.
  1. Delete legacy references from source code and schemas.
  1. Regenerate tables/vectors for the new milestone.

## References

- ADR-001: Primitives (X25519/HKDF/XChaCha20-Poly1305/Ed25519)
- ADR-002: Telemetry framing and replay policy
- ADR-005: PyNaCl migration
