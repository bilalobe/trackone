# ADR-044: JSON Schema Modularity and Authoritative Contract Artifacts

**Status**: Accepted
**Date**: 2026-03-12
**Updated**: 2026-03-12

## Related ADRs

- [ADR-006](ADR-006-forward-only-schema-and-salt8.md): Forward-only schema policy
- [ADR-034](ADR-034-serialization-boundaries-transport-vs-commitments.md): Transport vs commitment encodings
- [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md): Authoritative artifact boundaries
- [ADR-040](ADR-040-commitment-test-vectors-and-conformance-gates.md): Contract/conformance discipline

## Context

TrackOne uses `toolset/unified/schemas/*.schema.json` as machine-readable
contracts for facts, day artifacts, provisioning bundles, device tables, and
related verification outputs.

TrackOne now also distinguishes a smaller CBOR-authoritative commitment family
from the broader JSON artifact surface. That CBOR family is described
separately through CDDL, while JSON Schema remains the contract language for
JSON projections and operational JSON artifacts.

That schema set is currently inconsistent in structure:

- some files use JSON Schema draft 2020-12 while others still use draft-07;
- repeated scalar and object shapes are duplicated inline across files;
- some schemas use reusable local definitions while others restate the same
  field patterns independently;
- future growth creates pressure to "template" schemas with ad hoc text
  generation instead of using JSON Schema's native modularity features.

If TrackOne solves this with ad hoc templating alone, it creates a new class of
problems:

- a second, non-standard source of truth for contract structure;
- drift between generated output and the checked-in `.schema.json` artifacts;
- harder third-party consumption because reviewers and tooling need to
  understand custom generation logic before they can trust the contract.

TrackOne needs a more standard contract-authoring policy that scales without
turning schema files into hand-copied fragments or Jinja-style build products.

## Decision

### 1) Checked-in JSON Schema artifacts remain the contract

The normative machine-readable contract for TrackOne JSON artifacts remains the
checked-in `.schema.json` files under `toolset/unified/schemas/`.

- Consumers, tests, and CI MUST validate against emitted `.schema.json`
  artifacts, not against a higher-level template language.
- Any optional higher-level authoring source is an implementation aid, not the
  normative contract.

This policy applies to JSON artifacts. It does not prohibit TrackOne from
adding CDDL for the CBOR-authoritative commitment family defined by ADR-039.

### 2) Standardize on JSON Schema draft 2020-12

TrackOne SHOULD converge the unified schema set on JSON Schema draft 2020-12.

- New schemas MUST use draft 2020-12.
- Existing draft-07 schemas SHOULD be migrated during normal contract-touching
  work.
- New reuse work SHOULD prefer `$defs` and `$ref` over legacy `definitions`
  patterns.

This gives the repo a single dialect and avoids mixed-draft maintenance.

### 3) Prefer native schema modularity over text templating

When schema structure repeats, TrackOne SHOULD first solve it using JSON
Schema's standard composition features:

- `$defs`
- `$ref`
- `allOf`, `oneOf`, `anyOf` where semantically correct
- shared helper schemas for common scalar and object fragments

Typical reusable shapes include:

- `pod_id`, `site_id`, RFC 3339 timestamps, UTC dates;
- hex-encoded digests and signatures;
- deployment/provisioning metadata objects;
- shared artifact-path/digest entries used by verification bundles.

Ad hoc text templating (for example Jinja expansion of JSON fragments) MUST NOT
be the primary contract-structuring mechanism.

### 4) Shared common schema modules are allowed and preferred

TrackOne MAY add shared schema modules such as:

- `common.schema.json` for reusable scalar/string/identifier definitions;
- `deployment.schema.json` or `provisioning.schema.json` for reused object
  shapes;
- bundle-manifest helper schemas for repeated artifact-entry structures.

Those modules are still ordinary JSON Schema artifacts and remain directly
inspectable by standard tools.

### 5) Higher-level generation is optional, but output remains authoritative

If TrackOne later adopts a higher-level authoring system (for example CUE,
Pydantic-based generation, or another schema DSL), that layer MUST satisfy all
of the following:

- generated `.schema.json` output is checked in;
- CI validates that generated output is up to date;
- downstream tooling continues to consume the generated JSON Schema files;
- the generated JSON Schema remains the authoritative machine-readable
  contract.

TrackOne MUST NOT require external consumers to understand a private template
system in order to interpret the contract.

## Consequences

### Positive

- Keeps TrackOne aligned with standard JSON Schema tooling and reviewer
  expectations.
- Reduces copy-paste drift across schema files.
- Makes future schema growth easier without inventing a custom contract DSL.
- Preserves inspectable, versioned contract artifacts in-repo.
- Keeps the JSON Schema surface cleanly scoped even when CDDL is added for the
  narrower CBOR-authoritative family.

### Negative

- Requires migration work across older schemas.
- Shared schema modules introduce more files and more `$ref` relationships to
  manage carefully.
- Authors must be disciplined about not duplicating shapes "just for speed."

## Alternatives Considered

- **Keep the current mixed style**: rejected because repeated inline fragments
  and mixed draft versions do not scale cleanly.
- **Use ad hoc text templating as the main schema authoring model**: rejected
  because it makes the template layer, rather than JSON Schema itself, the de
  facto source of truth.
- **Switch entirely to a higher-level schema DSL immediately**: rejected for
  now because it adds tooling and migration cost without first exhausting
  standard JSON Schema modularity.

## Testing & Migration

1. Standardize new schema work on draft 2020-12.
1. Introduce shared reusable schema modules for repeated scalar and object
   shapes.
1. Migrate duplicated inline structures to `$defs` / `$ref` as touched by
   active work.
1. Add CI checks that validate all checked-in schemas and detect stale
   generated output if a higher-level generation step is later introduced.
1. Keep the checked-in `.schema.json` artifacts as the reviewable contract in
   PRs, even if authoring is assisted by generation tooling.
