# ADR-053: Beta Public Contract Spine

**Status**: Accepted
**Date**: 2026-04-25

## Related ADRs

- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md): Merkle canonicalization and anchoring
- [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md): CBOR-first commitment profile and artifact authority
- [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md): Verification disclosure bundles and privacy tiers
- [ADR-043](ADR-043-phased-bundle-manifest-maturity-for-id.md): Phased bundle-manifest maturity for the I-D
- [ADR-044](ADR-044-json-schema-modularity-and-authoritative-contract-artifacts.md): JSON Schema modularity and authoritative contract artifacts
- [ADR-052](ADR-052-commitment-profile-identifier-binding-boundary.md): Commitment profile identifier binding boundary

## Context

The beta bar needs a sharper distinction between the public contract spine and
implementation convenience. TrackOne already has schemas, CDDL, vectors, day
artifacts, verifier output, disclosure classes, and rejection audit logs, but
changes to those surfaces do not all carry the same compatibility cost.

This ADR defines the migration rules and freezes the verifier-visible behavior
that external verifiers, auditors, and publication profiles may rely on.

## Decision

### 1) Versioning and migration rules

The following rules decide which identifier or artifact line must change.

| Change                                                                                                                                                                                                                                                                                                                              | Required action                                                                      |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Changes authoritative fact/day/block CBOR bytes, deterministic CBOR encoding rules, accepted integer/float/null/timestamp/unknown-field behavior for commitment inputs, hash algorithm, Merkle leaf ordering, Merkle parent construction, odd-leaf policy, day-root chaining semantics, or disclosure-class recomputation semantics | New `commitment_profile_id`                                                          |
| Changes a checked-in JSON Schema's required fields, closed-field policy, field type, enum vocabulary, or meaning while preserving the same artifact family and commitment profile                                                                                                                                                   | New schema version or schema `$id`                                                   |
| Introduces a new primary evidence object, trust domain, publication statement, disclosure package, rejection-audit public contract, sealed-state object, or non-day commitment unit                                                                                                                                                 | New artifact family with its own schema/CDDL and directory/name convention           |
| Accepts legacy spellings, aliases, optional historical fields, alternate discovery locations, or a stricter/looser validation lane without changing produced commitments or truth claims                                                                                                                                            | Verifier tolerance only; output must report the compatibility behavior when material |
| Changes SensorThings, JSON presentation, CLI rendering, report formatting, non-authoritative labels, or read-only consumer exports that are not hashed into commitments and do not change verifier claims                                                                                                                           | Projection change only                                                               |

A change may trigger more than one action. For example, a new publication
claim that also changes commitment bytes needs both a new artifact family and a
new `commitment_profile_id`.

### 2) Verifier manifest is part of the public spine

`day/<date>.verify.json` is not just tooling output. For beta, it is the normal
public contract that binds a day bundle to:

- the explicit `commitment_profile_id`;
- the disclosure class;
- bundle-root-relative artifact paths;
- SHA-256 digest coverage for every listed artifact;
- executed and skipped verifier checks; and
- anchoring/publication-channel status.

Verifier manifests MUST be portable. Manifest paths are interpreted relative
to the evidence bundle root. Absolute paths and parent-directory traversal are
not verifier claims and are invalid in the public manifest schema.

The verification-critical minimum is:

- `version`, `date`, and `site`;
- `facts_dir` when Class A recomputation is claimed;
- `artifacts.block`, `artifacts.day_cbor`, `artifacts.day_json`, and
  `artifacts.day_sha256`;
- a `verification_bundle` with `disclosure_class`,
  `commitment_profile_id`, `checks_executed`, and `checks_skipped`; and
- an `anchoring` object that reports channel status rather than hiding skipped
  or unavailable channels.

The current schema also retains `device_id`, `frame_count`,
`provisioning_input`, `provisioning_records`, and
`sensorthings_projection` as required fields because the current emitted demo
and export workflow is still single-day/single-site and includes those
artifacts. They are verifier-visible summary/projection fields, not substitutes
for fact/day artifact authority.

### 3) Disclosure classes are verifier behavior

Class labels are frozen around what an independent verifier can recompute and
must report, not around operator intent.

| Class | Verifier can recompute                                                                                                                                                                                  | Verifier cannot recompute                                                                          | Required report behavior                                                                                                                                               | False claim                                                                                                                                                       |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A     | Fact CBOR digests from disclosed facts, ADR-003 Merkle root, block/day consistency, day artifact digest, manifest artifact digests, and enabled anchoring/publication proofs when artifacts are present | Real-world sensor truth, undisclosed upstream device lifecycle state, or omitted external channels | Execute fact-level recomputation; report root match/mismatch; report manifest/profile status; set public recomputability only when required artifacts pass             | Claiming Class A/public recomputability when facts are missing, root recomputation was skipped, manifest/profile is absent in strict lanes, or digest checks fail |
| B     | Day/block consistency, day artifact digest, manifest artifact digests, enabled anchors, and any disclosed partition commitments or auditor-supplied material                                            | The complete public fact set when facts are withheld                                               | Skip full fact recomputation with an explicit disclosure-class reason; report `publicly_recomputable=false`; distinguish partner/auditor material from public material | Claiming public full-fact recomputation or complete public auditability                                                                                           |
| C     | Day artifact digest, manifest digests, chain/anchor existence, timestamp/publication status when artifacts are present                                                                                  | Fact contents, fact set completeness, Merkle leaves, or semantic telemetry values                  | Skip fact recomputation; label as anchor/existence evidence; report which channels were executed or skipped                                                            | Claiming fact-level authenticity, fact completeness, or recomputed telemetry contents                                                                             |

If a verifier cannot execute a check because of class limits or missing
artifacts, it MUST list the check under `checks_skipped` with a reason instead
of silently omitting it.

### 4) Replay and rejection evidence

Rejection audit logs are **operator-audit evidence**, not beta public-spine
commitment artifacts.

The current shape is still schema-governed because auditors may inspect it:

- file family: `audit/rejections-<day>.ndjson`;
- record schema: `toolset/unified/schemas/rejection_audit.schema.json`;
- fields: `device_id`, `fc`, `reason`, `observed_at_utc`, `frame_sha256`,
  and `source`;
- source taxonomy: `parse`, `decrypt`, `replay`; and
- reason taxonomy: the closed parse/native/replay rejection vocabulary in the
  schema and `trackone_core.admission.REJECTION_REASON_TAXONOMY`.

Those records explain why input frames were not admitted. They are not Merkle
leaves, not day-record fields, and not required for a Class A public
recomputation claim. If a future audit workflow requires rejection evidence as
publicly published proof, that must promote rejection audit to a new artifact
family before beta freeze rather than slipping it into the existing day
commitment profile.

## Consequences

### Positive

- External verifier authors get a stable decision table for profile, schema,
  artifact-family, tolerance, and projection changes.
- `day/<date>.verify.json` becomes a real public contract with portable path
  and digest rules.
- Disclosure classes become machine-verifier behavior, reducing room for
  overclaiming partial disclosures.
- Rejection evidence remains useful to operators without becoming an implicit
  public commitment surface.

### Negative

- Compatibility decisions now need more explicit classification before merge.
- Some current manifest fields remain broader than the verification-critical
  minimum until the emitted workflow and schema can be split cleanly.
- Promoting rejection audit to public-spine status later will require a new
  artifact family rather than a quiet schema tweak.

## Testing & Migration

1. Keep `verify_manifest.schema.json` strict about relative artifact paths and
   digest-bearing artifact references.
1. Keep checked-in schemas valid under JSON Schema 2020-12.
1. Validate the published canonical CBOR vector corpus against the public
   vector manifest and fact-projection schemas.
1. Validate the rejection-audit schema against the package-level rejection
   reason/source taxonomies.
1. Treat any future change to disclosure-class recomputation behavior as a
   commitment-profile review item, not a report-wording tweak.
