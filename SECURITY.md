# Security Policy

## Scope

TrackOne is currently in an **alpha** release line. Security reports are welcome
for:

- the current `main` branch
- the latest tagged alpha release
- the published Python/Rust packaging surfaces
- the gateway, verifier, evidence export, and commitment tooling

This repository includes experimental and prototype-oriented components. A
report against those components is still useful, but the expected remediation
path may be "tighten or remove the surface" rather than "preserve exact API
compatibility."

## Supported Versions

Security fixes are expected on:

- the latest tagged alpha release
- `main`, when it is ahead of the latest tag

Older alpha tags should be treated as historical snapshots unless explicitly
called out in release notes.

## Reporting a Vulnerability

Please report vulnerabilities privately to:

- `elkhatabibilal@gmail.com`

Do not open a public GitHub issue for an unpatched security vulnerability.

When reporting, include as much of the following as possible:

- affected version, branch, commit, or artifact
- impacted component or path
- reproduction steps or proof of concept
- expected impact
- whether the issue affects confidentiality, integrity, availability, or
  release authenticity
- any relevant environment details such as Python version, Rust toolchain,
  operating system, and whether the native extension was installed

If the issue relates to cryptography, framing, replay handling, artifact
verification, or publication/export integrity, please say so explicitly.

## Response Expectations

Best effort expectations for initial handling:

- acknowledgment within 7 days
- follow-up triage after reproducing or bounding the report
- coordinated disclosure after a fix or mitigation is available

Because TrackOne is in alpha, some reports may be resolved by:

- removing or narrowing an unstable surface
- documenting a boundary more clearly
- shipping the fix only on the latest alpha line and `main`

## Security Posture Notes

TrackOne is centered on integrity, replay resistance, deterministic artifact
generation, and verifier-gated evidence export. The most security-sensitive
areas include:

- frame admission and anti-replay behavior
- canonical CBOR commitment generation
- day artifact verification and manifest validation
- anchoring and proof sidecar handling
- export/publication gating
- native Python/Rust boundary behavior

Automated security tooling in CI, including `tox -e security`, is helpful but
not a substitute for responsible disclosure. Some CI security checks are
currently non-blocking to avoid noisy failures in the alpha line; private
reports remain the preferred path for real vulnerabilities.

## Disclosure Preference

Please give the project a reasonable chance to investigate and mitigate before
public disclosure.
