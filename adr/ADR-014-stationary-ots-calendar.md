# ADR-014: Stationary OpenTimestamps Calendar for Deterministic Anchoring

Status: Proposed

Context

- OTS proofs acquired during CI or local runs may lack immediate BitcoinBlockHeaderAttestation; `ots upgrade` often needs time and repeated calls.
- Public calendars are shared resources; availability and latency vary.
- Our CI and reproducibility goals would benefit from an internal, predictable calendar endpoint to reduce external dependencies.

Decision

- Introduce a stationary (self-hosted) OpenTimestamps calendar service to improve determinism and reduce reliance on public pools.
- Provide configuration to prefer the stationary calendar, while still allowing fallbacks to public pools.

Scope

- Local development and CI can target the stationary calendar by default.
- Production deployments may continue to use public calendars, with the option to include the stationary calendar.

Technical Plan

- Calendar service
  - Deploy a containerized OTS calendar (official image or build from source) exposed internally.
  - Persist calendar state (e.g., volume mount) for reliability across restarts.
- Client configuration
  - Allow `ots_anchor.py` and shell wrappers to accept a list of calendars via env (e.g., `OTS_CALENDARS=https://calendar.local:8468`).
  - In CI, set `OTS_CALENDARS` to the stationary endpoint first, then public pools as fallback.
- Tox/CI integration
  - Add a tox env `ots-cal` to start/stop a local calendar for integration tests (future work).
  - Extend `ots-verify.yml` to optionally provision the calendar service (job-level `uses` or container service) before `tox -e ots`.
  - Cache headers and optionally cache calendar state to speed up subsequent runs.
- Verification workflow
  - Keep running `ots upgrade` before parsing heights.
  - Continue to support `.ots.bak` fallback and non-strict mode for placeholder proofs.

Alternatives Considered

- Rely purely on public calendars: simplest but less predictable.
- Mock OTS entirely: fast, but not representative of real-world anchoring and timing.

Consequences

- Additional maintenance overhead for hosting a service.
- Improved determinism and reduced flaky verification due to external pool variability.

Security & Operations

- Expose the stationary calendar only within CI or trusted networks.
- Monitor service health; restart on failure.
- Treat calendar input/output as untrusted; do not run as root; apply resource limits.

Rollout Plan

- Phase 1: Add `OTS_CALENDARS` configuration, document usage, and test manually against a locally run container.
- Phase 2: Add tox env to spin up calendar during tests and integrate with CI behind a gated workflow.
- Phase 3: Monitor performance and decide on making it the default for CI.

References

- https://opentimestamps.org/
- https://github.com/opentimestamps
- ADR-007: OTS verification in CI and Bitcoin headers policy (related verification workflow and headers-only strategy)
- ADR-008: Milestone M#4 completion and OTS verification workflow (production proof handling and metadata)
- ADR-015: Parallel Anchoring with OTS and RFC 3161 TSA (multi-anchor coordination; how calendar preference fits into hybrid anchoring)
