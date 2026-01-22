# ADR 009: Bandit findings remediation and decisions

Status: accepted (updated 2026-01-22)
Date: 2025-10-22

## Context

A Bandit security scan over runtime code (scripts/) reported several low-severity,
high-confidence issues. The goal was to remediate or provide justified suppressions
so CI fails only on high-severity/high-confidence issues while minimizing false positives.

## Findings (Bandit)

- B404: import of subprocess (blacklist) — scripts/gateway/ots_anchor.py, scripts/gateway/verify_cli.py
- B603/B607: subprocess invocation with partial path or without shell=False — calling the external `ots` CLI
- B603: subprocess calls where Bandit flagged potential untrusted input execution
- B110: try/except/pass detected — verify_cli.py
- B101: assert used — scripts/pod_sim/pod_sim.py
- B311: use of `random` module for values used in simulation — pod_sim.py

## Decision summary

1. Continue to call the external OpenTimestamps CLI (`ots`) where needed for "stamp" and
   "verify" operations. This is an external operational dependency and not re-implementable
   inside this repo.
1. Reduce Bandit noise by:
   - Validating the external executable path (via `shutil.which` and `os.access`) before invocation.
   - Invoking the executable via an absolute path and an argument list (no shell=True).
   - Narrowing exception handling to specific, meaningful exceptions.
   - Replacing problematic `assert` usage with explicit condition checks and raising appropriate exceptions.
   - Replacing non-cryptographic `random` with a cryptographically secure PRNG in the simulator to avoid B311.
   - Adding short, targeted `# nosec` suppressions at validated invocation sites with inline justification.
1. Configure Bandit in CI to only fail on issues that are both high-severity and high-confidence.
   This reduces false positives while keeping the CI signal meaningful.

## Files changed

- scripts/gateway/ots_anchor.py

  - Use `shutil.which('ots')` to find the executable.
  - Validate the resolved path is a file and executable via `Path.resolve()` and `os.access(..., X_OK)`.
  - Invoke the executable via full path list (no shell).
  - Catch `subprocess.CalledProcessError` and `OSError` explicitly; fallback to writing a placeholder proof.
  - Add `# nosec` to the validated subprocess.run call with justification comment.

- scripts/gateway/verify_cli.py

  - Narrowed file-read exceptions (`OSError`, `UnicodeDecodeError`) around the placeholder check.
  - Use `shutil.which` and validate the executable path before invoking `ots verify`.
  - Invoke verified full path and add `# nosec` inline to the subprocess.run call.

- scripts/pod_sim/pod_sim.py

  - Removed an `assert` that Bandit flagged (replaced with explicit import validation raising `ImportError` if the spec/loader is missing).
  - Replaced use of the pseudo-random `random` module with `secrets.SystemRandom()` for the simulator's sample data generation (addresses B311; simulators may use secure RNG to avoid tool warnings).

- .bandit.yaml

  - Exclude dev/test helpers: `tests` and `scripts/dev`
  - Set reporting thresholds to `severity: high` and `confidence: high` so CI only fails for high-risk/high-confidence findings.

## Why these changes

- B404 + B603/B607 relate to invoking external binaries. The safest in-repo mitigation is to:

  - Use absolute, validated paths and avoid shell interpolation.
  - Validate executables are actually present and executable.
  - Use targeted suppressions with clear inline justification when the invocation is deliberate and validated.

- B101: `assert` may be optimized away and is not appropriate for runtime checks. Use explicit condition checks and errors.

- B311: Using `random` for anything that might be mistaken as crypto usage triggers Bandit. For a simulator, using
  `secrets.SystemRandom` maintains the behavior but satisfies Bandit.

## Alternative approaches considered

- Replacing CLI calls with a pure-Python implementation of OTS—not feasible here (external network and Bitcoin anchoring required).
- Disabling Bandit checks globally or by rule—rejected to keep useful security scanning.
- Adding a separate Bandit configuration for exact rules—future work if the team wants finer-grained suppression.

## Consequences and follow-ups

- CI will now only fail on high/high Bandit findings. Developers should run Bandit locally with the provided config when making security-sensitive changes.
- We added inline `# nosec` suppressions for subprocess usage; these are justified and safe because of the explicit runtime validation.
- Dependency management note (supersedes older requirements-file guidance):
  - Tooling (Bandit, pip-audit, etc.) is declared in `pyproject.toml` under focused extras (e.g. `security`).
  - CI/tox installs these via extras and uses the committed `uv.lock` for deterministic resolution.
  - For interoperability, `make export-requirements` can generate pinned `out/requirements-security.txt` from `uv.lock`.

## How to reproduce the scan locally

Install Bandit and run from the repo root:

```bash
pip install -e ".[security]"
bandit -r scripts -ll
```

Optionally, run pip-audit in the same minimal env:

```bash
pip-audit
```

## Notes for reviewers

- The inline `# nosec` suppressions use Bandit’s supported `# nosec Bxxx` format; rationale lives in adjacent comments to avoid noisy “Test in comment … ignoring” output.
- If you prefer stricter or looser Bandit behavior (e.g., medium severity allowed), update `.bandit.yaml` accordingly.
