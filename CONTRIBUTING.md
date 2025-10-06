# Contributing to Track1 — Ultra–Low‑Power, Verifiable Telemetry

Thanks for helping build a secure and verifiable telemetry pipeline. This guide keeps PRs small, reviewable, and
reproducible.

## Ground rules

- Tests must pass (`pytest -q`) before review.
- Do not commit generated artifacts:
    - `out/`, `*.bin`, `*.bin.ots`, `*.sha256`, `__pycache__/`, `.pytest_cache/`
- Reference ADRs in PR descriptions (e.g., “implements ADR‑002 nonce policy”).
- Keep PRs focused (≤ ~300 lines of diff where possible).

## Getting started

1) Create a feature branch:

```bash 
git checkout -b feat/<short-topic>``` 
```

2) Set up environment:

```bash 
uv pip install -r requirements.txt || true uv pip install pytest jsonschema``` 
```

3) Run tests:

```bash 
pytest -q
``` 

## Code structure

- `scripts/gateway/`: batcher, anchor, verifier CLIs
- `scripts/pod_sim/`: simulators, crypto test vectors
- `toolset/unified/schemas/`: JSON Schemas (facts, block, day)
- `adr/`: architecture decision records (index at `adr/README.md`)
- `out/`: build artifacts (git‑ignored)

## Commit style

Use clear, conventional messages:

```
feat(gateway): add canonical batcher and day chaining (ADR‑003) fix(ci): pin Python 3.13 in workflow docs(adr): add ADR‑002 framing/replay policy test: add end‑to‑end verify test (batch→OTS→verify)
```

## Adding or updating ADRs

- Copy the template in `adr/README.md`.
- Start as `Status: Proposed`.
- Link the ADR in your PR description.
- Once merged, update status to `Accepted`.

## Schemas and determinism

- Update schemas in `toolset/unified/schemas/` and keep examples under `toolset/unified/examples/`.
- Ensure canonicalization stays consistent: sorted keys, compact separators.

## CI

- GitHub Actions runs lint/tests on PRs and pushes to `main`.
- If CI fails, reproduce locally with the same commands shown in the workflow.

## Security

- Do not commit secrets, device tables, or real OTS proofs from production.
- Report security issues privately to the maintainers.

## Releasing

- Tag milestones:

```bash 
git tag -a v0.0.1-m0 -m "Milestone 0: batcher + OTS + schemas + ADRs" git push origin --tags``` 
```

## Contact

Open an issue for bugs/feature requests. For design changes, start with an ADR (Proposed) and a small proof‑of‑concept
PR.
