# TrackOne Beta Negative Fixtures v1

This corpus is the ADR-055 beta floor for detached verifier refusal behavior.
Each fixture is a self-contained evidence bundle rooted under `fixtures/<id>/`
and is runnable through the public Rust verifier CLI:

```bash
cargo run --locked -p trackone-evidence -- verify \
  --root toolset/vectors/trackone-beta-negative-v1/fixtures/<id> \
  --facts toolset/vectors/trackone-beta-negative-v1/fixtures/<id>/facts \
  --json \
  --policy-mode <warn|strict> \
  --disclosure-class <A|B|C>
```

`cases.json` records the expected status and the diagnostic fragment that a
detached verifier must surface. The fixtures cover verifier-manifest errors,
disclosure-class recomputation behavior, replay/admission rejection audit
records, malformed-frame audit records, batch-shape failures, non-zero
previous-day-root chaining input, and canonical-CBOR/decoded fact refusal.

Rejected frames are represented only as operator-audit evidence under `audit/`.
They are not commitment leaves and must not be placed under `facts/`.
