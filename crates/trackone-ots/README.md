# trackone-ots

Reusable, Rust-native OpenTimestamps verification primitives for TrackOne.
The crate parses supported detached proofs, verifies proof bindings, validates
metadata sidecars, and can fall back to a bounded external `ots` verifier.

It deliberately contains no gateway-service, evidence-export, or PyO3 code.
Applications and bindings depend on this crate at the edge; no application
logic depends on the gateway service to reach OTS behavior.

## Public helpers

- `verify_ots_proof_native` verifies a proof against its artifact and reports
  the normalized OTS state.
- `validate_meta_sidecar_native` checks the evidence metadata sidecar and its
  artifact binding.
- `hash_for_ots_native` computes the artifact digest used by OTS subjects.
- `describe_ots_proof_native` returns bounded proof metadata for diagnostics.

The implementation recognizes placeholder, stationary, pending, and verified
proof states without fabricating external Bitcoin or TSA claims. Strict
external verification remains bounded by the shared timeout constant.

## Checks

```bash
cargo test --locked -p trackone-ots
cargo clippy --locked -p trackone-ots --all-targets -- -D warnings
```
