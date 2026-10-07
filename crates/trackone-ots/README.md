# trackone-ots

Reusable, Rust-native OpenTimestamps verification primitives for TrackOne.
The crate parses supported detached proofs, verifies proof bindings, validates
metadata sidecars, and can fall back to a bounded external `ots` verifier.

It deliberately contains no gateway-service, evidence-export, or PyO3 code.
Applications and bindings depend on this crate at the edge; no application
logic depends on the gateway service to reach OTS behavior.

## Public helpers

- `verify_ots_proof_native` verifies a proof against its artifact and reports
  the normalized OTS state, preserving the individual-argument API.
- `verify_ots_proof_with_options` accepts grouped `OtsVerifyOptions`, whose
  `validate()` method checks timeout configuration before verification.
- `validate_meta_sidecar_native` checks the evidence metadata sidecar and its
  artifact binding.
- `hash_for_ots_native` computes the artifact digest used by OTS subjects.
- `describe_ots_proof_native` returns bounded proof metadata for diagnostics.

The implementation recognizes placeholder, stationary, pending, and verified
proof states without fabricating external Bitcoin or TSA claims. Strict
external verification uses the shared timeout constant by default. When a
caller supplies an expected artifact digest, every proof path first hashes the
sibling artifact and fails closed if it is missing or different. Fallback to
an external `ots` binary always uses private staged copies of both artifact and
proof, so an external zero exit status or a concurrent replacement of the
original siblings cannot override the verified snapshot.

## Verification options

```rust
use std::path::Path;
use std::time::Duration;
use trackone_ots::{OtsVerifyOptions, verify_ots_proof_with_options};

let options = OtsVerifyOptions {
    ots_binary: Some(Path::new("/usr/bin/ots")),
    timeout: Duration::from_secs(30),
    ..Default::default()
};
options.validate().expect("valid timeout");
let result = verify_ots_proof_with_options(Path::new("day.cbor.ots"), &options);
```

Defaults reject placeholders, omit an expected digest, discover `ots` on
`PATH`, and use `OTS_VERIFY_TIMEOUT_SECS`. Timeouts must be positive and
representable via `Instant::checked_add` on the current platform; there is no
additional maximum. `OtsConfigError` exposes `ZeroTimeout` and
`TimeoutOutOfRange`, with stable display/reason codes `ots-timeout-zero` and
`ots-timeout-out-of-range`.

Both verification APIs validate the timeout at entry, even after a caller has
called `validate()`. Invalid timeouts return `ok: false` and status `Failed`
before digest parsing, proof reads, or process execution, including for
placeholder and native pending proofs. These configuration failures take
precedence over proof and artifact errors. The existing
`verify_ots_proof_native` function still accepts `None` for the default timeout;
explicit zero or unrepresentable durations now fail with the reason codes
above. External polling uses elapsed time to avoid deadline overflow.

## Checks

```bash
cargo test --locked -p trackone-ots
cargo clippy --locked -p trackone-ots --all-targets -- -D warnings
```
