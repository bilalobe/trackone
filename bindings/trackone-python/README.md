# trackone-python

Optional legacy PyO3 adapters for TrackOne's Rust libraries. The package is a
leaf binding: it owns Python conversion and module registration only, while
protocol, OTS, ingest, ledger, and SensorThings behavior remains in reusable
Rust crates.

The beta product surface is Rust-native, so this package is not published and
its Python bridge is enabled explicitly with the `python` Cargo feature. It is
checked as part of the workspace matrix but is excluded from the nine-package
release and conformance package set.

## Development check

```bash
cargo check --locked -p trackone-python --features python --all-targets
cargo test --locked -p trackone-python --features python
```

The PyO3 module is registered as the legacy `_native` extension. Do not add
protocol or persistence semantics here; put reusable behavior in the owning
crate and expose only the conversion surface from this package.
