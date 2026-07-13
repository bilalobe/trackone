# TrackOne detached conformance verifier

`verify_conformance_archive.py` is a standard-library archive runner. It checks
the complete `SHA256SUMS` inventory, resolves every public schema through the
archive-local catalog, replays the v1 and v2-preview commitment vectors, and
executes the bundled `trackone-evidence` binary against the ADR-055 negative
fixture floor.

From outside the source checkout:

```bash
python3 verify_conformance_archive.py --archive trackone-conformance.tar.gz
```

The bundled native verifier currently targets Linux x86-64. Packaged crate
sources remain in `software/crates/` for independent rebuilds on other targets.
The archive does not claim full v2 conformance; its v2 corpus is explicitly a
preview/segment-record gate.
