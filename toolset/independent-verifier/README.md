# TrackOne detached conformance verifier

`verify_conformance_archive.py` is a standard-library archive v3 runner. It checks
the complete `SHA256SUMS` inventory, resolves every public schema through the
archive-local catalog, replays the v1 and full draft-08 v2 commitment vectors, and
executes the bundled `trackone-evidence` binary against the ADR-055 negative
fixture floor.

From outside the source checkout:

```bash
python3 verify_conformance_archive.py --archive trackone-conformance.tar.gz
```

The bundled native verifier currently targets Linux x86-64. Packaged crate
sources remain in `software/crates/` for independent rebuilds on other targets.
The archive claims full conformance to the scoped draft-08 v2 profile:
durable production, disclosure Classes A/B/C, RFC 3161 verification, the
negative-fixture refusal floor, and offline schema resolution. The claim does
not cover telemetry truth or completeness, external TSA availability, or
fitness for automated sanctions or actuation.
