# TrackOne detached conformance verifier

`verify_conformance_archive.py` is a standard-library conformance archive runner. It
checks the complete `SHA256SUMS` inventory, resolves every public schema through
the archive-local catalog, reproduces the current VTL normative known-answer
vector, and executes the
bundled `trackone-evidence` binary against the version-one producer-manifest
and unversioned verifier-result slate.

From outside the source checkout:

```bash
python3 verify_conformance_archive.py --archive trackone-conformance.tar.gz
```

The bundled native verifier currently targets Linux x86-64. Packaged crate
sources remain in `software/crates/` for independent rebuilds on other targets.
The manifest makes only mechanically replayed archive claims: the normative
VTL vector, the current VTL evidence slate, offline schema resolution, and
release-asset counts.
It does not make an unscoped draft-conformance claim or attest telemetry truth,
deployment behavior, external TSA availability, or fitness for automated
sanctions or actuation.

## Building an archive

`build_conformance_archive.py` assembles the archive that the runner above
verifies. The builder intentionally does not package the externally published profile
document. The archive retains the checked-in schemas, CDDL, vectors, and
detached verifier; the active profile source remains the [current document on
the IETF Datatracker](https://datatracker.ietf.org/doc/draft-elkhatabi-verifiable-telemetry-ledgers/).
