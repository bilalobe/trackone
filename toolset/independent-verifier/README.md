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

## HTTPS reference-binding acceptance checker

The [HTTPS acceptance walkthrough](../../docs/vtl-https-acceptance.md) connects
the audit scenario to the concrete exchange. The
[acceptance README](../acceptance/README.md) gives the fresh producer command,
focused rejection coverage, and detached corpus replay instructions.

`verify_https_bundle.py` is separate from the archive runner and from the Rust
verifier. It retrieves an immutable snapshot with Python's TLS 1.3 / HTTP/1.1
stack, encodes each validated UTF-8 path component exactly once, recomputes VTL
commitments and predecessor continuity, parses the relevant CBOR and DER
structures itself, and delegates only cryptographic signature and RFC 5280
path operations to OpenSSL. Its JSON report lists the checks actually
exercised; it does not claim exhaustive baseline-verifier coverage.

For timestamp-complete Class A evidence:

```bash
python3 verify_https_bundle.py \
  --bundle-url https://evidence.example/bundles/example/ \
  --expected-segment-sha256 "$EXPECTED_SEGMENT_SHA256" \
  --https-ca-file https-root.pem \
  --scope public_recompute \
  --tsa-ca-file tsa-root.pem \
  --tsa-crls-file tsa-crls.pem \
  --tsa-policy 1.3.6.1.4.1.55555.1 \
  --tsa-signer-cert-sha256 "$TSA_SIGNER_SHA256" \
  --evaluation-time 2026-09-09T12:00:00Z \
  --output acceptance-report.json
```

The HTTPS CA and TSA trust inputs are intentionally distinct. The bundle URL,
required scope, and expected segment digest are provisioned independently of
the retrieved manifest.

The checker also supports authenticated gateway disclosure generation:
`--bearer-token-file FILE --generate-class A|B|C --download-dir NEW_DIRECTORY`.
With `--generate-class`, `--bundle-url` is the ledger/segment directory URL;
Class B selects complete batches using `--batch`. Without generation, a bearer
file can authenticate reads of an existing immutable bundle URL. Downloads
include every digest-bound manifest reference and never overwrite a directory.
See the [HTTP binding](../../docs/vtl-http-binding.md) for a complete example and
the subsequent `trackone-evidence verify --root` command.
