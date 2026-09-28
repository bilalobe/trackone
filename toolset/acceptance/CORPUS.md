# Controlled VTL HTTPS acceptance corpus

This archive contains a real PostgreSQL-backed producer run, exact exported
evidence, public test trust material, reports from two verification implementations,
a focused rejection matrix, and the source bytes used for reproduction.
Read [the walkthrough](docs/vtl-https-acceptance.md) and
[fresh-run instructions](toolset/acceptance/README.md).

Verify the downloaded `.tar.gz.sha256` with `sha256sum -c`, then extract the
archive into a new directory. From its extracted top-level directory, run:

```bash
python3 -B tools/replay_corpus.py --corpus . --output ../vtl-replay-results
```

The output directory must be new and outside the corpus. Python 3.10+ and
OpenSSL 3 are required, with permission to listen on loopback. No Docker,
Cargo, TrackOne binary, or live TSA is needed. The checker first validates the
complete inventory, generates temporary web certificates, serves the unchanged
bundle bytes over authenticated local TLS 1.3, and checks all three scopes with
the archived TSA evaluation policy. It compares the reproduced evidence
conclusions and network object counts with the recorded independent reports.
Use `--inventory-only` without `--output` to check only the file inventory.
Do not edit the corpus or create caches/reports inside it.

The original test certificates have short validity. The new web certificate
authenticates the local replay endpoint; the archived TSA certificate, CRLs,
policy, signer pin and evaluation time govern the historical timestamp checks.
This does not replay the original TLS session or establish current trust in the
original test services. Public test trust inputs are fixtures, not production
trust recommendations. No private keys are included.

For a fresh producer exchange, use `source/` as the checkout and follow the
fresh-run command. New timestamps, keys and identifiers produce different bytes.
`provenance.json` identifies the base commit and hashes the actual source
snapshot; it explicitly does not represent the snapshot as a clean commit.

Both verification implementations use OpenSSL cryptography. The Python checker
implements its own parsing and commitment checks and does not use the Rust
verdict as an oracle. This is implementation independence, not organizational
independence. The report demonstrates scope-specific consistency and timestamp
and predecessor conclusions, not measurement accuracy, admission completeness,
unique ledger history, field experience or complete Appendix E conformance.
