# Companion SCITT publication fixtures

`segment-statement.json` references the exact segment artifact in the VTL HTTP
binding corpus. `disclosure-{A,B,C}.tar` and their statements are synthetic
single-segment disclosure fixtures with the same underlying segment bytes and
different disclosed contents. Their unsigned issuer is a syntax example;
cryptographic fixtures carry a real synthetic organizational certificate chain.

`negative-statements.json` records schema failures and schema-valid semantic
disagreements. `check_contracts.py` checks the expected schema outcomes;
`toolset/scitt/test_publication.py` checks their semantic rejection.

`exchange/` is an actual exchange with the pinned independent SCITT CCF service.
It retains submitted/transparent COSE statements, a receipt, public organization
and service trust inputs, authorization and registration policies, exact HTTP
headers/entity bodies, dependency versions, and separate publication/VTL reports.
The VTL fixture's RFC 3161 channel was refreshed with a synthetic TSA during the
capture; the authoritative segment bytes are unchanged. No private keys or
production access credentials are included.

The re-signed `mismatch-*.cose` fixtures have valid organizational signatures
but copied identifiers that disagree with the artifact. They are not transparent
statements. `unauthorized-ledger.cose` was rejected by the real service. Receipt
corruption, wrong-statement binding, and untrusted-service-key cases are exercised
against the captured real receipt by `test_replay.py`.

Run offline with the pinned Python dependencies:

```sh
python toolset/scitt/replay.py
PYTHONPATH=toolset/scitt python -m unittest discover -s toolset/scitt -p 'test_*.py'
```

Replay evaluates organizational certificates and retained CRLs at the explicit
capture time. It does not assert present-day freshness. The VTL reports record
the separate live verification; replay's output is a publication verdict only.
For a fresh exchange, follow
[`docs/scitt-trackone-statement-profile.md`](../../../docs/scitt-trackone-statement-profile.md).
