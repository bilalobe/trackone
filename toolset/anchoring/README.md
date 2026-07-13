# Beta anchor-evidence tooling

`anchor_evidence.py` binds a successful detached conformance verification to a
canonical JSON subject, preserves the corresponding OpenTimestamps proof across
scheduled runs, normalizes its state, and verifies detached receipt bundles.

`ots_verifier_sanity.py` qualifies the exact open-PR clients used by the
workflow against a checked-in completed proof and historical Bitcoin header.
It requires positive verification and negative tamper rejection. The stable
OpenTimestamps 0.7.2 release remains the only client allowed to stamp or
upgrade real subjects.

The beta state order is:

```text
stationary
  -> calendar-pending
  -> bitcoin-attested-structure
  -> bitcoin-header-quorum-verified
```

The final state above uses a two-of-three public Esplora quorum and a sparse
OTSV sidecar. It does not validate Bitcoin difficulty transitions, cumulative
chainwork, or the active chain under full consensus rules. Every v1 receipt
therefore records `full_bitcoin_consensus_validated: false`.

Only state from a previous successful Anchoring Vitality run is resumed.
Mutable proof, sidecar, receipt, and attempt files are rolled back together if
an advancement fails. `bitcoin-header-quorum-verified` is terminal for the v1
queue, so completed anchors no longer consume calendar or explorer calls.
Publication markers avoid repeated OCI pull-backs while preserving retry after
any failed publishing run.

Run the standard-library unit floor with:

```bash
PYTHONPATH=toolset/anchoring \
  python3 -m unittest discover -s toolset/anchoring -p 'test_*.py'
```

Verify a downloaded OCI receipt directory without the repository runtime:

```bash
cd /tmp
python3 /path/to/receipt/verify-anchor-evidence.py \
  verify-bundle --root /path/to/receipt
```

ADR-060 defines the state, pinning, and delivery policy.
