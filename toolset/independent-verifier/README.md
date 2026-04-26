# TrackOne Tiny Independent Verifier

This is a tiny external verifier for the published
`trackone-canonical-cbor-v1` vector corpus.

It intentionally does not import TrackOne. The verifier uses Python stdlib
only, including a small local CBOR decoder, and checks:

- manifest profile identifiers and profile constraints;
- JSON projection shape for the vector facts;
- deterministic CBOR decode and map-key ordering;
- SHA-256 digests over raw CBOR artifact bytes;
- ADR-003 hash-sorted Merkle root calculation;
- day-record CBOR/JSON agreement.

For exported evidence bundles, it also checks:

- verifier manifest artifact paths are bundle-relative and digest-covered;
- required public-spine artifacts exist and match their SHA-256 references;
- disclosed fact CBOR files recompute the block/day Merkle root;
- `day/<date>.cbor`, `day/<date>.json`, and the SHA-256 sidecar agree;
- optional OTS metadata points at the exported day artifact/proof paths.

Run it from anywhere, pointing at a copied or checked-out vector corpus:

```sh
python toolset/independent-verifier/verify_vector_corpus.py \
  toolset/vectors/trackone-canonical-cbor-v1
```

CI runs the same verifier from a detached temporary directory:

```sh
tox -e archive-independent
```

The fuller archival scenario runs the TrackOne pipeline/export path first, then
copies only the exported bundle and this verifier into a detached directory:

```sh
tox -e archive-evidence-scenario
```

Expected output includes `"ok": true`, the corpus Merkle root, and the day CBOR
SHA-256 digest.
