from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.gateway.canonical_cbor import canonicalize_json_bytes_to_cbor
from scripts.gateway.merkle_batcher import merkle_root_from_leaves
from trackone_core.ledger import sha256_hex

VECTOR_DIR = (
    Path(__file__).resolve().parents[2]
    / "toolset"
    / "vectors"
    / "trackone-canonical-cbor-v1"
)


def _load_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _corpus_is_complete(manifest_path: Path) -> bool:
    """Return True only if the manifest and every file it references are present."""
    if not manifest_path.exists():
        return False
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    base = manifest_path.parent
    for fact in manifest.get("facts", []):
        if not (base / fact["json_path"]).exists():
            return False
        if not (base / fact["cbor_path"]).exists():
            return False
    for key in ("day_record_json_path", "day_record_cbor_path"):
        if key in manifest and not (base / manifest[key]).exists():
            return False
    return True


def test_python_reproduces_published_commitment_vectors() -> None:
    if not _corpus_is_complete(VECTOR_DIR / "manifest.json"):
        pytest.skip("vector corpus is incomplete – run gen_commitment_vectors.py to populate")
    manifest = _load_json(VECTOR_DIR / "manifest.json")
    leaves: list[bytes] = []

    for fact in manifest["facts"]:
        json_path = VECTOR_DIR / fact["json_path"]
        cbor_path = VECTOR_DIR / fact["cbor_path"]
        expected = cbor_path.read_bytes()
        actual = canonicalize_json_bytes_to_cbor(json_path.read_bytes())
        assert actual == expected
        assert sha256_hex(actual) == fact["cbor_sha256"]
        leaves.append(actual)

    root_hex, leaf_hashes = merkle_root_from_leaves(leaves)
    assert root_hex == manifest["merkle_root"]
    assert leaf_hashes == manifest["leaf_hashes"]

    day_json = (VECTOR_DIR / manifest["day_record_json_path"]).read_bytes()
    day_cbor = (VECTOR_DIR / manifest["day_record_cbor_path"]).read_bytes()
    assert canonicalize_json_bytes_to_cbor(day_json) == day_cbor
    assert sha256_hex(day_cbor) == manifest["day_cbor_sha256"]


def test_native_extension_reproduces_published_commitment_vectors() -> None:
    if not _corpus_is_complete(VECTOR_DIR / "manifest.json"):
        pytest.skip("vector corpus is incomplete – run gen_commitment_vectors.py to populate")
    trackone_core = pytest.importorskip("trackone_core")
    native = getattr(trackone_core, "_native", None)
    if native is None:
        pytest.skip("trackone_core native extension unavailable")

    manifest = _load_json(VECTOR_DIR / "manifest.json")
    leaves: list[bytes] = []
    ledger = getattr(native, "ledger", None)
    merkle = getattr(native, "merkle", None)
    if ledger is None or merkle is None:
        pytest.skip("native ledger/merkle helpers unavailable")

    for fact in manifest["facts"]:
        json_path = VECTOR_DIR / fact["json_path"]
        cbor_path = VECTOR_DIR / fact["cbor_path"]
        expected = cbor_path.read_bytes()
        actual = bytes(ledger.canonicalize_json_to_cbor_bytes(json_path.read_bytes()))
        assert actual == expected
        leaves.append(actual)

    root_hex, leaf_hashes = merkle.merkle_root_hex_and_leaf_hashes(leaves)
    assert root_hex == manifest["merkle_root"]
    assert leaf_hashes == manifest["leaf_hashes"]
