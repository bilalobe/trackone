from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
VERIFIER_PATH = ROOT / "toolset" / "independent-verifier" / "verify_vector_corpus.py"
VECTOR_DIR = ROOT / "toolset" / "vectors" / "trackone-canonical-cbor-v1"

spec = importlib.util.spec_from_file_location(
    "trackone_independent_verifier", VERIFIER_PATH
)
assert spec is not None
verifier = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = verifier
spec.loader.exec_module(verifier)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _major(buf: bytearray, major: int, value: int) -> None:
    if value < 24:
        buf.append((major << 5) | value)
    elif value <= 0xFF:
        buf.extend(((major << 5) | 24, value))
    elif value <= 0xFFFF:
        buf.append((major << 5) | 25)
        buf.extend(value.to_bytes(2, "big"))
    elif value <= 0xFFFFFFFF:
        buf.append((major << 5) | 26)
        buf.extend(value.to_bytes(4, "big"))
    else:
        buf.append((major << 5) | 27)
        buf.extend(value.to_bytes(8, "big"))


def _encode_cbor(value: Any) -> bytes:
    buf = bytearray()

    def encode(item: Any) -> None:
        if item is None:
            buf.append(0xF6)
        elif item is False:
            buf.append(0xF4)
        elif item is True:
            buf.append(0xF5)
        elif isinstance(item, int):
            if item >= 0:
                _major(buf, 0, item)
            else:
                _major(buf, 1, -1 - item)
        elif isinstance(item, str):
            raw = item.encode("utf-8")
            _major(buf, 3, len(raw))
            buf.extend(raw)
        elif isinstance(item, list):
            _major(buf, 4, len(item))
            for child in item:
                encode(child)
        elif isinstance(item, dict):
            entries = []
            for key, child in item.items():
                key_bytes = key.encode("utf-8")
                entries.append((len(key_bytes), key_bytes, key, child))
            entries.sort(key=lambda entry: (entry[0], entry[1]))
            _major(buf, 5, len(entries))
            for _length, _raw, key, child in entries:
                encode(key)
                encode(child)
        else:
            raise TypeError(type(item).__name__)

    encode(value)
    return bytes(buf)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _copy_vector_dir(tmp_path: Path) -> Path:
    target = tmp_path / "vectors"
    shutil.copytree(VECTOR_DIR, target)
    return target


def _read_manifest(vector_dir: Path) -> dict[str, Any]:
    return json.loads((vector_dir / "manifest.json").read_text(encoding="utf-8"))


def test_cbor_decoder_rejects_non_shortest_integer_and_float_encodings() -> None:
    with pytest.raises(verifier.VerifyError, match="non-shortest CBOR integer"):
        verifier.CborDecoder(b"\x18\x01").decode()

    with pytest.raises(verifier.VerifyError, match="non-shortest CBOR float"):
        verifier.CborDecoder(b"\xfa\x3f\x80\x00\x00").decode()


def test_vector_manifest_fact_entries_are_exact_and_portable(tmp_path: Path) -> None:
    vector_dir = _copy_vector_dir(tmp_path)
    manifest = _read_manifest(vector_dir)
    manifest["facts"][0]["extra"] = "not-public-contract"
    _write_json(vector_dir / "manifest.json", manifest)

    with pytest.raises(verifier.VerifyError, match="fields do not match"):
        verifier.verify_vector_dir(vector_dir)

    vector_dir = _copy_vector_dir(tmp_path / "portable")
    manifest = _read_manifest(vector_dir)
    manifest["facts"][0]["json_path"] = "../fact-001.json"
    _write_json(vector_dir / "manifest.json", manifest)

    with pytest.raises(verifier.VerifyError, match="not portable"):
        verifier.verify_vector_dir(vector_dir)


def test_vector_fact_kind_must_match_public_schema_pattern(tmp_path: Path) -> None:
    vector_dir = _copy_vector_dir(tmp_path)
    manifest = _read_manifest(vector_dir)
    fact_path = vector_dir / manifest["facts"][0]["json_path"]
    fact = json.loads(fact_path.read_text(encoding="utf-8"))
    fact["kind"] = "Custom"
    _write_json(fact_path, fact)

    with pytest.raises(verifier.VerifyError, match="fact kind syntax"):
        verifier.verify_vector_dir(vector_dir)


def test_verification_manifest_rejects_non_schema_skipped_checks() -> None:
    digest = "a" * 64
    manifest = {
        "version": 1,
        "date": "2025-10-07",
        "site": "an-001",
        "device_id": "pod-001",
        "frame_count": 1,
        "facts_dir": "facts",
        "artifacts": {
            "block": {"path": "blocks/block.json", "sha256": digest},
            "day_cbor": {"path": "day/2025-10-07.cbor", "sha256": digest},
            "day_json": {"path": "day/2025-10-07.json", "sha256": digest},
            "day_sha256": {"path": "day/2025-10-07.sha256", "sha256": digest},
            "provisioning_input": {"path": "provisioning/input.json", "sha256": digest},
            "provisioning_records": {
                "path": "provisioning/records.json",
                "sha256": digest,
            },
            "sensorthings_projection": {
                "path": "sensorthings/projection.json",
                "sha256": digest,
            },
        },
        "anchoring": {},
        "verification_bundle": {
            "disclosure_class": "A",
            "commitment_profile_id": "trackone-canonical-cbor-v1",
            "checks_executed": ["day_artifact_validation"],
            "checks_skipped": ["ots_verification"],
        },
    }

    with pytest.raises(verifier.VerifyError, match="checks_skipped\\[0\\]"):
        verifier.validate_verification_manifest(manifest)


def test_bundle_fact_cbor_is_validated_without_json_projection(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    facts_dir = root / "facts"
    facts_dir.mkdir(parents=True)
    fact = {
        "pod_id": "pod-001",
        "fc": 1,
        "ingest_time": 1,
        "pod_time": None,
        "kind": "env.sample",
        "payload": {},
        "unexpected": True,
    }
    fact_cbor = _encode_cbor(fact)
    (facts_dir / "fact-001.cbor").write_bytes(fact_cbor)
    leaf_hash = _sha256(fact_cbor)
    merkle_root = verifier.merkle_root([leaf_hash])

    block = {
        "version": 1,
        "site_id": "an-001",
        "day": "2025-10-07",
        "batch_id": "an-001-2025-10-07-00",
        "merkle_root": merkle_root,
        "count": 1,
        "leaf_hashes": [leaf_hash],
    }
    day = {
        "version": 1,
        "site_id": "an-001",
        "date": "2025-10-07",
        "prev_day_root": "0" * 64,
        "batches": [block],
        "day_root": merkle_root,
    }
    day_cbor = _encode_cbor(day)

    artifacts = {
        "block": root / "blocks" / "block.json",
        "day_cbor": root / "day" / "2025-10-07.cbor",
        "day_json": root / "day" / "2025-10-07.json",
        "day_sha256": root / "day" / "2025-10-07.sha256",
        "provisioning_input": root / "provisioning" / "input.json",
        "provisioning_records": root / "provisioning" / "records.json",
        "sensorthings_projection": root / "sensorthings" / "projection.json",
    }
    _write_json(artifacts["block"], block)
    artifacts["day_cbor"].parent.mkdir(parents=True, exist_ok=True)
    artifacts["day_cbor"].write_bytes(day_cbor)
    _write_json(artifacts["day_json"], day)
    artifacts["day_sha256"].write_text(_sha256(day_cbor) + "  day/2025-10-07.cbor\n")
    _write_json(artifacts["provisioning_input"], {})
    _write_json(artifacts["provisioning_records"], {})
    _write_json(artifacts["sensorthings_projection"], {})

    manifest = {
        "version": 1,
        "date": "2025-10-07",
        "site": "an-001",
        "device_id": "pod-001",
        "frame_count": 1,
        "facts_dir": "facts",
        "artifacts": {
            name: {
                "path": str(path.relative_to(root)),
                "sha256": _sha256(path.read_bytes()),
            }
            for name, path in artifacts.items()
        },
        "anchoring": {},
        "verification_bundle": {
            "disclosure_class": "A",
            "commitment_profile_id": "trackone-canonical-cbor-v1",
            "checks_executed": ["day_artifact_validation"],
            "checks_skipped": [],
        },
    }
    _write_json(root / "day" / "2025-10-07.verify.json", manifest)

    with pytest.raises(verifier.VerifyError, match="unknown fields"):
        verifier.verify_bundle_dir(root)
