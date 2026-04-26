#!/usr/bin/env python3
"""Tiny independent verifier for TrackOne public evidence artifacts.

This script intentionally does not import TrackOne. It consumes the published
vector corpus or an exported evidence bundle and checks the public manifest,
CBOR bytes, SHA-256 digests, and ADR-003 Merkle root.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

COMMITMENT_PROFILE_ID = "trackone-canonical-cbor-v1"
CBOR_PROFILE = {
    "id": "trackone-deterministic-json-cbor-v1",
    "integer_encoding": "shortest-form",
    "float_encoding": "shortest-exact-float16-float32-float64",
    "map_key_order": "encoded-key-length-then-utf8-bytes",
    "non_finite_floats": "invalid",
}
MERKLE_POLICY = {
    "id": "trackone-adr003-sha256-hash-sorted-v1",
    "leaf_hash": "SHA-256(leaf_cbor_bytes)",
    "leaf_order": "lexicographic-raw-32-byte-hash",
    "parent_hash": "SHA-256(left || right)",
    "odd_leaf": "duplicate-last",
    "empty_root": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
PROFILE_CONSTRAINTS = {
    "integer_ranges": {
        "json_integer": "signed-or-unsigned-64-bit",
        "signed_min": -9223372036854775808,
        "unsigned_max": 18446744073709551615,
        "out_of_range": "invalid",
    },
    "timestamp_representation": {
        "fact_projection": "rfc3339-utc-z-text",
        "day_labels": "yyyy-mm-dd-utc-text",
        "runtime_fact_schema": "integer-unix-seconds-not-used-by-this-vector-projection",
    },
    "null_vs_absent": {
        "pod_time": "required-nullable",
        "optional_fields": "omit-when-unset",
        "null_encoding": "cbor-null-only-when-json-field-is-present-null",
    },
    "bytes_representation": {
        "artifact_files": "raw-bytes",
        "digests": "lowercase-hex-text",
        "json_projection_bytes": "not-used",
        "lower_level_bstr": "only-in-positional-runtime-cddl-shapes",
    },
    "unknown_fields": {
        "fact_projection_top_level": "reject",
        "block_header": "reject",
        "day_record": "reject",
        "manifest": "reject",
        "payload": "allow-json-values",
    },
}
FACT_FIELDS = {"pod_id", "fc", "ingest_time", "pod_time", "kind", "payload"}
BUNDLE_FACT_FIELDS = FACT_FIELDS | {"ingest_time_rfc3339_utc", "signature"}
BLOCK_FIELDS = {
    "version",
    "site_id",
    "day",
    "batch_id",
    "merkle_root",
    "count",
    "leaf_hashes",
}
DAY_FIELDS = {"version", "site_id", "date", "prev_day_root", "batches", "day_root"}
VERIFY_MANIFEST_REQUIRED_FIELDS = {
    "version",
    "date",
    "site",
    "device_id",
    "frame_count",
    "facts_dir",
    "artifacts",
    "anchoring",
    "verification_bundle",
}
VERIFY_MANIFEST_OPTIONAL_FIELDS = {"frames_file", "verifier"}
BUNDLE_REQUIRED_ARTIFACTS = {
    "block",
    "day_cbor",
    "day_json",
    "day_sha256",
    "provisioning_input",
    "provisioning_records",
    "sensorthings_projection",
}
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
RFC3339_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
UTC_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class VerifyError(Exception):
    pass


@dataclass
class CborDecoder:
    data: bytes
    offset: int = 0

    def decode(self) -> Any:
        value = self._item()
        if self.offset != len(self.data):
            raise VerifyError("trailing CBOR bytes")
        return value

    def _take(self, length: int) -> bytes:
        end = self.offset + length
        if end > len(self.data):
            raise VerifyError("truncated CBOR item")
        raw = self.data[self.offset : end]
        self.offset = end
        return raw

    def _initial(self) -> tuple[int, int]:
        if self.offset >= len(self.data):
            raise VerifyError("unexpected end of CBOR")
        first = self.data[self.offset]
        self.offset += 1
        return first >> 5, first & 0x1F

    def _uint_arg(self, addl: int) -> int:
        if addl < 24:
            return addl
        if addl == 24:
            return self._take(1)[0]
        if addl == 25:
            return int.from_bytes(self._take(2), "big")
        if addl == 26:
            return int.from_bytes(self._take(4), "big")
        if addl == 27:
            return int.from_bytes(self._take(8), "big")
        raise VerifyError("indefinite or reserved CBOR length is not allowed")

    def _item(self) -> Any:
        major, addl = self._initial()
        if major == 0:
            return self._uint_arg(addl)
        if major == 1:
            return -1 - self._uint_arg(addl)
        if major == 2:
            return self._take(self._uint_arg(addl))
        if major == 3:
            raw = self._take(self._uint_arg(addl))
            return raw.decode("utf-8")
        if major == 4:
            return [self._item() for _ in range(self._uint_arg(addl))]
        if major == 5:
            return self._map(self._uint_arg(addl))
        if major == 6:
            raise VerifyError("CBOR tags are not allowed")
        if major == 7:
            return self._simple(addl)
        raise VerifyError(f"unsupported CBOR major type {major}")

    def _map(self, length: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        prior_key_encoding: bytes | None = None
        for _ in range(length):
            key_start = self.offset
            key = self._item()
            key_encoding = self.data[key_start : self.offset]
            if not isinstance(key, str):
                raise VerifyError("only text-string map keys are supported")
            if prior_key_encoding is not None and (
                len(prior_key_encoding),
                prior_key_encoding,
            ) >= (len(key_encoding), key_encoding):
                raise VerifyError("CBOR map keys are not in deterministic order")
            prior_key_encoding = key_encoding
            if key in result:
                raise VerifyError(f"duplicate CBOR map key {key!r}")
            result[key] = self._item()
        return result

    def _simple(self, addl: int) -> Any:
        if addl == 20:
            return False
        if addl == 21:
            return True
        if addl == 22:
            return None
        if addl == 25:
            value = struct.unpack(">e", self._take(2))[0]
        elif addl == 26:
            value = struct.unpack(">f", self._take(4))[0]
        elif addl == 27:
            value = struct.unpack(">d", self._take(8))[0]
        else:
            raise VerifyError(f"unsupported CBOR simple value {addl}")
        if not math.isfinite(value):
            raise VerifyError("non-finite CBOR float is not allowed")
        return value


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> Any:
    def reject_constant(value: str) -> None:
        raise VerifyError(f"non-finite JSON value {value!r} is not allowed")

    try:
        return json.loads(
            path.read_text(encoding="utf-8"), parse_constant=reject_constant
        )
    except json.JSONDecodeError as exc:
        raise VerifyError(f"invalid JSON {path}: {exc}") from exc


def write_result(result: dict[str, Any], output: Path | None) -> None:
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload, encoding="utf-8")
    print(payload, end="")


def decode_cbor(path: Path) -> Any:
    return CborDecoder(path.read_bytes()).decode()


def merkle_root(leaf_hex: list[str]) -> str:
    if not leaf_hex:
        return MERKLE_POLICY["empty_root"]
    layer = sorted(bytes.fromhex(item) for item in leaf_hex)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [
            hashlib.sha256(layer[index] + layer[index + 1]).digest()
            for index in range(0, len(layer), 2)
        ]
    return layer[0].hex()


def assert_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise VerifyError(f"{label} mismatch: {actual!r} != {expected!r}")


def assert_hex64(value: Any, label: str) -> None:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise VerifyError(f"{label} must be lowercase hex64")


def assert_portable_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerifyError(f"{label} must be a non-empty relative path")
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise VerifyError(f"{label} is not portable: {value!r}")
    return value


def resolve_portable(root: Path, value: Any, label: str) -> Path:
    rel = assert_portable_path(value, label)
    path = (root / rel).resolve()
    root_resolved = root.resolve()
    try:
        path.relative_to(root_resolved)
    except ValueError:
        raise VerifyError(f"{label} escapes bundle root: {rel!r}") from None
    if not path.exists():
        raise VerifyError(f"{label} target does not exist: {rel!r}")
    return path


def validate_json_value(value: Any, label: str) -> None:
    if value is None or isinstance(value, bool | str):
        return
    if isinstance(value, int):
        if value < -(2**63) or value > 2**64 - 1:
            raise VerifyError(f"{label} integer out of profile range")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise VerifyError(f"{label} non-finite float is not allowed")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            validate_json_value(item, f"{label}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise VerifyError(f"{label} key is not text")
            validate_json_value(item, f"{label}.{key}")
        return
    raise VerifyError(f"{label} has unsupported JSON type {type(value).__name__}")


def validate_fact(fact: Any, label: str) -> None:
    if not isinstance(fact, dict):
        raise VerifyError(f"{label} must be a JSON object")
    if set(fact) != FACT_FIELDS:
        raise VerifyError(f"{label} fields mismatch: {sorted(fact)}")
    if not isinstance(fact["pod_id"], str) or not fact["pod_id"]:
        raise VerifyError(f"{label}.pod_id must be non-empty text")
    if (
        not isinstance(fact["fc"], int)
        or isinstance(fact["fc"], bool)
        or fact["fc"] < 0
    ):
        raise VerifyError(f"{label}.fc must be a non-negative integer")
    if not isinstance(fact["kind"], str) or not fact["kind"]:
        raise VerifyError(f"{label}.kind must be non-empty text")
    for field in ("ingest_time", "pod_time"):
        if field == "pod_time" and fact[field] is None:
            continue
        if not isinstance(fact[field], str) or not RFC3339_Z_RE.fullmatch(fact[field]):
            raise VerifyError(f"{label}.{field} must be RFC3339 UTC Z text")
    if not isinstance(fact["payload"], dict):
        raise VerifyError(f"{label}.payload must be an object")
    validate_json_value(fact["payload"], f"{label}.payload")


def validate_bundle_fact(fact: Any, label: str) -> None:
    if not isinstance(fact, dict):
        raise VerifyError(f"{label} must be a JSON object")
    missing = FACT_FIELDS - set(fact)
    if missing:
        raise VerifyError(f"{label} missing fields: {sorted(missing)}")
    unknown = set(fact) - BUNDLE_FACT_FIELDS
    if unknown:
        raise VerifyError(f"{label} unknown fields: {sorted(unknown)}")
    if not isinstance(fact["pod_id"], str) or not fact["pod_id"]:
        raise VerifyError(f"{label}.pod_id must be non-empty text")
    if (
        not isinstance(fact["fc"], int)
        or isinstance(fact["fc"], bool)
        or fact["fc"] < 0
    ):
        raise VerifyError(f"{label}.fc must be a non-negative integer")
    if not isinstance(fact["ingest_time"], int) or isinstance(
        fact["ingest_time"], bool
    ):
        raise VerifyError(f"{label}.ingest_time must be an integer timestamp")
    if fact["pod_time"] is not None and (
        not isinstance(fact["pod_time"], int) or isinstance(fact["pod_time"], bool)
    ):
        raise VerifyError(f"{label}.pod_time must be null or an integer timestamp")
    if not isinstance(fact["kind"], str) or not fact["kind"]:
        raise VerifyError(f"{label}.kind must be non-empty text")
    if not isinstance(fact["payload"], dict):
        raise VerifyError(f"{label}.payload must be an object")
    if "ingest_time_rfc3339_utc" in fact and (
        not isinstance(fact["ingest_time_rfc3339_utc"], str)
        or not fact["ingest_time_rfc3339_utc"]
    ):
        raise VerifyError(f"{label}.ingest_time_rfc3339_utc must be non-empty text")
    if "signature" in fact and (
        not isinstance(fact["signature"], str) or not fact["signature"]
    ):
        raise VerifyError(f"{label}.signature must be non-empty text")
    validate_json_value(fact, label)


def validate_block(block: Any, label: str) -> None:
    if not isinstance(block, dict) or set(block) != BLOCK_FIELDS:
        raise VerifyError(f"{label} fields mismatch")
    if block["version"] != 1:
        raise VerifyError(f"{label}.version must be 1")
    if not isinstance(block["site_id"], str) or not block["site_id"]:
        raise VerifyError(f"{label}.site_id must be non-empty text")
    if not isinstance(block["day"], str) or not UTC_DAY_RE.fullmatch(block["day"]):
        raise VerifyError(f"{label}.day must be yyyy-mm-dd")
    if not isinstance(block["batch_id"], str) or not block["batch_id"]:
        raise VerifyError(f"{label}.batch_id must be non-empty text")
    assert_hex64(block["merkle_root"], f"{label}.merkle_root")
    if not isinstance(block["count"], int) or block["count"] < 0:
        raise VerifyError(f"{label}.count must be non-negative")
    if not isinstance(block["leaf_hashes"], list):
        raise VerifyError(f"{label}.leaf_hashes must be an array")
    if block["count"] != len(block["leaf_hashes"]):
        raise VerifyError(f"{label}.count must equal leaf_hashes length")
    for index, item in enumerate(block["leaf_hashes"]):
        assert_hex64(item, f"{label}.leaf_hashes[{index}]")
    if block["leaf_hashes"] != sorted(block["leaf_hashes"]):
        raise VerifyError(f"{label}.leaf_hashes must be sorted")
    if merkle_root(block["leaf_hashes"]) != block["merkle_root"]:
        raise VerifyError(f"{label}.merkle_root does not match leaf_hashes")


def validate_day(day: Any, label: str) -> None:
    if not isinstance(day, dict) or set(day) != DAY_FIELDS:
        raise VerifyError(f"{label} fields mismatch")
    if day["version"] != 1:
        raise VerifyError(f"{label}.version must be 1")
    if not isinstance(day["site_id"], str) or not day["site_id"]:
        raise VerifyError(f"{label}.site_id must be non-empty text")
    if not isinstance(day["date"], str) or not UTC_DAY_RE.fullmatch(day["date"]):
        raise VerifyError(f"{label}.date must be yyyy-mm-dd")
    assert_hex64(day["prev_day_root"], f"{label}.prev_day_root")
    assert_hex64(day["day_root"], f"{label}.day_root")
    if not isinstance(day["batches"], list):
        raise VerifyError(f"{label}.batches must be an array")
    all_leaf_hashes: list[str] = []
    for index, block in enumerate(day["batches"]):
        validate_block(block, f"{label}.batches[{index}]")
        all_leaf_hashes.extend(block["leaf_hashes"])
    if merkle_root(all_leaf_hashes) != day["day_root"]:
        raise VerifyError(f"{label}.day_root does not match batch leaves")


def validate_manifest(manifest: Any) -> None:
    expected_keys = {
        "version",
        "commitment_profile_id",
        "cbor_profile",
        "merkle_policy",
        "profile_constraints",
        "manifest_schema",
        "fact_json_schema",
        "cddl_profile",
        "fact_cbor_shape",
        "day_record_cbor_shape",
        "site_id",
        "date",
        "batch_id",
        "facts",
        "leaf_hashes",
        "merkle_root",
        "prev_day_root",
        "block_header_path",
        "day_record_json_path",
        "day_record_cbor_path",
        "day_cbor_sha256",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_keys:
        raise VerifyError("manifest fields do not match public contract")
    assert_equal(manifest["version"], 1, "manifest.version")
    assert_equal(manifest["commitment_profile_id"], COMMITMENT_PROFILE_ID, "profile id")
    assert_equal(manifest["cbor_profile"], CBOR_PROFILE, "cbor_profile")
    assert_equal(manifest["merkle_policy"], MERKLE_POLICY, "merkle_policy")
    assert_equal(
        manifest["profile_constraints"], PROFILE_CONSTRAINTS, "profile_constraints"
    )
    assert_equal(
        manifest["manifest_schema"],
        "toolset/unified/schemas/commitment_vector_manifest.schema.json",
        "manifest_schema",
    )
    assert_equal(
        manifest["fact_json_schema"],
        "toolset/unified/schemas/commitment_fact_projection.schema.json",
        "fact_json_schema",
    )
    assert_equal(
        manifest["cddl_profile"],
        "toolset/unified/cddl/commitment-artifacts-v1.cddl",
        "cddl_profile",
    )
    assert_equal(manifest["fact_cbor_shape"], "fact-json-projection-v1", "fact shape")
    assert_equal(manifest["day_record_cbor_shape"], "day-record-v1", "day shape")
    if not isinstance(manifest["facts"], list) or not manifest["facts"]:
        raise VerifyError("manifest.facts must be a non-empty array")
    for item in manifest["leaf_hashes"]:
        assert_hex64(item, "manifest.leaf_hashes[]")
    assert_hex64(manifest["merkle_root"], "manifest.merkle_root")
    assert_hex64(manifest["prev_day_root"], "manifest.prev_day_root")
    assert_hex64(manifest["day_cbor_sha256"], "manifest.day_cbor_sha256")


def validate_verification_manifest(manifest: Any) -> None:
    allowed_fields = VERIFY_MANIFEST_REQUIRED_FIELDS | VERIFY_MANIFEST_OPTIONAL_FIELDS
    if not isinstance(manifest, dict):
        raise VerifyError("verification manifest must be a JSON object")
    if not VERIFY_MANIFEST_REQUIRED_FIELDS.issubset(manifest):
        missing = sorted(VERIFY_MANIFEST_REQUIRED_FIELDS - set(manifest))
        raise VerifyError(f"verification manifest missing fields: {missing}")
    unknown = sorted(set(manifest) - allowed_fields)
    if unknown:
        raise VerifyError(f"verification manifest has unknown fields: {unknown}")
    assert_equal(manifest["version"], 1, "verification manifest version")
    if not isinstance(manifest["date"], str) or not UTC_DAY_RE.fullmatch(
        manifest["date"]
    ):
        raise VerifyError("verification manifest date must be yyyy-mm-dd")
    if not isinstance(manifest["site"], str) or not manifest["site"]:
        raise VerifyError("verification manifest site must be non-empty text")
    if not isinstance(manifest["device_id"], str) or not manifest["device_id"]:
        raise VerifyError("verification manifest device_id must be non-empty text")
    if (
        not isinstance(manifest["frame_count"], int)
        or isinstance(manifest["frame_count"], bool)
        or manifest["frame_count"] < 0
    ):
        raise VerifyError("verification manifest frame_count must be non-negative")
    assert_portable_path(manifest["facts_dir"], "facts_dir")
    if "frames_file" in manifest:
        assert_portable_path(manifest["frames_file"], "frames_file")

    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, dict):
        raise VerifyError("verification manifest artifacts must be an object")
    missing_artifacts = sorted(BUNDLE_REQUIRED_ARTIFACTS - set(artifacts))
    if missing_artifacts:
        raise VerifyError(
            f"verification manifest missing artifacts: {missing_artifacts}"
        )
    for name, artifact in artifacts.items():
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
            raise VerifyError(f"artifact {name!r} must contain path and sha256 only")
        assert_portable_path(artifact["path"], f"artifacts.{name}.path")
        assert_hex64(artifact["sha256"], f"artifacts.{name}.sha256")

    bundle = manifest["verification_bundle"]
    if not isinstance(bundle, dict):
        raise VerifyError("verification_bundle must be an object")
    if bundle.get("commitment_profile_id") != COMMITMENT_PROFILE_ID:
        raise VerifyError("unsupported commitment_profile_id")
    if bundle.get("disclosure_class") != "A":
        raise VerifyError("independent bundle verifier requires disclosure_class A")
    checks_executed = bundle.get("checks_executed")
    checks_skipped = bundle.get("checks_skipped")
    if not isinstance(checks_executed, list) or not all(
        isinstance(item, str) and item for item in checks_executed
    ):
        raise VerifyError("checks_executed must be a non-empty string array")
    if not isinstance(checks_skipped, list):
        raise VerifyError("checks_skipped must be an array")


def verify_artifact_refs(
    bundle_root: Path, manifest: dict[str, Any]
) -> dict[str, Path]:
    resolved: dict[str, Path] = {}
    for name, artifact in manifest["artifacts"].items():
        path = resolve_portable(bundle_root, artifact["path"], f"artifacts.{name}.path")
        digest = sha256_hex(path.read_bytes())
        assert_equal(digest, artifact["sha256"], f"artifacts.{name}.sha256")
        resolved[name] = path
    return resolved


def read_declared_sha256(path: Path) -> str:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise VerifyError(f"empty sha256 sidecar: {path}")
    digest = text.split()[0]
    assert_hex64(digest, f"{path}.sha256")
    return digest


def verify_vector_dir(vector_dir: Path) -> dict[str, Any]:
    manifest = read_json(vector_dir / "manifest.json")
    validate_manifest(manifest)

    computed_leaf_hashes: list[str] = []
    for vector in manifest["facts"]:
        for field in ("name", "json_path", "cbor_path", "cbor_sha256"):
            if field not in vector:
                raise VerifyError(f"fact vector missing {field}")
        fact_json = read_json(vector_dir / vector["json_path"])
        validate_fact(fact_json, vector["name"])
        fact_cbor_path = vector_dir / vector["cbor_path"]
        fact_cbor_bytes = fact_cbor_path.read_bytes()
        fact_sha = sha256_hex(fact_cbor_bytes)
        assert_equal(fact_sha, vector["cbor_sha256"], f"{vector['name']} cbor sha")
        decoded_fact = decode_cbor(fact_cbor_path)
        assert_equal(decoded_fact, fact_json, f"{vector['name']} CBOR decode")
        computed_leaf_hashes.append(fact_sha)

    expected_leaf_hashes = sorted(computed_leaf_hashes)
    assert_equal(manifest["leaf_hashes"], expected_leaf_hashes, "leaf hashes")
    assert_equal(
        merkle_root(computed_leaf_hashes), manifest["merkle_root"], "merkle root"
    )

    block = read_json(vector_dir / manifest["block_header_path"])
    validate_block(block, "block header")
    assert_equal(block["leaf_hashes"], expected_leaf_hashes, "block leaf_hashes")
    assert_equal(block["merkle_root"], manifest["merkle_root"], "block merkle_root")

    day_json = read_json(vector_dir / manifest["day_record_json_path"])
    validate_day(day_json, "day record")
    decoded_day = decode_cbor(vector_dir / manifest["day_record_cbor_path"])
    assert_equal(decoded_day, day_json, "day CBOR decode")
    assert_equal(day_json["day_root"], manifest["merkle_root"], "day_root")
    assert_equal(day_json["prev_day_root"], manifest["prev_day_root"], "prev_day_root")
    day_cbor_sha = sha256_hex(
        (vector_dir / manifest["day_record_cbor_path"]).read_bytes()
    )
    assert_equal(day_cbor_sha, manifest["day_cbor_sha256"], "day cbor sha")

    return {
        "ok": True,
        "commitment_profile_id": manifest["commitment_profile_id"],
        "facts": len(manifest["facts"]),
        "merkle_root": manifest["merkle_root"],
        "day_cbor_sha256": manifest["day_cbor_sha256"],
    }


def verify_bundle_dir(bundle_root: Path) -> dict[str, Any]:
    manifests = sorted((bundle_root / "day").glob("*.verify.json"))
    if len(manifests) != 1:
        raise VerifyError(
            f"expected exactly one day/*.verify.json file, found {len(manifests)}"
        )

    manifest = read_json(manifests[0])
    validate_verification_manifest(manifest)
    artifact_paths = verify_artifact_refs(bundle_root, manifest)

    facts_dir = resolve_portable(bundle_root, manifest["facts_dir"], "facts_dir")
    if not facts_dir.is_dir():
        raise VerifyError("facts_dir must resolve to a directory")
    fact_files = sorted(facts_dir.glob("*.cbor"))
    if not fact_files:
        raise VerifyError("no disclosed fact CBOR files found")
    if manifest["frame_count"] != len(fact_files):
        raise VerifyError("frame_count does not match disclosed fact CBOR count")

    leaf_hashes: list[str] = []
    for fact_path in fact_files:
        fact_bytes = fact_path.read_bytes()
        fact_sha = sha256_hex(fact_bytes)
        decoded_fact = decode_cbor(fact_path)
        json_path = fact_path.with_suffix(".json")
        if json_path.exists():
            fact_json = read_json(json_path)
            validate_bundle_fact(fact_json, json_path.name)
            assert_equal(decoded_fact, fact_json, f"{fact_path.name} CBOR decode")
        leaf_hashes.append(fact_sha)

    expected_leaf_hashes = sorted(leaf_hashes)
    root = merkle_root(leaf_hashes)

    block = read_json(artifact_paths["block"])
    validate_block(block, "bundle block header")
    assert_equal(block["day"], manifest["date"], "block day")
    assert_equal(block["site_id"], manifest["site"], "block site")
    assert_equal(block["leaf_hashes"], expected_leaf_hashes, "block leaf_hashes")
    assert_equal(block["merkle_root"], root, "block merkle_root")

    day_json = read_json(artifact_paths["day_json"])
    validate_day(day_json, "bundle day record")
    day_cbor = decode_cbor(artifact_paths["day_cbor"])
    assert_equal(day_cbor, day_json, "day CBOR decode")
    assert_equal(day_json["date"], manifest["date"], "day date")
    assert_equal(day_json["site_id"], manifest["site"], "day site")
    assert_equal(day_json["day_root"], root, "day_root")

    day_cbor_sha = sha256_hex(artifact_paths["day_cbor"].read_bytes())
    assert_equal(
        read_declared_sha256(artifact_paths["day_sha256"]),
        day_cbor_sha,
        "day sha256 sidecar",
    )

    if "day_ots_meta" in artifact_paths:
        meta = read_json(artifact_paths["day_ots_meta"])
        if not isinstance(meta, dict):
            raise VerifyError("day_ots_meta must be a JSON object")
        if "artifact" in meta:
            assert_equal(
                meta["artifact"],
                manifest["artifacts"]["day_cbor"]["path"],
                "OTS artifact path",
            )
        if "ots_proof" in meta and "day_ots" in manifest["artifacts"]:
            assert_equal(
                meta["ots_proof"],
                manifest["artifacts"]["day_ots"]["path"],
                "OTS proof path",
            )

    return {
        "ok": True,
        "kind": "evidence-bundle",
        "commitment_profile_id": manifest["verification_bundle"][
            "commitment_profile_id"
        ],
        "bundle_root": str(bundle_root),
        "date": manifest["date"],
        "site": manifest["site"],
        "facts": len(fact_files),
        "merkle_root": root,
        "day_cbor_sha256": day_cbor_sha,
        "manifest": str(manifests[0].relative_to(bundle_root)),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("vector_dir", type=Path, nargs="?")
    parser.add_argument("--bundle-root", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.bundle_root is not None:
            result = verify_bundle_dir(args.bundle_root)
        elif args.vector_dir is not None:
            result = verify_vector_dir(args.vector_dir)
        else:
            raise VerifyError("provide vector_dir or --bundle-root")
    except Exception as exc:
        result = {"ok": False, "error": str(exc)}
        if args.output is not None:
            write_result(result, args.output)
        print(json.dumps(result, indent=2), file=sys.stderr)
        return 1
    write_result(result, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
