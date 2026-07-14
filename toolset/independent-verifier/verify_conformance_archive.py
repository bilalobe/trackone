#!/usr/bin/env python3
"""Detached, standard-library verifier for TrackOne conformance archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urldefrag


ARCHIVE_SCHEMA = "trackone-conformance-archive-v2"
ARTIFACT_TYPE = "application/vnd.trackone.conformance.archive.v2+tar"
PROVIDER = (
    "https://raw.githubusercontent.com/bilalobe/trackone/"
    "main/toolset/unified/schemas/"
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
V2_VECTOR_SCHEMA = "trackone-v2-vector-manifest-2"


class VerifyError(RuntimeError):
    pass


class CborDecoder:
    """Decoder for the deterministic JSON/CBOR subset used by v1 vectors."""

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def decode(self) -> Any:
        value = self.item()
        if self.offset != len(self.data):
            raise VerifyError("trailing CBOR bytes")
        return value

    def take(self, length: int) -> bytes:
        end = self.offset + length
        if end > len(self.data):
            raise VerifyError("truncated CBOR item")
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def uint_arg(self, additional: int) -> int:
        if additional < 24:
            return additional
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        if additional not in sizes:
            raise VerifyError("indefinite or reserved CBOR length")
        size = sizes[additional]
        value = int.from_bytes(self.take(size), "big")
        minimum = {1: 24, 2: 0x100, 4: 0x1_0000, 8: 0x1_0000_0000}[size]
        if value < minimum:
            raise VerifyError("non-shortest CBOR integer or length")
        return value

    def item(self) -> Any:
        if self.offset >= len(self.data):
            raise VerifyError("unexpected end of CBOR")
        initial = self.data[self.offset]
        self.offset += 1
        major, additional = initial >> 5, initial & 0x1F
        if major == 0:
            return self.uint_arg(additional)
        if major == 1:
            return -1 - self.uint_arg(additional)
        if major == 2:
            return self.take(self.uint_arg(additional))
        if major == 3:
            return self.take(self.uint_arg(additional)).decode("utf-8")
        if major == 4:
            return [self.item() for _ in range(self.uint_arg(additional))]
        if major == 5:
            return self.map(self.uint_arg(additional))
        if major == 6:
            raise VerifyError("CBOR tags are not allowed")
        if major == 7:
            return self.simple(additional)
        raise VerifyError(f"unsupported CBOR major type {major}")

    def map(self, length: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        previous: bytes | None = None
        for _ in range(length):
            start = self.offset
            key = self.item()
            encoded = self.data[start : self.offset]
            if not isinstance(key, str):
                raise VerifyError("v1 CBOR map key is not text")
            if previous is not None and (len(previous), previous) >= (len(encoded), encoded):
                raise VerifyError("v1 CBOR map keys are not in deterministic order")
            if key in result:
                raise VerifyError(f"duplicate v1 CBOR map key: {key}")
            previous = encoded
            result[key] = self.item()
        return result

    def simple(self, additional: int) -> Any:
        if additional == 20:
            return False
        if additional == 21:
            return True
        if additional == 22:
            return None
        formats = {25: (">e", 2), 26: (">f", 4), 27: (">d", 8)}
        if additional not in formats:
            raise VerifyError(f"unsupported CBOR simple value {additional}")
        format_name, size = formats[additional]
        value = struct.unpack(format_name, self.take(size))[0]
        if not math.isfinite(value):
            raise VerifyError("non-finite CBOR float")
        if additional == 26:
            try:
                half_roundtrip = struct.unpack(">e", struct.pack(">e", value))[0]
            except OverflowError:
                half_roundtrip = None
            if half_roundtrip == value:
                raise VerifyError("non-shortest CBOR float")
        if additional == 27:
            for shorter in (">e", ">f"):
                try:
                    roundtrip = struct.unpack(shorter, struct.pack(shorter, value))[0]
                except OverflowError:
                    continue
                if roundtrip == value:
                    raise VerifyError("non-shortest CBOR float")
        return value


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerifyError(f"cannot read JSON {path}: {exc}") from exc


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def portable(root: Path, relative: Any, label: str, *, directory: bool = False) -> Path:
    if not isinstance(relative, str) or not relative:
        raise VerifyError(f"{label} must be a non-empty relative path")
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise VerifyError(f"{label} is not portable: {relative!r}")
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise VerifyError(f"{label} escapes the archive root") from exc
    if not resolved.exists() or (directory and not resolved.is_dir()):
        raise VerifyError(f"{label} target is missing: {relative}")
    return resolved


def extract_archive(archive: Path, destination: Path) -> Path:
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise VerifyError(f"unsafe tar member: {member.name!r}")
            if not (member.isdir() or member.isfile()):
                raise VerifyError(f"unsupported tar member type: {member.name!r}")
        bundle.extractall(destination, filter="data")
    roots = sorted(item for item in destination.iterdir() if item.is_dir())
    if len(roots) != 1:
        raise VerifyError(f"archive must contain exactly one root directory, found {len(roots)}")
    return roots[0]


def verify_checksums(root: Path) -> int:
    sums_path = root / "SHA256SUMS"
    if not sums_path.is_file():
        raise VerifyError("SHA256SUMS is missing")
    declared: dict[str, str] = {}
    for line_number, line in enumerate(
        sums_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise VerifyError(f"invalid SHA256SUMS line {line_number}")
        digest, relative = match.groups()
        if relative in declared:
            raise VerifyError(f"duplicate SHA256SUMS path: {relative}")
        path = portable(root, relative, f"SHA256SUMS line {line_number}")
        if not path.is_file() or path.is_symlink():
            raise VerifyError(f"checksum target is not a regular file: {relative}")
        actual = sha256(path)
        if actual != digest:
            raise VerifyError(f"SHA-256 mismatch for {relative}: {actual} != {digest}")
        declared[relative] = digest
    actual_files = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    if set(declared) != actual_files:
        missing = sorted(actual_files - set(declared))
        stale = sorted(set(declared) - actual_files)
        raise VerifyError(f"SHA256SUMS coverage mismatch; missing={missing}, stale={stale}")
    return len(declared)


def walk_refs(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        if isinstance(value.get("$ref"), str):
            yield value["$ref"]
        for child in value.values():
            yield from walk_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_refs(child)


def verify_schema_catalog(root: Path, manifest: dict[str, Any]) -> int:
    catalog_path = portable(root, manifest["contents"]["schema_catalog"], "schema catalog")
    catalog = read_json(catalog_path)
    if catalog.get("schema") != "trackone-schema-catalog-v1":
        raise VerifyError("schema catalog token mismatch")
    if catalog.get("provider") != PROVIDER:
        raise VerifyError("schema catalog provider mismatch")
    resources = {**catalog.get("resources", {}), **catalog.get("urn_resources", {})}
    schemas: dict[str, Any] = {}
    for schema_id, relative in resources.items():
        path = portable(catalog_path.parent, relative, f"schema {schema_id}")
        schema = read_json(path)
        if schema.get("$id") != schema_id:
            raise VerifyError(f"catalog $id mismatch for {relative}")
        if "example.org" in json.dumps(schema, sort_keys=True):
            raise VerifyError(f"placeholder provider remains in {relative}")
        schemas[schema_id] = schema
    for schema_id, schema in schemas.items():
        for ref in walk_refs(schema):
            target, _fragment = urldefrag(ref)
            if target and not target.startswith("https://json-schema.org/") and target not in schemas:
                raise VerifyError(f"schema {schema_id} has dangling offline $ref {ref}")
    return len(schemas)


def v1_merkle(hashes: list[str]) -> str:
    if not hashes:
        return hashlib.sha256(b"").hexdigest()
    layer = sorted(bytes.fromhex(item) for item in hashes)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [
            hashlib.sha256(layer[index] + layer[index + 1]).digest()
            for index in range(0, len(layer), 2)
        ]
    return layer[0].hex()


def verify_v1_vectors(vector_root: Path) -> int:
    manifest = read_json(vector_root / "manifest.json")
    if manifest.get("commitment_profile_id") != "verifiable-telemetry-canonical-cbor-v1":
        raise VerifyError("v1 commitment profile mismatch")
    hashes: list[str] = []
    for item in manifest.get("facts", []):
        cbor_path = portable(vector_root, item.get("cbor_path"), "v1 fact CBOR")
        json_path = portable(vector_root, item.get("json_path"), "v1 fact JSON")
        digest = sha256(cbor_path)
        if digest != item.get("cbor_sha256"):
            raise VerifyError(f"v1 fact digest mismatch: {cbor_path.name}")
        decoded = CborDecoder(cbor_path.read_bytes()).decode()
        if decoded != read_json(json_path):
            raise VerifyError(f"v1 CBOR/JSON projection mismatch: {cbor_path.name}")
        hashes.append(digest)
    if not hashes or sorted(hashes) != manifest.get("leaf_hashes"):
        raise VerifyError("v1 leaf hash set mismatch")
    if v1_merkle(hashes) != manifest.get("merkle_root"):
        raise VerifyError("v1 Merkle root mismatch")
    day_path = portable(vector_root, manifest.get("day_record_cbor_path"), "v1 day CBOR")
    if sha256(day_path) != manifest.get("day_cbor_sha256"):
        raise VerifyError("v1 day CBOR digest mismatch")
    day_json = portable(vector_root, manifest.get("day_record_json_path"), "v1 day JSON")
    if CborDecoder(day_path.read_bytes()).decode() != read_json(day_json):
        raise VerifyError("v1 day CBOR/JSON projection mismatch")
    return len(hashes)


def v2_tree(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + v2_tree(leaves[:split]) + v2_tree(leaves[split:])).digest()


def verify_v2_vectors(vector_root: Path) -> int:
    manifest = read_json(vector_root / "manifest.json")
    if manifest.get("schema") != V2_VECTOR_SCHEMA:
        raise VerifyError("v2 vector schema token mismatch")
    if manifest.get("commitment_profile_id") != "verifiable-telemetry-canonical-cbor-v2":
        raise VerifyError("v2 commitment profile mismatch")
    leaves: list[bytes] = []
    for index, record in enumerate(manifest.get("records", [])):
        try:
            cbor = bytes.fromhex(record["cbor_hex"])
        except (KeyError, ValueError) as exc:
            raise VerifyError(f"invalid v2 CBOR hex at record {index}") from exc
        leaf = hashlib.sha256(b"\x00" + cbor).digest()
        if leaf.hex() != record.get("leaf_sha256"):
            raise VerifyError(f"v2 leaf digest mismatch at record {index}")
        leaves.append(leaf)
    if not leaves:
        raise VerifyError("v2 vector set is empty")
    leaves.sort()
    if v2_tree(leaves).hex() != manifest.get("segment_root"):
        raise VerifyError("v2 segment root mismatch")
    return len(leaves)


def verify_v2_bundles(vector_root: Path, binary: Path) -> int:
    cases = read_json(vector_root / "cases.json")
    if cases.get("schema") != "trackone-v2-bundle-cases-1":
        raise VerifyError("v2 bundle case schema token mismatch")
    count = 0
    for case in cases.get("cases", []):
        fixture = portable(
            vector_root,
            case.get("path"),
            f"v2 bundle {case.get('id')}",
            directory=True,
        )
        completed = subprocess.run(
            [str(binary), "verify-v2", "--root", str(fixture), "--json"],
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
        succeeded = completed.returncode == 0
        if succeeded != case.get("expect_success"):
            raise VerifyError(
                f"v2 bundle {case.get('id')} exit mismatch: {completed.returncode}\n"
                f"{completed.stdout}{completed.stderr}"
            )
        if succeeded:
            expected = read_json(portable(fixture, case.get("expected_result"), "v2 expected result"))
            try:
                actual = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                raise VerifyError(f"v2 bundle {case.get('id')} emitted invalid JSON") from exc
            if actual != expected:
                raise VerifyError(f"v2 bundle {case.get('id')} result drifted")
        else:
            expected = read_json(portable(fixture, case.get("expected_error"), "v2 expected error"))
            if expected.get("error_contains") not in completed.stderr:
                raise VerifyError(f"v2 bundle {case.get('id')} diagnostic drifted")
        count += 1
    if count == 0:
        raise VerifyError("v2 detached bundle corpus is empty")
    return count


def verify_negative_fixtures(root: Path, manifest: dict[str, Any]) -> int:
    vector_root = portable(root, manifest["contents"]["vectors"], "vectors", directory=True)
    corpus = vector_root / "trackone-beta-negative-v1"
    cases = read_json(corpus / "cases.json")
    if cases.get("schema") != "trackone-beta-negative-fixtures-v1":
        raise VerifyError("negative fixture schema token mismatch")
    binary = portable(root, manifest["contents"]["detached_verifier"], "detached verifier")
    if not os.access(binary, os.X_OK):
        raise VerifyError("detached verifier is not executable")
    count = 0
    for case in cases.get("cases", []):
        fixture = portable(corpus, case.get("path"), f"negative fixture {case.get('id')}", directory=True)
        command = [
            str(binary),
            "verify",
            "--root",
            str(fixture),
            "--facts",
            str(fixture / "facts"),
            "--json",
            "--policy-mode",
            case["policy_mode"],
            "--disclosure-class",
            case["disclosure_class"],
        ]
        completed = subprocess.run(command, text=True, capture_output=True, timeout=60, check=False)
        output = completed.stdout + completed.stderr
        succeeded = completed.returncode == 0
        if succeeded != case.get("expect_success"):
            raise VerifyError(
                f"negative fixture {case.get('id')} exit mismatch: {completed.returncode}\n{output}"
            )
        if case.get("expect_contains") not in output:
            raise VerifyError(
                f"negative fixture {case.get('id')} diagnostic mismatch; expected "
                f"{case.get('expect_contains')!r}"
            )
        count += 1
    if count == 0:
        raise VerifyError("negative fixture corpus is empty")
    return count


def verify_root(root: Path) -> dict[str, Any]:
    if root.is_symlink():
        raise VerifyError("archive root must not be a symlink")
    checksummed_files = verify_checksums(root)
    manifest = read_json(root / "conformance-manifest.json")
    if manifest.get("schema") != ARCHIVE_SCHEMA or manifest.get("version") != 2:
        raise VerifyError("conformance archive manifest version mismatch")
    if manifest.get("schema_uri") != f"{PROVIDER}conformance_archive_manifest_v2.schema.json":
        raise VerifyError("conformance archive schema URI mismatch")
    if manifest.get("carrier", {}).get("artifact_type") != ARTIFACT_TYPE:
        raise VerifyError("conformance archive media type mismatch")
    claims = manifest.get("claims", {})
    expected_claims = {
        "canonical_cbor_v1_vectors": True,
        "canonical_cbor_v2_preview_vectors": True,
        "v2_full_conformance": False,
        "negative_fixture_floor": True,
        "offline_schema_resolution": True,
    }
    if claims != expected_claims:
        raise VerifyError("conformance claim set mismatch")
    schemas = verify_schema_catalog(root, manifest)
    vectors = portable(root, manifest["contents"]["vectors"], "vectors", directory=True)
    v1_records = verify_v1_vectors(vectors / "verifiable-telemetry-canonical-cbor-v1")
    v2_root = vectors / "verifiable-telemetry-canonical-cbor-v2"
    v2_records = verify_v2_vectors(v2_root)
    binary = portable(root, manifest["contents"]["detached_verifier"], "detached verifier")
    v2_bundles = verify_v2_bundles(v2_root, binary)
    negative_cases = verify_negative_fixtures(root, manifest)
    return {
        "ok": True,
        "schema": ARCHIVE_SCHEMA,
        "subject": manifest["subject"],
        "checksummed_files": checksummed_files,
        "schemas": schemas,
        "v1_records": v1_records,
        "v2_records": v2_records,
        "v2_bundles": v2_bundles,
        "negative_cases": negative_cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--root", type=Path)
    source.add_argument("--archive", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.archive:
            with tempfile.TemporaryDirectory(prefix="trackone-conformance-verify-") as temp:
                root = extract_archive(args.archive.resolve(), Path(temp))
                result = verify_root(root)
        else:
            result = verify_root(args.root.resolve())
    except Exception as exc:
        result = {"ok": False, "error": str(exc)}
        payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(payload, encoding="utf-8")
        print(payload, file=sys.stderr, end="")
        return 1
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
