#!/usr/bin/env python3
"""Detached, standard-library verifier for TrackOne conformance archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urldefrag


ARCHIVE_SCHEMA = "trackone-conformance-archive"
ARTIFACT_TYPE = "application/vnd.trackone.conformance.archive+tar"
PROVIDER = (
    "https://raw.githubusercontent.com/bilalobe/trackone/"
    "main/toolset/unified/schemas/"
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VTL_KNOWN_ANSWER_VECTORS = "vtl-known-answer"


class VerifyError(RuntimeError):
    pass


class CborDecoder:
    """Decoder for the deterministic CBOR subset used by the VTL vector."""

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
                raise VerifyError("CBOR map key is not text")
            if previous is not None and (len(previous), previous) >= (len(encoded), encoded):
                raise VerifyError("CBOR map keys are not in deterministic order")
            if key in result:
                raise VerifyError(f"duplicate CBOR map key: {key}")
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


def vtl_tree(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(
        b"\x01" + vtl_tree(leaves[:split]) + vtl_tree(leaves[split:])
    ).digest()


def verify_vtl_known_answer(vector_root: Path) -> dict[str, Any]:
    vector = read_json(vector_root / "vector.json")
    profile = "c08ade4e-1785-4eb6-9648-b7003d76288d"
    if vector.get("commitment_profile_id") != profile:
        raise VerifyError("VTL known-answer profile UUID mismatch")
    try:
        records = [bytes.fromhex(item) for item in vector["records_cbor_hex"]]
        segment_bytes = bytes.fromhex(vector["segment_cbor_hex"])
    except (KeyError, TypeError, ValueError) as exc:
        raise VerifyError("VTL known-answer vector contains invalid hexadecimal") from exc
    leaves = sorted(hashlib.sha256(b"\x00" + record).digest() for record in records)
    segment_root = vtl_tree(leaves)
    if segment_root.hex() != vector.get("segment_root"):
        raise VerifyError("VTL known-answer segment root mismatch")
    batch_limit = vector.get("batch_record_limit")
    if not isinstance(batch_limit, int) or batch_limit <= 0:
        raise VerifyError("VTL known-answer batch limit is invalid")
    batch_roots = [
        vtl_tree(leaves[index : index + batch_limit])
        for index in range(0, len(leaves), batch_limit)
    ]
    if [item.hex() for item in batch_roots] != vector.get("batch_roots"):
        raise VerifyError("VTL known-answer batch roots mismatch")
    if vtl_tree(batch_roots) != segment_root:
        raise VerifyError("VTL aligned batch composition mismatch")
    if len(segment_bytes) != vector.get("segment_cbor_length"):
        raise VerifyError("VTL segment length mismatch")
    if hashlib.sha256(segment_bytes).hexdigest() != vector.get("segment_cbor_sha256"):
        raise VerifyError("VTL segment digest mismatch")
    segment = CborDecoder(segment_bytes).decode()
    if not isinstance(segment, dict) or segment.get("version") != 1:
        raise VerifyError("VTL segment version mismatch")
    if segment.get("commitment_profile_id") != profile:
        raise VerifyError("VTL segment profile UUID mismatch")
    if segment.get("record_count") != len(records):
        raise VerifyError("VTL segment record count mismatch")
    if segment.get("segment_root") != segment_root:
        raise VerifyError("VTL segment root field mismatch")
    if segment.get("batch_roots") != batch_roots:
        raise VerifyError("VTL segment batch roots field mismatch")
    if [item.hex() for item in leaves] != vector.get("sorted_leaf_hashes"):
        raise VerifyError("VTL known-answer sorted leaf hashes mismatch")
    verify_vtl_distinct_encodings(vector)
    verify_vtl_duplicate_roots(vector)
    verify_vtl_empty_successor(vector, segment_bytes, profile)
    return {"records": len(records), "segment_sha256": hashlib.sha256(segment_bytes).hexdigest()}


def verify_vtl_distinct_encodings(vector: dict[str, Any]) -> None:
    """Integer 1, float 1.0, and both floating-point zeros stay distinguishable."""
    cases = vector.get("distinct_encoding_cases")
    if not isinstance(cases, list) or len(cases) != 4:
        raise VerifyError("VTL distinct-encoding cases are missing or malformed")
    seen: dict[str, str] = {}
    for case in cases:
        try:
            record = bytes.fromhex(case["record_cbor_hex"])
        except (KeyError, TypeError, ValueError) as exc:
            raise VerifyError("VTL distinct-encoding case has invalid hexadecimal") from exc
        digest = hashlib.sha256(b"\x00" + record).hexdigest()
        if digest != case.get("leaf_hash"):
            raise VerifyError(f"VTL distinct-encoding leaf mismatch for {case.get('name')}")
        if digest in seen:
            raise VerifyError(
                f"VTL distinct-encoding collision between {seen[digest]} and {case.get('name')}"
            )
        seen[digest] = str(case.get("name"))


def verify_vtl_duplicate_roots(vector: dict[str, Any]) -> None:
    """Repeated occurrences of one record commit to a multiset, not a set."""
    duplicates = vector.get("duplicate_occurrence_roots")
    if not isinstance(duplicates, dict):
        raise VerifyError("VTL duplicate-occurrence roots are missing")
    try:
        record = bytes.fromhex(duplicates["record_cbor_hex"])
    except (KeyError, TypeError, ValueError) as exc:
        raise VerifyError("VTL duplicate-occurrence record is invalid hexadecimal") from exc
    leaf = hashlib.sha256(b"\x00" + record).digest()
    for count, key in ((3, "three_identical_record_1_root"), (4, "four_identical_record_1_root")):
        if vtl_tree(sorted([leaf] * count)).hex() != duplicates.get(key):
            raise VerifyError(f"VTL duplicate-occurrence root mismatch for {key}")


def verify_vtl_empty_successor(
    vector: dict[str, Any], predecessor_bytes: bytes, profile: str
) -> None:
    """The empty shutdown artifact retains empty_mode suppress and chains correctly."""
    empty = vector.get("empty_shutdown_suppress")
    if not isinstance(empty, dict):
        raise VerifyError("VTL empty shutdown successor is missing")
    try:
        empty_bytes = bytes.fromhex(empty["segment_cbor_hex"])
    except (KeyError, TypeError, ValueError) as exc:
        raise VerifyError("VTL empty successor contains invalid hexadecimal") from exc
    if len(empty_bytes) != empty.get("segment_cbor_length"):
        raise VerifyError("VTL empty successor length mismatch")
    if hashlib.sha256(empty_bytes).hexdigest() != empty.get("segment_cbor_sha256"):
        raise VerifyError("VTL empty successor digest mismatch")
    decoded = CborDecoder(empty_bytes).decode()
    if not isinstance(decoded, dict):
        raise VerifyError("VTL empty successor is not a CBOR map")
    if decoded.get("commitment_profile_id") != profile:
        raise VerifyError("VTL empty successor profile UUID mismatch")
    if decoded.get("record_count") != 0 or decoded.get("batch_roots") != []:
        raise VerifyError("VTL empty successor is not empty")
    if decoded.get("segment_root") != hashlib.sha256(b"").digest():
        raise VerifyError("VTL empty successor root is not SHA-256 over zero octets")
    if decoded.get("close_reason") != "shutdown":
        raise VerifyError("VTL empty successor close reason mismatch")
    policy = decoded.get("closure_policy")
    if not isinstance(policy, dict) or policy.get("empty_mode") != "suppress":
        raise VerifyError("VTL empty successor did not retain empty_mode suppress")
    if decoded.get("prev_segment_sha256") != hashlib.sha256(predecessor_bytes).digest():
        raise VerifyError("VTL empty successor does not chain to the compact segment")


def verify_vtl_evidence_slate(vector_root: Path, binary: Path) -> int:
    vector = read_json(vector_root / "vector.json")
    segment = bytes.fromhex(vector["segment_cbor_hex"])
    with tempfile.TemporaryDirectory(prefix="trackone-vtl-slate-") as temporary:
        root = Path(temporary)
        (root / "segment.cbor").write_bytes(segment)
        manifest = {
            "version": 1,
            "ledger_id": "b7a1d5e40c6f438e9a75db27c96f31aa",
            "segment_number": "0",
            "commitment_profile_id": vector["commitment_profile_id"],
            "disclosure_class": "C",
            "artifacts": {
                "segment_cbor": {
                    "path": "segment.cbor",
                    "sha256": hashlib.sha256(segment).hexdigest(),
                }
            },
            "anchoring": {"tsa": {"status": "unavailable"}},
        }
        (root / "segment.verify.json").write_text(
            json.dumps(manifest, separators=(",", ":")), encoding="utf-8"
        )
        completed = subprocess.run(
            [str(binary), "verify", "--root", str(root), "--json"],
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
        if completed.returncode == 0:
            raise VerifyError("VTL unavailable-TSA slate unexpectedly succeeded")
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise VerifyError("VTL verifier did not emit a result object") from exc
        if (
            "version" in result
            or result.get("commitment_profile_id") != vector["commitment_profile_id"]
            or result.get("claimed_disclosure_class") != "C"
            or result.get("verification_scope") != "anchor_only"
            or result.get("overall") != "failure"
            or result.get("failure_reasons") != ["channel_failure"]
        ):
            raise VerifyError("VTL verifier result slate drifted")
    return 1


def verify_root(root: Path) -> dict[str, Any]:
    if root.is_symlink():
        raise VerifyError("archive root must not be a symlink")
    checksummed_files = verify_checksums(root)
    manifest = read_json(root / "conformance-manifest.json")
    if manifest.get("schema") != ARCHIVE_SCHEMA or manifest.get("version") != 1:
        raise VerifyError("conformance archive manifest version mismatch")
    if manifest.get("schema_uri") != f"{PROVIDER}conformance_archive_manifest.schema.json":
        raise VerifyError("conformance archive schema URI mismatch")
    if manifest.get("carrier", {}).get("artifact_type") != ARTIFACT_TYPE:
        raise VerifyError("conformance archive media type mismatch")
    claims = manifest.get("claims", {})
    expected_claims = {
        "vtl_normative_known_answer_vector": True,
        "vtl_version_one_evidence_slate": True,
        "offline_schema_resolution": True,
        "publishable_rust_crates": True,
        "helm_release_asset": True,
    }
    if claims != expected_claims:
        raise VerifyError("conformance claim set mismatch")
    schemas = verify_schema_catalog(root, manifest)
    vectors = portable(root, manifest["contents"]["vectors"], "vectors", directory=True)
    binary = portable(root, manifest["contents"]["detached_verifier"], "detached verifier")
    vtl_vector = verify_vtl_known_answer(vectors / VTL_KNOWN_ANSWER_VECTORS)
    vtl_slate_cases = verify_vtl_evidence_slate(vectors / VTL_KNOWN_ANSWER_VECTORS, binary)
    crates = portable(root, manifest["contents"]["crates"], "crates", directory=True)
    helm = portable(root, manifest["contents"]["helm"], "Helm", directory=True)
    crate_count = len(list(crates.glob("*.crate")))
    helm_count = len(list(helm.glob("*.tgz")))
    if crate_count != 10 or helm_count != 1:
        raise VerifyError("publishable crate or Helm release asset count mismatch")
    return {
        "ok": True,
        "schema": ARCHIVE_SCHEMA,
        "subject": manifest["subject"],
        "checksummed_files": checksummed_files,
        "schemas": schemas,
        "vtl_vector": vtl_vector,
        "vtl_slate_cases": vtl_slate_cases,
        "crates": crate_count,
        "helm_charts": helm_count,
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
