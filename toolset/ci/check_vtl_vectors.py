#!/usr/bin/env python3
"""Recompute the VTL known-answer vector corpus from its own record bytes.

The corpus under ``toolset/vectors/`` transcribes the normative known-answer
values of the VTL profile. This check recomputes every derived value in that
corpus -- leaf hashes, the sorted leaf order, aligned batch roots, the segment
root, the batch-root composition, duplicate-occurrence roots, and both segment
artifact digests -- from the raw record and artifact bytes the corpus carries,
and strictly validates the deterministic CBOR encoding of both segment
artifacts against the profile's artifact schema.

It imports no repository runtime code, so agreement with the Rust
implementation is evidence rather than tautology. Its input is the committed
corpus alone: the profile document itself is an external published artifact and
is deliberately not read from the working tree, so this check confirms the
corpus is internally consistent and correctly derived, not that it agrees with
a particular published revision.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
VECTOR = REPO / "toolset/vectors/vtl-known-answer/vector.json"
PROFILE_UUID = "c08ade4e-1785-4eb6-9648-b7003d76288d"

SEGMENT_FIELDS = {
    "version",
    "commitment_profile_id",
    "ledger_id",
    "segment_number",
    "closure_policy",
    "close_reason",
    "prev_segment_sha256",
    "record_count",
    "batch_roots",
    "segment_root",
}
POLICY_FIELDS = {
    "version",
    "interval_ms",
    "batch_record_limit",
    "record_limit",
    "size_limit_bytes",
    "empty_mode",
}


class VectorError(RuntimeError):
    pass


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(record: bytes) -> bytes:
    """leaf_hash = SHA-256(0x00 || record)."""
    return sha256(b"\x00" + record)


def vtl_root(leaves: list[bytes]) -> bytes:
    """VTLRoot over an already-sorted list of leaf hashes."""
    if not leaves:
        return sha256(b"")
    if len(leaves) == 1:
        return leaves[0]
    split = 1
    while split * 2 < len(leaves):
        split *= 2
    return sha256(b"\x01" + vtl_root(leaves[:split]) + vtl_root(leaves[split:]))


def compose(roots: list[bytes], leaf_count: int, limit: int) -> bytes:
    """Compose aligned batch roots back into the segment root."""
    if leaf_count <= limit:
        return roots[0]
    split = 1
    while split * 2 < leaf_count:
        split *= 2
    boundary = split // limit
    return sha256(
        b"\x01"
        + compose(roots[:boundary], split, limit)
        + compose(roots[boundary:], leaf_count - split, limit)
    )


class StrictCbor:
    """Decoder enforcing the profile's deterministic-encoding requirements."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0
        self.problems: list[str] = []

    def _head(self) -> tuple[int, int, int]:
        initial = self.data[self.offset]
        self.offset += 1
        major, extra = initial >> 5, initial & 0x1F
        if extra < 24:
            return major, extra, extra
        width = {24: 1, 25: 2, 26: 4, 27: 8}.get(extra)
        if width is None:
            self.problems.append(f"offset {self.offset - 1}: indefinite or reserved length")
            return major, extra, 0
        value = int.from_bytes(self.data[self.offset : self.offset + width], "big")
        self.offset += width
        if value < 24:
            shortest = 0
        elif value < 0x100:
            shortest = 1
        elif value < 0x10000:
            shortest = 2
        elif value < 0x1_0000_0000:
            shortest = 4
        else:
            shortest = 8
        if shortest != width:
            self.problems.append(
                f"offset {self.offset - width - 1}: non-shortest encoding of {value}"
            )
        return major, extra, value

    def decode(self, path: str = "$") -> Any:
        major, extra, value = self._head()
        if major == 0:
            return value
        if major == 1:
            return -1 - value
        if major == 2:
            chunk = self.data[self.offset : self.offset + value]
            self.offset += value
            return chunk
        if major == 3:
            chunk = self.data[self.offset : self.offset + value]
            self.offset += value
            try:
                return chunk.decode("utf-8")
            except UnicodeDecodeError:
                self.problems.append(f"{path}: invalid UTF-8 text string")
                return chunk
        if major == 4:
            return [self.decode(f"{path}[{index}]") for index in range(value)]
        if major == 5:
            encoded_keys: list[bytes] = []
            names: list[str] = []
            result: dict[str, Any] = {}
            for _ in range(value):
                start = self.offset
                key = self.decode(f"{path}.<key>")
                encoded_keys.append(self.data[start : self.offset])
                if not isinstance(key, str):
                    self.problems.append(f"{path}: map key is not a text string")
                    key = repr(key)
                if key in result:
                    self.problems.append(f"{path}: duplicate map key {key!r}")
                names.append(key)
                result[key] = self.decode(f"{path}.{key}")
            if encoded_keys != sorted(encoded_keys):
                self.problems.append(f"{path}: map keys not in bytewise order: {names}")
            lengths = [len(name.encode()) for name in names]
            if lengths != sorted(lengths):
                self.problems.append(f"{path}: map keys not length-first ordered: {names}")
            return result
        if major == 6:
            self.problems.append(f"{path}: CBOR tag present")
            return self.decode(path)
        if extra == 20:
            return False
        if extra == 21:
            return True
        if extra == 22:
            return None
        if extra in (25, 26, 27):
            self.problems.append(f"{path}: floating-point value in segment artifact")
            return None
        self.problems.append(f"{path}: unexpected simple value {extra}")
        return None


def decode_hex(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise VectorError(f"{label} is not a hexadecimal string")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise VectorError(f"{label} is not valid hexadecimal") from error


def check_segment(data: bytes, label: str) -> dict[str, Any]:
    decoder = StrictCbor(data)
    decoded = decoder.decode()
    if decoder.offset != len(data):
        decoder.problems.append(f"{len(data) - decoder.offset} trailing octets")
    if decoder.problems:
        raise VectorError(f"{label} is not deterministic CBOR: {decoder.problems[0]}")
    if not isinstance(decoded, dict):
        raise VectorError(f"{label} is not a CBOR map")
    if set(decoded) != SEGMENT_FIELDS:
        raise VectorError(f"{label} field set does not match the segment artifact schema")
    if set(decoded["closure_policy"]) != POLICY_FIELDS:
        raise VectorError(f"{label} closure_policy does not match the segment artifact schema")
    if decoded["commitment_profile_id"] != PROFILE_UUID:
        raise VectorError(f"{label} carries an unexpected commitment_profile_id")
    return decoded


def main() -> int:
    corpus = json.loads(VECTOR.read_text(encoding="utf-8"))
    if corpus.get("commitment_profile_id") != PROFILE_UUID:
        raise VectorError("corpus commitment_profile_id is not the normative UUID")
    checks = 0

    # Distinct deterministic encodings must yield distinct leaves.
    seen: dict[bytes, str] = {}
    cases = corpus.get("distinct_encoding_cases")
    if not isinstance(cases, list) or len(cases) != 4:
        raise VectorError("distinct_encoding_cases is missing or malformed")
    for case in cases:
        name = case.get("name")
        record = decode_hex(case.get("record_cbor_hex"), f"{name} record")
        computed = leaf_hash(record)
        if computed.hex() != case.get("leaf_hash"):
            raise VectorError(f"{name}: recomputed leaf hash does not match the corpus")
        if computed in seen:
            raise VectorError(f"{name} collides with {seen[computed]}")
        seen[computed] = str(name)
        checks += 1

    # The compact segment: leaves, sorted order, aligned batches, root.
    records = [
        decode_hex(item, f"records_cbor_hex[{index}]")
        for index, item in enumerate(corpus.get("records_cbor_hex", []))
    ]
    if not records:
        raise VectorError("records_cbor_hex is missing or empty")
    leaves = [leaf_hash(record) for record in records]
    if [item.hex() for item in leaves] != corpus.get("leaf_hashes"):
        raise VectorError("recomputed leaf hashes do not match the corpus")
    ordered = sorted(leaves)
    if [item.hex() for item in ordered] != corpus.get("sorted_leaf_hashes"):
        raise VectorError("sorted_leaf_hashes is not ascending bytewise order")
    checks += 2

    segment_bytes = decode_hex(corpus.get("segment_cbor_hex"), "segment_cbor_hex")
    segment = check_segment(segment_bytes, "segment_cbor")
    limit = segment["closure_policy"]["batch_record_limit"]
    if limit <= 0 or limit & (limit - 1):
        raise VectorError("batch_record_limit is not a positive power of two")
    if limit != corpus.get("batch_record_limit"):
        raise VectorError("corpus batch_record_limit disagrees with the segment artifact")
    batches = [ordered[index : index + limit] for index in range(0, len(ordered), limit)]
    roots = [vtl_root(batch) for batch in batches]
    if [item.hex() for item in roots] != corpus.get("batch_roots"):
        raise VectorError("recomputed batch roots do not match the corpus")
    root = vtl_root(ordered)
    if root.hex() != corpus.get("segment_root"):
        raise VectorError("recomputed segment root does not match the corpus")
    if compose(roots, len(ordered), limit) != root:
        raise VectorError("aligned batch roots do not compose into segment_root")
    if len(roots) != 1 + ((len(ordered) - 1) // limit):
        raise VectorError("batch root cardinality does not follow 1 + ((N - 1) / B)")
    if segment["segment_root"] != root or segment["batch_roots"] != roots:
        raise VectorError("segment artifact does not carry the recomputed roots")
    if segment["record_count"] != len(records):
        raise VectorError("segment record_count does not match the leaf count")
    if segment["segment_number"] != 0 or segment["prev_segment_sha256"] != bytes(32):
        raise VectorError("epoch segment identity is wrong")
    if segment["ledger_id"] != corpus.get("ledger_id"):
        raise VectorError("segment ledger_id disagrees with the corpus")
    if len(segment_bytes) != corpus.get("segment_cbor_length"):
        raise VectorError("segment_cbor_length does not match the artifact bytes")
    segment_digest = sha256(segment_bytes)
    if segment_digest.hex() != corpus.get("segment_cbor_sha256"):
        raise VectorError("segment_cbor_sha256 does not match the artifact bytes")
    checks += 10

    # Duplicate occurrences commit to a multiset, not a set.
    duplicates = corpus.get("duplicate_occurrence_roots")
    if not isinstance(duplicates, dict):
        raise VectorError("duplicate_occurrence_roots is missing")
    duplicate_leaf = leaf_hash(decode_hex(duplicates.get("record_cbor_hex"), "duplicate record"))
    for count, key in (
        (3, "three_identical_record_1_root"),
        (4, "four_identical_record_1_root"),
    ):
        if vtl_root([duplicate_leaf] * count).hex() != duplicates.get(key):
            raise VectorError(f"recomputed {key} does not match the corpus")
        checks += 1

    # The empty shutdown successor retains empty_mode suppress and chains.
    empty_corpus = corpus.get("empty_shutdown_suppress")
    if not isinstance(empty_corpus, dict):
        raise VectorError("empty_shutdown_suppress is missing")
    empty_bytes = decode_hex(empty_corpus.get("segment_cbor_hex"), "empty successor")
    empty = check_segment(empty_bytes, "empty_shutdown_suppress_segment_cbor")
    if empty["record_count"] != 0 or empty["batch_roots"] != []:
        raise VectorError("empty successor is not empty")
    if empty["segment_root"] != sha256(b""):
        raise VectorError("empty successor root is not SHA-256 over zero octets")
    if empty["close_reason"] != "shutdown":
        raise VectorError("empty successor close_reason is not shutdown")
    if empty["closure_policy"]["empty_mode"] != "suppress":
        raise VectorError("empty successor did not retain empty_mode suppress")
    if empty["segment_number"] != segment["segment_number"] + 1:
        raise VectorError("empty successor does not increment segment_number")
    if empty["ledger_id"] != segment["ledger_id"]:
        raise VectorError("empty successor changed ledger_id")
    if empty["commitment_profile_id"] != segment["commitment_profile_id"]:
        raise VectorError("empty successor changed commitment_profile_id")
    if empty["prev_segment_sha256"] != segment_digest:
        raise VectorError("empty successor does not chain to the compact segment")
    if len(empty_bytes) != empty_corpus.get("segment_cbor_length"):
        raise VectorError("empty successor length does not match the artifact bytes")
    if sha256(empty_bytes).hex() != empty_corpus.get("segment_cbor_sha256"):
        raise VectorError("empty successor digest does not match the artifact bytes")
    checks += 10

    print(json.dumps({"ok": True, "vector": VECTOR.name, "checks": checks}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (VectorError, KeyError, TypeError, OSError) as error:
        print(f"VTL vector check failed: {error}", file=sys.stderr)
        sys.exit(1)
