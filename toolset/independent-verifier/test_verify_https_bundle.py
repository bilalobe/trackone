"""Draft -13 record and segment rejection cases for the independent checker."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from verify_https_bundle import (
    CborDecoder,
    CheckError,
    validate_record,
    validate_segment,
)

VECTOR = (
    Path(__file__).resolve().parents[2] / "toolset/vectors/vtl-known-answer/vector.json"
)


class HttpsBundleSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vector = json.loads(VECTOR.read_text(encoding="utf-8"))

    def test_known_answer_records_and_segment(self) -> None:
        for encoded in self.vector["records_cbor_hex"]:
            validate_record(bytes.fromhex(encoded))
        for case in self.vector["distinct_encoding_cases"]:
            validate_record(bytes.fromhex(case["record_cbor_hex"]))
        segment = CborDecoder(bytes.fromhex(self.vector["segment_cbor_hex"])).decode()
        self.assertEqual(validate_segment(segment)[:2], (3, 2))
        empty = CborDecoder(
            bytes.fromhex(self.vector["empty_shutdown_suppress"]["segment_cbor_hex"])
        ).decode()
        self.assertEqual(validate_segment(empty)[:2], (0, 2))

    def test_record_field_types_and_canonical_float(self) -> None:
        valid = bytes.fromhex(self.vector["records_cbor_hex"][0])
        for index, replacement in ((1, 0xF5), (11, 0xF5), (13, 0xF5), (14, 0xF5)):
            with self.subTest(index=index), self.assertRaises(CheckError):
                validate_record(
                    valid[:index] + bytes([replacement]) + valid[index + 1 :]
                )
        with self.assertRaisesRegex(CheckError, "shortest exact width"):
            validate_record(valid[:-1] + bytes.fromhex("fa3f800000"))

    def test_draft_13_baseline_record_envelope(self) -> None:
        cases = json.loads(
            (
                Path(__file__).resolve().parents[2]
                / "toolset/vectors/vtl-interoperability/cases.json"
            ).read_text(encoding="utf-8")
        )
        case = cases["canonical_record_acceptance_cases"][0]
        construction = case["construction"]
        record = (
            bytes.fromhex(construction["record_prefix_hex"])
            + bytes.fromhex(construction["repeated_array_head_hex"])
            * construction["repeat_count"]
            + b"\x59"
            + construction["innermost_bstr_length"].to_bytes(2, "big")
            + bytes.fromhex(construction["fill_octet_hex"])
            * construction["innermost_bstr_length"]
        )
        self.assertEqual(len(record), case["expected_encoded_length"])
        self.assertEqual(
            hashlib.sha256(b"\x00" + record).hexdigest(), case["expected_leaf_hash"]
        )
        validate_record(record)

    def test_segment_field_set_policy_and_empty_invariant(self) -> None:
        valid = CborDecoder(bytes.fromhex(self.vector["segment_cbor_hex"])).decode()
        bad_values = [
            ("interval_ms", 0),
            ("batch_record_limit", 1 << 64),
            ("record_limit", 0),
            ("size_limit_bytes", False),
            ("empty_mode", "unknown"),
            ("version", True),
        ]
        for field, value in bad_values:
            with self.subTest(field=field), self.assertRaises(CheckError):
                candidate = copy.deepcopy(valid)
                candidate["closure_policy"][field] = value
                validate_segment(candidate)
        for change in (
            lambda segment: segment.update(extra=1),
            lambda segment: segment["closure_policy"].update(extra=1),
            lambda segment: segment.update(close_reason="unknown"),
            lambda segment: segment.update(prev_segment_sha256=b"short"),
        ):
            with self.subTest(change=change), self.assertRaises(CheckError):
                candidate = copy.deepcopy(valid)
                change(candidate)
                validate_segment(candidate)
        empty = CborDecoder(
            bytes.fromhex(self.vector["empty_shutdown_suppress"]["segment_cbor_hex"])
        ).decode()
        empty["close_reason"] = "interval"
        with self.assertRaises(CheckError):
            validate_segment(empty)


if __name__ == "__main__":
    unittest.main()
