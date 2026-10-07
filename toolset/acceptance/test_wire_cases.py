"""Regression coverage for fixture selection and required matrix inventory."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run_vtl_https_exchange as exchange
from wire_cases import REQUIRED_CASES, command_verdict, validate_matrix


class ResponseSelectionTests(unittest.TestCase):
    def test_predecessor_can_be_second_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in (0, 1):
                (root / f"request-{index:04}.tsq").write_bytes(b"query")
                (root / f"response-{index:04}.tsr").write_bytes(str(index).encode())
            with (
                patch.object(
                    exchange,
                    "query_imprint",
                    side_effect=lambda path: (
                        "target" if "0000" in path.name else "predecessor"
                    ),
                ),
                patch.object(exchange, "run") as run,
                patch.object(exchange, "dump_imprint", return_value="predecessor"),
            ):
                run.return_value.stdout = "response dump"
                self.assertEqual(
                    exchange.predecessor_response(root, "predecessor", "target"), b"1"
                )

    def test_missing_ambiguous_and_same_digest_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(exchange.AcceptanceError, "distinct"):
                exchange.predecessor_response(root, "same", "same")
            with self.assertRaisesRegex(
                exchange.AcceptanceError, "missing or ambiguous"
            ):
                exchange.predecessor_response(root, "predecessor", "target")
            for index in (0, 1):
                (root / f"request-{index:04}.tsq").touch()
            with (
                patch.object(exchange, "query_imprint", return_value="predecessor"),
                self.assertRaisesRegex(
                    exchange.AcceptanceError, "missing or ambiguous"
                ),
            ):
                exchange.predecessor_response(root, "predecessor", "target")

    def test_response_must_bind_predecessor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "request-0000.tsq").touch()
            (root / "response-0000.tsr").touch()
            with (
                patch.object(exchange, "query_imprint", return_value="predecessor"),
                patch.object(exchange, "run") as run,
                patch.object(exchange, "dump_imprint", return_value="target"),
            ):
                run.return_value.stdout = "response dump"
                with self.assertRaisesRegex(
                    exchange.AcceptanceError, "imprint mismatch"
                ):
                    exchange.predecessor_response(root, "predecessor", "target")


class MatrixInventoryTests(unittest.TestCase):
    def test_verdict_is_read_from_either_stream(self):
        verdict = {"overall": "failure", "channels": {"tsa": {"status": "missing"}}}
        for stdout, stderr in (
            (json.dumps(verdict), "ERROR"),
            ("", json.dumps(verdict)),
        ):
            self.assertEqual(
                command_verdict(subprocess.CompletedProcess([], 1, stdout, stderr)),
                verdict,
            )

    def report(self):
        return {
            "required_cases": list(REQUIRED_CASES),
            "passed": True,
            "cases": [
                {"case": name, "implementation": impl, "passed": True}
                for name in REQUIRED_CASES
                for impl in ("trackone", "independent")
            ],
        }

    def test_complete_matrix_passes(self):
        validate_matrix(self.report())

    def test_missing_duplicate_unknown_and_failed_cases_fail(self):
        report = self.report()
        variants = []
        missing = json.loads(json.dumps(report))
        missing["cases"].pop()
        variants.append(missing)
        for field, value in (
            ("case", "unknown"),
            ("case", report["cases"][2]["case"]),
            ("passed", False),
        ):
            changed = json.loads(json.dumps(report))
            changed["cases"][0][field] = value
            variants.append(changed)
        for changed in variants:
            with self.assertRaises(ValueError):
                validate_matrix(changed)
