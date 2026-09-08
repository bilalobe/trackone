"""Regression tests for the detached conformance archive verifier."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = Path(__file__).with_name("verify_conformance_archive.py")
SPEC = importlib.util.spec_from_file_location("verify_conformance_archive", VERIFIER_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import machinery guard
    raise RuntimeError(f"cannot load verifier from {VERIFIER_PATH}")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class VtlVectorTests(unittest.TestCase):
    def test_normative_known_answer_vector_is_accepted(self) -> None:
        vector_root = (
            REPOSITORY_ROOT
            / "toolset"
            / "vectors"
            / "vtl-known-answer"
        )

        result = VERIFIER.verify_vtl_known_answer(vector_root)
        self.assertEqual(result["records"], 3)
        self.assertEqual(
            result["segment_sha256"],
            "2672cb72d5f06863110af1b30660c7e5ba495c0b2ce7d084b0436e010e99388d",
        )

    def test_wrong_profile_uuid_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            vector_root = Path(temporary_directory)
            (vector_root / "vector.json").write_text(
                json.dumps({"commitment_profile_id": "not-the-vtl-profile"}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                VERIFIER.VerifyError, "profile UUID mismatch"
            ):
                VERIFIER.verify_vtl_known_answer(vector_root)


if __name__ == "__main__":
    unittest.main()
