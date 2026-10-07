"""Regression tests for the detached conformance archive verifier."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from conformance_cases import (
    EXPANDED_CLAIMS,
    EvidenceReplayError,
    der_parts,
    fixture_path,
    mutate_tsa,
    verify_evidence_cases,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = Path(__file__).with_name("verify_conformance_archive.py")
SPEC = importlib.util.spec_from_file_location(
    "verify_conformance_archive", VERIFIER_PATH
)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import machinery guard
    raise RuntimeError(f"cannot load verifier from {VERIFIER_PATH}")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class VtlVectorTests(unittest.TestCase):
    def test_mutation_paths_cannot_escape_temporary_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "bundle"
            root.mkdir()
            outside = Path(temporary) / "outside"
            outside.write_bytes(b"untouched")
            (root / "link").symlink_to(outside)
            for relative in ("../outside", str(outside), "link"):
                with self.assertRaises(ValueError):
                    fixture_path(root, relative)
            self.assertEqual(outside.read_bytes(), b"untouched")

    def test_only_complete_supported_claim_sets_are_accepted(self) -> None:
        base = VERIFIER.BASE_CLAIMS
        self.assertFalse(VERIFIER.has_expanded_claims(base))
        self.assertTrue(VERIFIER.has_expanded_claims({**base, **EXPANDED_CLAIMS}))
        for claims in (
            {**base, "unknown": True},
            {**base, "vtl_disclosure_fixture_replay": True},
            {**base, **EXPANDED_CLAIMS, "vtl_tsa_fixture_rejection_replay": False},
            {**base, "vtl_normative_known_answer_vector": 1},
        ):
            with self.assertRaises(VERIFIER.VerifyError):
                VERIFIER.has_expanded_claims(claims)

    def test_always_successful_verifier_cannot_pass_negative_replay(self) -> None:
        def always_success(command, **kwargs):
            root = Path(command[command.index("--root") + 1])
            manifest = json.loads((root / "segment.verify.json").read_text())
            result = {
                "overall": "success",
                "channels": {"tsa": {"status": "verified"}},
                "claimed_disclosure_class": manifest["disclosure_class"],
                "verification_scope": command[command.index("--scope") + 1],
                "artifact_sha256": "2672cb72d5f06863110af1b30660c7e5ba495c0b2ce7d084b0436e010e99388d",
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(result), "")

        with patch("conformance_cases.subprocess.run", side_effect=always_success):
            with self.assertRaises(EvidenceReplayError) as raised:
                verify_evidence_cases(
                    REPOSITORY_ROOT / "toolset/vectors", Path("unused")
                )
        report = raised.exception.report
        self.assertEqual(report["executed"], 16)
        self.assertEqual(sum(case["passed"] for case in report["cases"]), 3)

    def test_tsa_mutations_preserve_der_and_target_intended_fields(self) -> None:
        response = (
            REPOSITORY_ROOT / "toolset/vectors/vtl-http-binding/class-a/timestamp.tsr"
        ).read_bytes()
        duplicate = mutate_tsa(response, "multiple-signer-infos-are-rejected", "")
        outer = der_parts(duplicate)
        fields = der_parts(outer[0][1])
        content = der_parts(fields[1][1])
        signed = der_parts(der_parts(content[1][1])[0][1])
        self.assertEqual(len(der_parts(signed[-1][1])), 2)
        changed = mutate_tsa(response, "granted-with-mods-is-rejected", "")
        status = der_parts(der_parts(der_parts(changed)[0][1])[0][1])
        self.assertEqual(status[0], (2, b"\x01"))
        legacy = mutate_tsa(response, "legacy-signing-certificate-is-rejected", "")
        self.assertIn(bytes.fromhex("060b2a864886f70d010910020c"), legacy)

    def test_normative_known_answer_vector_is_accepted(self) -> None:
        vector_root = REPOSITORY_ROOT / "toolset" / "vectors" / "vtl-known-answer"

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

            with self.assertRaisesRegex(VERIFIER.VerifyError, "profile UUID mismatch"):
                VERIFIER.verify_vtl_known_answer(vector_root)


if __name__ == "__main__":
    unittest.main()
