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


class V2VectorManifestTests(unittest.TestCase):
    def test_current_v2_corpus_is_accepted(self) -> None:
        vector_root = (
            REPOSITORY_ROOT
            / "toolset"
            / "vectors"
            / "verifiable-telemetry-canonical-cbor-v2"
        )

        self.assertGreater(VERIFIER.verify_v2_vectors(vector_root), 0)

    def test_legacy_v1_schema_token_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            vector_root = Path(temporary_directory)
            (vector_root / "manifest.json").write_text(
                json.dumps({"schema": "trackone-v2-vector-manifest-1"}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                VERIFIER.VerifyError, "v2 vector schema token mismatch"
            ):
                VERIFIER.verify_v2_vectors(vector_root)


if __name__ == "__main__":
    unittest.main()
