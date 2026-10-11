from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import cbor2
from publication import (
    PublicationError,
    check_artifact,
    envelope,
    strict_cbor,
    verify_organization,
    verify_publication,
)
from replay import DEFAULT_CAPTURE, replay


class CapturedExchangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = DEFAULT_CAPTURE
        cls.capture = json.loads((cls.directory / "capture.json").read_text())
        cls.signed = (cls.directory / "signed.cose").read_bytes()
        cls.transparent = (cls.directory / "transparent.cose").read_bytes()
        cls.artifact = (cls.directory / "segment.cbor").read_bytes()
        cls.kwargs = {
            "policy": json.loads((cls.directory / "authorization.json").read_text()),
            "ca_file": cls.directory / "organization-ca.pem",
            "crls_file": cls.directory / "organization-crls.pem",
            "service_keys_file": cls.directory / "service-keys.cbor",
            "verification_time": cls.capture["verification_time"],
        }

    def test_replay(self):
        self.assertTrue(replay(self.directory)["publication_valid"])

    def test_corrupted_and_wrong_statement_receipts(self):
        parts, _ = envelope(self.transparent)
        receipt = parts[1][394][0]
        for corrupt in (receipt[:-1] + bytes([receipt[-1] ^ 1]), self.signed):
            with self.subTest(receipt=corrupt[:8].hex()):
                changed = [parts[0], {394: [corrupt]}, parts[2], parts[3]]
                with self.assertRaisesRegex(
                    PublicationError, "receipt verification failed"
                ):
                    verify_publication(
                        self.signed,
                        cbor2.dumps(cbor2.CBORTag(18, changed)),
                        self.artifact,
                        **self.kwargs,
                    )

    def test_receipt_for_another_signed_statement(self):
        other = (self.directory / "mismatch-segment_number.cose").read_bytes()
        parts, _ = envelope(other)
        receipts, _ = envelope(self.transparent)
        # The organizational signature is valid; the old receipt commits to other bytes.
        transparent = cbor2.dumps(
            cbor2.CBORTag(18, [parts[0], receipts[1], parts[2], parts[3]])
        )
        with self.assertRaisesRegex(PublicationError, "receipt verification failed"):
            verify_publication(other, transparent, self.artifact, **self.kwargs)

    def test_untrusted_service_key(self):
        keys = strict_cbor((self.directory / "service-keys.cbor").read_bytes())
        for key in keys:
            key[2] = b"untrusted-key"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keys.cbor"
            path.write_bytes(cbor2.dumps(keys))
            kwargs = {**self.kwargs, "service_keys_file": path}
            with self.assertRaisesRegex(
                PublicationError, "receipt verification failed"
            ):
                verify_publication(
                    self.signed, self.transparent, self.artifact, **kwargs
                )

    def test_valid_receipt_cannot_bind_different_artifact(self):
        with self.assertRaisesRegex(PublicationError, "digest mismatch"):
            verify_publication(
                self.signed, self.transparent, self.artifact + b"\x00", **self.kwargs
            )

    def test_resigned_semantic_fixtures(self):
        for field in ("segment_number", "commitment_profile_id"):
            with self.subTest(field=field):
                signed = (self.directory / f"mismatch-{field}.cose").read_bytes()
                statement = verify_organization(
                    signed,
                    self.kwargs["policy"],
                    self.kwargs["ca_file"],
                    self.kwargs["crls_file"],
                    self.kwargs["verification_time"],
                )
                with self.assertRaisesRegex(PublicationError, "copied artifact"):
                    check_artifact(statement, self.artifact)

    def test_service_authorization_negative(self):
        signed = (self.directory / "unauthorized-ledger.cose").read_bytes()
        transcript = json.loads((self.directory / "exchange.json").read_text())
        rejected = [
            e
            for e in transcript
            if e["method"] == "POST"
            and e["status"] == 400
            and (self.directory / e["request_body"]).read_bytes() == signed
        ]
        self.assertEqual(len(rejected), 1)
        self.assertIn(
            b"Unauthorized ledger/kind",
            (self.directory / rejected[0]["response_body"]).read_bytes(),
        )
        with self.assertRaisesRegex(PublicationError, "not authorized"):
            verify_organization(
                signed,
                self.kwargs["policy"],
                self.kwargs["ca_file"],
                self.kwargs["crls_file"],
                self.kwargs["verification_time"],
            )

    def test_publication_and_vtl_results_are_distinct(self):
        # The live runner produced both reports using the unchanged published segment.
        self.assertTrue(replay(self.directory)["publication_valid"])
        positive = json.loads((self.directory / "vtl-report.json").read_text())
        negative = json.loads((self.directory / "vtl-negative-report.json").read_text())
        self.assertEqual(positive["overall"], "success")
        self.assertNotEqual(negative["overall"], "success")
        self.assertEqual(positive["artifact_sha256"], negative["artifact_sha256"])
        self.assertIn("commitment_mismatch", negative["failure_reasons"])


if __name__ == "__main__":
    unittest.main()
