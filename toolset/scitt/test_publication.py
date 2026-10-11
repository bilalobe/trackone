from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from publication import (
    BUNDLE_KIND,
    PROFILE_ID,
    ROOT,
    PublicationError,
    check_artifact,
    envelope,
    make_statement,
    parse_json,
    sign,
    strict_cbor,
    verify_organization,
    verify_publication,
)
from test_support import bundle_fixture, create_identity


class PublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.identity = create_identity(Path(cls.temporary.name))
        cls.artifact = (
            ROOT / "toolset/vectors/vtl-http-binding/class-a/segment.cbor"
        ).read_bytes()
        cls.statement = make_statement(cls.artifact, cls.identity["issuer"])

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def signed(self, statement=None, **kwargs):
        return sign(
            statement or self.statement,
            self.identity["key"],
            self.identity["chain"],
            **kwargs,
        )

    def organization(self, signed, policy=None, verification_time=None):
        return verify_organization(
            signed,
            policy or self.identity["policy"],
            self.identity["ca_file"],
            self.identity["crls_file"],
            verification_time or self.identity["verification_time"],
        )

    def test_segment_positive(self):
        check_artifact(self.organization(self.signed()), self.artifact)

    def test_published_payload_fixture_inventory(self):
        fixtures = ROOT / "toolset/vectors/scitt-publication"
        check_artifact(
            parse_json((fixtures / "segment-statement.json").read_bytes()),
            self.artifact,
        )
        for disclosure in ("A", "B", "C"):
            check_artifact(
                parse_json(
                    (fixtures / f"disclosure-{disclosure}-statement.json").read_bytes()
                ),
                (fixtures / f"disclosure-{disclosure}.tar").read_bytes(),
            )
        for case in parse_json((fixtures / "negative-statements.json").read_bytes()):
            with (
                self.subTest(case=case["id"]),
                self.assertRaisesRegex(PublicationError, case["reason"]),
            ):
                check_artifact(case["statement"], self.artifact)

    def test_bundle_classes_are_properties_of_disclosures(self):
        digests = set()
        for disclosure in ("A", "B", "C"):
            statement, data = bundle_fixture(self.identity["issuer"], disclosure)
            check_artifact(statement, data)
            self.assertEqual(statement["commitment_profile_id"], PROFILE_ID)
            self.assertEqual(statement["ledger_id"], self.statement["ledger_id"])
            digests.add(statement["bundle"]["digest"])
        self.assertEqual(len(digests), 3)
        self.assertNotIn("disclosure_class", self.statement)

    def test_resigned_identity_mismatches(self):
        for field, value in (
            ("ledger_id", "0" * 32),
            ("segment_number", "1"),
            ("commitment_profile_id", "00000000-0000-0000-0000-000000000000"),
        ):
            with self.subTest(field=field):
                changed = {**self.statement, field: value}
                policy = copy.deepcopy(self.identity["policy"])
                policy["issuers"][changed["issuer"]]["ledger_ids"].append(
                    changed["ledger_id"]
                )
                verified = self.organization(self.signed(changed), policy=policy)
                with self.assertRaisesRegex(PublicationError, "copied artifact"):
                    check_artifact(verified, self.artifact)

    def test_schema_negatives(self):
        cases = [
            ("ledger_id", "ABC"),
            ("segment_number", str(2**64)),
            ("segment_number", "01"),
            ("commitment_profile_id", "old-profile"),
            ("statement_kind", "trackone.verify-manifest.v1"),
            ("disclosure_class", "A"),
        ]
        for field, value in cases:
            with self.subTest(field=field), self.assertRaises(PublicationError):
                check_artifact({**self.statement, field: value}, self.artifact)
        changed = copy.deepcopy(self.statement)
        changed["artifact"]["digest_algorithm"] = "sha-512"
        with self.assertRaises(PublicationError):
            check_artifact(changed, self.artifact)

    def test_artifact_and_subject_binding(self):
        with self.assertRaisesRegex(PublicationError, "digest mismatch"):
            check_artifact(self.statement, self.artifact + b"\x00")
        changed = {**self.statement, "subject": self.statement["subject"][:-1] + "0"}
        with self.assertRaisesRegex(PublicationError, "subject mismatch"):
            check_artifact(self.organization(self.signed(changed)), self.artifact)

    def test_header_payload_agreement(self):
        with self.assertRaisesRegex(PublicationError, "protected/payload"):
            self.organization(self.signed(publication_subject="another-subject"))
        changed = {
            **self.statement,
            "issuer": self.statement["issuer"].replace("Publisher", "Other"),
        }
        with self.assertRaisesRegex(PublicationError, "protected/payload"):
            self.organization(self.signed(changed, issuer=self.statement["issuer"]))

    def test_issuer_ledger_and_kind_authorization(self):
        for key, values in (("ledger_ids", []), ("statement_kinds", [BUNDLE_KIND])):
            policy = copy.deepcopy(self.identity["policy"])
            policy["issuers"][self.statement["issuer"]][key] = values
            with self.assertRaisesRegex(PublicationError, "not authorized"):
                self.organization(self.signed(), policy=policy)
        with self.assertRaisesRegex(PublicationError, "not authorized"):
            self.organization(self.signed(), policy={"issuers": {}})

    def test_invalid_signature(self):
        signed = self.signed()
        with self.assertRaisesRegex(PublicationError, "signature is invalid"):
            self.organization(signed[:-1] + bytes([signed[-1] ^ 1]))

    def test_untrusted_organization_and_certificate_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            other = create_identity(Path(directory))
            with self.assertRaisesRegex(
                PublicationError, "untrusted organization root"
            ):
                verify_organization(
                    self.signed(),
                    self.identity["policy"],
                    other["ca_file"],
                    self.identity["crls_file"],
                    self.identity["verification_time"],
                )
        with self.assertRaisesRegex(
            PublicationError, "does not match certificate chain"
        ):
            self.organization(
                self.signed(
                    issuer=self.identity["issuer"].replace("Publisher", "Other")
                )
            )

    def test_claimed_root_cannot_borrow_another_trusted_roots_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            other = create_identity(root / "other")
            ca_file = root / "trusted-roots.pem"
            crls_file = root / "trusted-crls.pem"
            ca_file.write_bytes(
                self.identity["ca_file"].read_bytes() + other["ca_file"].read_bytes()
            )
            crls_file.write_bytes(
                self.identity["crls_file"].read_bytes()
                + other["crls_file"].read_bytes()
            )
            statement = make_statement(self.artifact, other["issuer"])

            def verify(signed):
                return verify_organization(
                    signed,
                    other["policy"],
                    ca_file,
                    crls_file,
                    other["verification_time"],
                )

            self.assertEqual(
                verify(sign(statement, other["key"], other["chain"])), statement
            )
            for chain in (
                [self.identity["chain"][0], other["chain"][-1]],
                [*self.identity["chain"], other["chain"][-1]],
            ):
                with (
                    self.subTest(chain_length=len(chain)),
                    self.assertRaisesRegex(PublicationError, "validity/revocation"),
                ):
                    verify(sign(statement, self.identity["key"], chain))

    def test_certificate_time_and_revocation(self):
        with self.assertRaisesRegex(PublicationError, "validity/revocation"):
            self.organization(
                self.signed(),
                verification_time=self.identity["verification_time"] + 400 * 86400,
            )
        with tempfile.TemporaryDirectory() as directory:
            revoked = create_identity(Path(directory), revoked=True)
            statement = make_statement(self.artifact, revoked["issuer"])
            with self.assertRaisesRegex(PublicationError, "validity/revocation"):
                verify_organization(
                    sign(statement, revoked["key"], revoked["chain"]),
                    revoked["policy"],
                    revoked["ca_file"],
                    revoked["crls_file"],
                    revoked["verification_time"],
                )

    def test_duplicate_and_trailing_encodings(self):
        with self.assertRaisesRegex(PublicationError, "duplicate"):
            strict_cbor(b"\xa2\x01\x01\x01\x02")
        with self.assertRaisesRegex(PublicationError, "trailing"):
            envelope(self.signed() + b"\x00")

    def test_missing_receipt(self):
        signed = self.signed()
        with self.assertRaisesRegex(PublicationError, "receipts required"):
            verify_publication(
                signed,
                signed,
                self.artifact,
                policy=self.identity["policy"],
                ca_file=self.identity["ca_file"],
                crls_file=self.identity["crls_file"],
                service_keys_file=Path("unused"),
                verification_time=self.identity["verification_time"],
            )

    def test_bundle_copied_fields(self):
        statement, data = bundle_fixture(self.identity["issuer"], "A")
        with self.assertRaisesRegex(PublicationError, "disclosure class mismatch"):
            check_artifact({**statement, "disclosure_class": "C"}, data)


if __name__ == "__main__":
    unittest.main()
