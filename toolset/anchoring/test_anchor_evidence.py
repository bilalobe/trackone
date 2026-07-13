import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import anchor_evidence as anchor


JSON_COMMIT = "3fd9cc735b48e5103316adc53f587220315e18cb"
HEADERS_COMMIT = "c0386ab1f1fe56e0d7742961e3e456e27c4f83a1"
GIT_COMMIT = "a" * 40


def write_json(path: Path, value):
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


class AnchorEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.archive = self.root / "trackone-conformance-sha.tar.gz"
        self.archive.write_bytes(b"deterministic conformance archive")
        self.manifest = self.root / "archive.manifest.json"
        self.manifest_value = {
            "schema": "trackone-conformance-archive-v2",
            "subject": {
                "kind": "commit",
                "name": f"sha-{GIT_COMMIT}",
                "git_commit": GIT_COMMIT,
            },
            "repository": "bilalobe/trackone",
            "carrier": {
                "oci_ref": (
                    f"ghcr.io/bilalobe/trackone/conformance-archive:sha-{GIT_COMMIT}"
                ),
                "artifact_type": "application/vnd.trackone.conformance.archive.v2+tar",
            },
        }
        write_json(self.manifest, self.manifest_value)
        self.verification = self.root / "verification.json"
        write_json(
            self.verification,
            {
                "ok": True,
                "schema": "trackone-conformance-archive-v2",
                "subject": self.manifest_value["subject"],
            },
        )
        self.sanity = self.root / "sanity.json"
        write_json(
            self.sanity,
            {
                "schema": "trackone-ots-verifier-sanity-v1",
                "ok": True,
                "fixture": {"id": "opentimestamps-hello-world-bitcoin-358391"},
                "clients": {
                    "json": {"commit": JSON_COMMIT},
                    "headers": {"commit": HEADERS_COMMIT},
                },
            },
        )
        self.state = self.root / "state"

    def tearDown(self):
        self.temporary.cleanup()

    def prepare(self):
        args = argparse.Namespace(
            repository="bilalobe/trackone",
            git_commit=GIT_COMMIT,
            source_ci_run_id=42,
            archive=self.archive,
            archive_manifest=self.manifest,
            independent_verification=self.verification,
            verifier_sanity=self.sanity,
            expected_archive_sha256=hashlib.sha256(
                self.archive.read_bytes()
            ).hexdigest(),
            state_root=self.state,
            json_client_commit=JSON_COMMIT,
            headers_client_commit=HEADERS_COMMIT,
            github_output=None,
        )
        return anchor.prepare(args)

    def advance_args(self):
        return argparse.Namespace(
            state_root=self.state,
            stable_ots=Path("/bin/true"),
            json_ots=Path("/bin/true"),
            headers_ots=Path("/bin/true"),
            stable_client_version="opentimestamps-client==0.7.2",
            json_client_commit=JSON_COMMIT,
            headers_client_commit=HEADERS_COMMIT,
            calendar=["https://a.pool.opentimestamps.org"],
            header_source=[
                "https://blockstream.info/api",
                "https://mempool.space/api",
            ],
            header_quorum=2,
            stamp_timeout=1,
            calendar_timeout=1,
            header_timeout=1,
            client_timeout=1,
        )

    def test_prepare_is_content_addressed_and_idempotent(self):
        first = self.prepare()
        second = self.prepare()
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        subject = Path(first["subject_path"])
        self.assertEqual(
            hashlib.sha256(subject.read_bytes()).hexdigest(), first["anchor_id"]
        )
        self.assertEqual(
            subject.read_bytes(), anchor.canonical_json_bytes(anchor.read_json(subject))
        )

    def test_prepare_rejects_archive_digest_drift(self):
        args = argparse.Namespace(
            repository="bilalobe/trackone",
            git_commit=GIT_COMMIT,
            source_ci_run_id=42,
            archive=self.archive,
            archive_manifest=self.manifest,
            independent_verification=self.verification,
            verifier_sanity=self.sanity,
            expected_archive_sha256="0" * 64,
            state_root=self.state,
            json_client_commit=JSON_COMMIT,
            headers_client_commit=HEADERS_COMMIT,
            github_output=None,
        )
        with self.assertRaises(anchor.AnchorError):
            anchor.prepare(args)

    def test_receipt_timestamp_does_not_churn_without_material_change(self):
        path = self.root / "receipt.json"
        material = {"schema": anchor.EVIDENCE_SCHEMA, "version": 1}
        self.assertTrue(anchor.write_receipt_if_changed(path, material))
        first = path.read_bytes()
        self.assertFalse(anchor.write_receipt_if_changed(path, material))
        self.assertEqual(first, path.read_bytes())

    def test_sparse_sidecar_parser_reports_header_identity(self):
        metadata = json.loads(
            (
                Path(__file__).resolve().parent / "fixtures/hello-world-header.json"
            ).read_text(encoding="utf-8")
        )
        header = bytes.fromhex(metadata["bitcoin_header_hex"])
        sidecar = self.root / "headers.bin"
        sidecar.write_bytes(
            b"OTSV"
            + bytes((1, 0, 0, 0))
            + b"\x00" * 8
            + int(metadata["bitcoin_block_height"]).to_bytes(4, "little")
            + header
        )
        records = anchor.parse_sparse_sidecar(sidecar)
        self.assertEqual(records[0]["height"], metadata["bitcoin_block_height"])
        self.assertEqual(records[0]["block_hash"], metadata["bitcoin_block_hash"])

    def test_calendar_outage_yields_verifiable_stationary_receipt(self):
        prepared = self.prepare()
        args = self.advance_args()
        args.stable_ots = Path("/bin/false")
        result = anchor.advance(args)
        self.assertEqual(result["anchors"][0]["state"], "stationary")
        verified = anchor.verify_bundle(Path(prepared["anchor_dir"]))
        self.assertTrue(verified["ok"])
        self.assertEqual(verified["state"], "stationary")
        detached = subprocess.run(
            [
                sys.executable,
                str(Path(prepared["anchor_dir"]) / "verify-anchor-evidence.py"),
                "verify-bundle",
                "--root",
                prepared["anchor_dir"],
            ],
            cwd=self.root,
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(detached.returncode, 0, detached.stdout + detached.stderr)

    def test_pending_anchor_rejects_unqualified_verifier_rotation(self):
        self.prepare()
        args = self.advance_args()
        args.stable_ots = Path("/bin/false")
        anchor.advance(args)
        args.json_client_commit = "b" * 40
        with self.assertRaisesRegex(
            anchor.AnchorError, "different from its sanity gate"
        ):
            anchor.advance(args)

    def test_completed_proof_advances_to_header_quorum_without_state_churn(self):
        prepared = self.prepare()
        anchor_dir = Path(prepared["anchor_dir"])
        (anchor_dir / "subject.json.ots").write_bytes(b"synthetic-proof")
        metadata = json.loads(
            (
                Path(__file__).resolve().parent / "fixtures/hello-world-header.json"
            ).read_text(encoding="utf-8")
        )
        header = bytes.fromhex(metadata["bitcoin_header_hex"])
        sidecar_bytes = (
            b"OTSV"
            + bytes((1, 0, 0, 0))
            + b"\x00" * 8
            + int(metadata["bitcoin_block_height"]).to_bytes(4, "little")
            + header
        )

        def fake_run(command, _timeout):
            if "info" in command:
                payload = {
                    "file_digest": prepared["anchor_id"],
                    "timestamp": {
                        "attestations": [
                            {
                                "type": "BitcoinBlockHeaderAttestation",
                                "height": metadata["bitcoin_block_height"],
                            }
                        ]
                    },
                }
                return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
            if "fetch" in command:
                output = Path(command[command.index("--output") + 1])
                output.write_bytes(sidecar_bytes)
            return subprocess.CompletedProcess(command, 0, "ok", "")

        args = self.advance_args()
        with patch("anchor_evidence.run", fake_run):
            first = anchor.advance(args)
            second = anchor.advance(args)
        self.assertEqual(first["anchors"][0]["state"], "bitcoin-header-quorum-verified")
        self.assertEqual(first["changed"], 1)
        self.assertEqual(second["changed"], 0)
        verified = anchor.verify_bundle(anchor_dir)
        self.assertEqual(verified["state"], "bitcoin-header-quorum-verified")

    def test_failed_advancement_rolls_back_mutable_evidence(self):
        prepared = self.prepare()
        anchor_dir = Path(prepared["anchor_dir"])
        proof = anchor_dir / "subject.json.ots"
        proof.write_bytes(b"stable-proof")

        def successful_run(command, _timeout):
            if "info" in command:
                payload = {
                    "file_digest": prepared["anchor_id"],
                    "timestamp": {
                        "attestations": [
                            {
                                "type": "PendingAttestation",
                                "calendar": "https://a.pool.opentimestamps.org",
                            }
                        ]
                    },
                }
                return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
            return subprocess.CompletedProcess(command, 0, "ok", "")

        args = self.advance_args()
        with patch("anchor_evidence.run", successful_run):
            first = anchor.advance(args)
        self.assertEqual(first["anchors"][0]["state"], "calendar-pending")
        before = {
            path: path.read_bytes() for path in (proof, anchor_dir / "receipt.json")
        }

        def interrupted_run(command, _timeout):
            if "upgrade" in command:
                proof.write_bytes(b"partially-upgraded-proof")
            if "info" in command:
                return subprocess.CompletedProcess(command, 0, "not-json", "")
            return subprocess.CompletedProcess(command, 0, "ok", "")

        with patch("anchor_evidence.run", interrupted_run):
            with self.assertRaises(anchor.AnchorError):
                anchor.advance(args)

        for path, expected in before.items():
            self.assertEqual(path.read_bytes(), expected)
        self.assertEqual(anchor.verify_bundle(anchor_dir)["state"], "calendar-pending")


if __name__ == "__main__":
    unittest.main()
