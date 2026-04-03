"""
Frame security and tamper detection tests.

Tests that the frame_verifier correctly rejects frames with:
- Tampered ciphertext, authentication tags, or AAD
- Invalid nonce lengths
- Unknown device IDs
- Malformed or missing header fields
"""

from __future__ import annotations

import json
from base64 import b64decode, b64encode
from pathlib import Path


def verify_frames(frames: Path, facts: Path, device_table: Path, frame_verifier) -> int:
    """Helper to run frame verification with standard arguments."""
    args = [
        "--in",
        str(frames),
        "--out-facts",
        str(facts),
        "--device-table",
        str(device_table),
        "--window",
        "64",
    ]
    return frame_verifier.process(args)


class TestTamper:
    """Test frame tamper detection and rejection."""

    def test_tampered_ciphertext_rejected(
        self, temp_dirs, write_frames, frame_verifier, write_frame_json
    ):
        """Frames with tampered ciphertext should be rejected."""
        temp_dirs["root"].mkdir(parents=True, exist_ok=True)
        write_frames("pod-010", 1, temp_dirs["frames"], temp_dirs["device_table"])

        # Load, tamper ciphertext
        f = json.loads(temp_dirs["frames"].read_text(encoding="utf-8").splitlines()[0])
        b = bytearray(b64decode(f["ct"]))
        b[0] ^= 0x01
        f["ct"] = b64encode(bytes(b)).decode("ascii")
        write_frame_json(temp_dirs["frames"], f)

        # Verify → expect 0 facts
        rc = verify_frames(
            temp_dirs["frames"],
            temp_dirs["facts"],
            temp_dirs["device_table"],
            frame_verifier,
        )
        assert rc == 0
        assert not list(temp_dirs["facts"].glob("*.json"))

    def test_tampered_tag_rejected(
        self, temp_dirs, write_frames, frame_verifier, write_frame_json
    ):
        """Frames with tampered authentication tags should be rejected."""
        temp_dirs["root"].mkdir(parents=True, exist_ok=True)
        write_frames("pod-011", 1, temp_dirs["frames"], temp_dirs["device_table"])

        f = json.loads(temp_dirs["frames"].read_text().strip())
        t = bytearray(b64decode(f["tag"]))
        t[0] ^= 0xFF
        f["tag"] = b64encode(bytes(t)).decode("ascii")
        write_frame_json(temp_dirs["frames"], f)

        rc = verify_frames(
            temp_dirs["frames"],
            temp_dirs["facts"],
            temp_dirs["device_table"],
            frame_verifier,
        )
        assert rc == 0
        assert not list(temp_dirs["facts"].glob("*.json"))

    def test_tampered_aad_rejected(
        self, temp_dirs, write_frames, frame_verifier, write_frame_json
    ):
        """Frames with tampered AAD should be rejected."""
        temp_dirs["root"].mkdir(parents=True, exist_ok=True)
        write_frames("pod-012", 1, temp_dirs["frames"], temp_dirs["device_table"])

        f = json.loads(temp_dirs["frames"].read_text().strip())
        # Change msg_type in header (affects AAD)
        f["hdr"]["msg_type"] ^= 0x01
        write_frame_json(temp_dirs["frames"], f)

        rc = verify_frames(
            temp_dirs["frames"],
            temp_dirs["facts"],
            temp_dirs["device_table"],
            frame_verifier,
        )
        assert rc == 0
        assert not list(temp_dirs["facts"].glob("*.json"))

    def test_invalid_nonce_length_rejected(
        self, temp_dirs, write_frames, frame_verifier, write_frame_json
    ):
        """Frames with invalid nonce lengths should be rejected."""
        temp_dirs["root"].mkdir(parents=True, exist_ok=True)
        write_frames("pod-013", 1, temp_dirs["frames"], temp_dirs["device_table"])

        f = json.loads(temp_dirs["frames"].read_text().strip())
        n = b64decode(f["nonce"])[:-1]  # drop a byte → 11 bytes
        f["nonce"] = b64encode(n).decode("ascii")
        write_frame_json(temp_dirs["frames"], f)

        rc = verify_frames(
            temp_dirs["frames"],
            temp_dirs["facts"],
            temp_dirs["device_table"],
            frame_verifier,
        )
        assert rc == 0
        assert not list(temp_dirs["facts"].glob("*.json"))

    def test_unknown_device_rejected(
        self, temp_dirs, write_frames, frame_verifier, write_frame_json
    ):
        """Frames from unknown devices should be rejected."""
        temp_dirs["root"].mkdir(parents=True, exist_ok=True)
        write_frames("pod-014", 1, temp_dirs["frames"], temp_dirs["device_table"])

        f = json.loads(temp_dirs["frames"].read_text().strip())
        # Change device id in header to a different one not present in device_table
        f["hdr"]["dev_id"] = 999
        write_frame_json(temp_dirs["frames"], f)

        rc = verify_frames(
            temp_dirs["frames"],
            temp_dirs["facts"],
            temp_dirs["device_table"],
            frame_verifier,
        )
        assert rc == 0
        assert not list(temp_dirs["facts"].glob("*.json"))

    def test_oversized_ciphertext_rejected(
        self, temp_dirs, write_frames, frame_verifier, write_frame_json
    ):
        """Frames with oversized ciphertext should be rejected before decrypt."""
        temp_dirs["root"].mkdir(parents=True, exist_ok=True)
        write_frames("pod-016", 1, temp_dirs["frames"], temp_dirs["device_table"])

        f = json.loads(temp_dirs["frames"].read_text().strip())
        f["ct"] = b64encode(b"\x00" * (frame_verifier.MAX_CIPHERTEXT_BYTES + 1)).decode(
            "ascii"
        )
        write_frame_json(temp_dirs["frames"], f)

        rc = verify_frames(
            temp_dirs["frames"],
            temp_dirs["facts"],
            temp_dirs["device_table"],
            frame_verifier,
        )
        assert rc == 0
        assert not list(temp_dirs["facts"].glob("*.json"))


class TestFrameStructure:
    """Test frame structure validation and resilience."""

    def test_missing_header_field_rejected(
        self, temp_dirs, write_frames, frame_verifier, write_frame_json
    ):
        """Frames with missing header fields should be rejected."""
        temp_dirs["root"].mkdir(parents=True, exist_ok=True)
        write_frames("pod-015", 1, temp_dirs["frames"], temp_dirs["device_table"])

        f = json.loads(temp_dirs["frames"].read_text().strip())
        # Remove a required header field
        del f["hdr"]["fc"]
        write_frame_json(temp_dirs["frames"], f)

        rc = verify_frames(
            temp_dirs["frames"],
            temp_dirs["facts"],
            temp_dirs["device_table"],
            frame_verifier,
        )
        assert rc == 0
        assert not list(temp_dirs["facts"].glob("*.json"))

    def test_malformed_json_rejected(self, temp_dirs, frame_verifier):
        """Malformed JSON frames should be rejected gracefully."""
        temp_dirs["root"].mkdir(parents=True, exist_ok=True)
        temp_dirs["frames"].write_text("not valid json\n", encoding="utf-8")

        rc = verify_frames(
            temp_dirs["frames"],
            temp_dirs["facts"],
            temp_dirs["device_table"],
            frame_verifier,
        )
        assert rc == 0
        assert not list(temp_dirs["facts"].glob("*.json"))

    def test_empty_frame_file_handled(self, temp_dirs, frame_verifier):
        """Empty frame files should be handled gracefully."""
        temp_dirs["root"].mkdir(parents=True, exist_ok=True)
        temp_dirs["frames"].write_text("", encoding="utf-8")

        rc = verify_frames(
            temp_dirs["frames"],
            temp_dirs["facts"],
            temp_dirs["device_table"],
            frame_verifier,
        )
        assert rc == 0
