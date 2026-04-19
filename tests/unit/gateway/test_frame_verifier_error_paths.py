#!/usr/bin/env python3
"""
Error-path tests for frame_verifier (moved from test_unit_coverage_boost.py)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.gateway import frame_verifier


class TestFrameVerifierErrorPaths:
    """Test error paths in frame_verifier.load_schema_from_path."""

    def test_load_schema_nonexistent_file(self, tmp_path):
        """Test load_schema_from_path with non-existent file returns None."""
        schema_path = tmp_path / "nonexistent_schema.json"
        result = frame_verifier.load_schema_from_path(schema_path)
        assert result is None

    def test_load_schema_invalid_json(self, tmp_path):
        """Test load_schema_from_path raises JSONDecodeError on invalid JSON content."""
        schema_path = tmp_path / "invalid_schema.json"
        schema_path.write_text("{ invalid json }", encoding="utf-8")
        with pytest.raises(json.JSONDecodeError):
            frame_verifier.load_schema_from_path(schema_path)

    def test_load_schema_non_dict_content(self, tmp_path):
        """Test load_schema_from_path raises ValueError when JSON root is not a dict."""
        schema_path = tmp_path / "array_schema.json"
        schema_path.write_text('["array", "not", "dict"]', encoding="utf-8")
        with pytest.raises(ValueError, match="must be a JSON object"):
            frame_verifier.load_schema_from_path(schema_path)

    def test_load_schema_read_permission_error(self, tmp_path):
        """Test load_schema_from_path raises PermissionError when file cannot be read."""
        schema_path = tmp_path / "unreadable_schema.json"
        schema_path.write_text('{"valid": "json"}', encoding="utf-8")

        with (
            patch.object(
                Path, "read_text", side_effect=PermissionError("Access denied")
            ),
            pytest.raises(PermissionError, match="Access denied"),
        ):
            frame_verifier.load_schema_from_path(schema_path)

    def test_validate_fact_raises_on_schema_violation(self) -> None:
        if not frame_verifier.JSONSCHEMA_AVAILABLE or frame_verifier.jsonschema is None:
            pytest.skip("jsonschema not installed")

        schema = {
            "type": "object",
            "required": ["pod_id"],
            "properties": {"pod_id": {"type": "string"}},
        }
        with pytest.raises(ValueError, match="Fact validation failure"):
            frame_verifier.validate_fact({"fc": 1}, schema)

    def test_validate_and_decrypt_framed_forwards_ingest_profile(
        self, monkeypatch
    ) -> None:
        calls: dict[str, object] = {}

        class _NativeCrypto:
            @staticmethod
            def validate_and_decrypt_framed(frame, device_entry, *, ingest_profile):
                calls["frame"] = frame
                calls["device_entry"] = device_entry
                calls["ingest_profile"] = ingest_profile
                return {"counter": 1}, None

        monkeypatch.setattr(
            frame_verifier, "_load_native_crypto", lambda: _NativeCrypto()
        )

        payload, reason = frame_verifier._validate_and_decrypt_framed(
            {"hdr": {"dev_id": 1}, "ct": "AA==", "nonce": "AA=="},
            {"1": {"ck_up": "k", "salt8": "s"}},
            ingest_profile=frame_verifier.DEFAULT_INGEST_PROFILE,
        )

        assert payload == {"counter": 1}
        assert reason == ""
        assert calls["ingest_profile"] == frame_verifier.DEFAULT_INGEST_PROFILE

    def test_admit_framed_fact_forwards_ingest_profile(self, monkeypatch) -> None:
        calls: dict[str, object] = {}

        class _NativeCrypto:
            class ReplayWindowState:
                def __init__(self, *, window_size, highest_fc_seen):
                    self.window_size = window_size
                    self.highest_fc_seen = highest_fc_seen

            @staticmethod
            def admit_framed_fact(
                frame,
                device_entry,
                state,
                *,
                ingest_time,
                ingest_time_rfc3339_utc,
                ingest_profile,
            ):
                calls["frame"] = frame
                calls["device_entry"] = device_entry
                calls["state"] = state
                calls["ingest_time"] = ingest_time
                calls["ingest_time_rfc3339_utc"] = ingest_time_rfc3339_utc
                calls["ingest_profile"] = ingest_profile
                return {"fc": 0}, None, None

        monkeypatch.setattr(
            frame_verifier, "_load_native_crypto", lambda: _NativeCrypto()
        )

        fact, reason, source = frame_verifier._admit_framed_fact(
            {"hdr": {"dev_id": 1}},
            {"1": {"ck_up": "k", "salt8": "s"}},
            {},
            window_size=64,
            ingest_time=1,
            ingest_time_rfc3339_utc="2026-01-01T00:00:01Z",
            ingest_profile=frame_verifier.DEFAULT_INGEST_PROFILE,
        )

        assert fact == {"fc": 0}
        assert reason == ""
        assert source == ""
        assert calls["ingest_profile"] == frame_verifier.DEFAULT_INGEST_PROFILE
