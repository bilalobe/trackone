#!/usr/bin/env python3
"""
Edge cases for merkle_batcher (moved from test_edge_cases.py)
"""

from __future__ import annotations

import contextlib
import io
import json

import pytest

from scripts.gateway.canonical_cbor import canonicalize_obj_to_cbor


@pytest.fixture(scope="module", autouse=True)
def _load_modules(gateway_modules):
    """Load required gateway modules."""
    merkle_batcher = gateway_modules.get("merkle_batcher")
    if merkle_batcher is None:
        pytest.skip("Required gateway module 'merkle_batcher' not available")
    return merkle_batcher


class TestMerkleBatcherEdgeCases:
    """Test edge cases in merkle_batcher."""

    def test_batcher_with_empty_facts_dir(self, tmp_path, facts_dir, merkle_batcher):
        """Empty facts directory should be handled."""
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        args = [
            "--facts",
            str(facts_dir),
            "--out",
            str(out_dir),
            "--site",
            "test",
            "--date",
            "2025-10-07",
            "--allow-empty",
        ]

        result = merkle_batcher.main(args)
        assert result == 0

    def test_batcher_invalid_date_format(self, tmp_path, facts_dir, merkle_batcher):
        """Invalid date format should be rejected."""
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        # Create a fact file (authoritative CBOR + JSON projection)
        fact_obj = {
            "pod_id": "0000000000000001",
            "fc": 1,
            "ingest_time": 1759831200,
            "ingest_time_rfc3339_utc": "2025-10-07T10:00:00Z",
            "pod_time": None,
            "kind": "Custom",
            "payload": {},
        }
        fact_stem = facts_dir / "fact"
        fact_stem.with_suffix(".cbor").write_bytes(canonicalize_obj_to_cbor(fact_obj))
        fact_stem.with_suffix(".json").write_text(json.dumps(fact_obj))

        args = [
            "--facts",
            str(facts_dir),
            "--out",
            str(out_dir),
            "--site",
            "test",
            "--date",
            "invalid-date",
        ]

        result = merkle_batcher.main(args)
        # Should fail gracefully
        assert result != 0

    def test_batcher_nonexistent_facts_dir(self, tmp_path, merkle_batcher):
        """Nonexistent facts directory should be handled."""
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        args = [
            "--facts",
            str(tmp_path / "nonexistent"),
            "--out",
            str(out_dir),
            "--site",
            "test",
            "--date",
            "2025-10-07",
        ]

        result = merkle_batcher.main(args)
        assert result != 0

    @pytest.mark.parametrize(
        "site_id",
        [
            "site-001",
            "s",
            "a" * 50,
            "site_with_underscore",
        ],
    )
    def test_batcher_various_site_ids(
        self, tmp_path, facts_dir, merkle_batcher, site_id
    ):
        """Test various site ID formats."""
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        fact_obj = {
            "pod_id": "0000000000000001",
            "fc": 1,
            "ingest_time": 1759831200,
            "ingest_time_rfc3339_utc": "2025-10-07T10:00:00Z",
            "pod_time": None,
            "kind": "Custom",
            "payload": {},
        }
        fact_stem = facts_dir / "fact"
        fact_stem.with_suffix(".cbor").write_bytes(canonicalize_obj_to_cbor(fact_obj))
        fact_stem.with_suffix(".json").write_text(json.dumps(fact_obj))

        args = [
            "--facts",
            str(facts_dir),
            "--out",
            str(out_dir),
            "--site",
            site_id,
            "--date",
            "2025-10-07",
        ]

        result = merkle_batcher.main(args)
        assert result == 0

    def test_batcher_requires_native_ledger(
        self, monkeypatch, tmp_path, facts_dir, merkle_batcher
    ):
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        fact_obj = {
            "pod_id": "0000000000000001",
            "fc": 1,
            "ingest_time": 1759831200,
            "ingest_time_rfc3339_utc": "2025-10-07T10:00:00Z",
            "pod_time": None,
            "kind": "Custom",
            "payload": {},
        }
        fact_stem = facts_dir / "fact"
        fact_stem.with_suffix(".cbor").write_bytes(canonicalize_obj_to_cbor(fact_obj))
        fact_stem.with_suffix(".json").write_text(json.dumps(fact_obj))

        monkeypatch.setattr(merkle_batcher, "native_ledger", None)

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = merkle_batcher.main(
                [
                    "--facts",
                    str(facts_dir),
                    "--out",
                    str(out_dir),
                    "--site",
                    "test",
                    "--date",
                    "2025-10-07",
                ]
            )

        assert result == 1
        assert "trackone_core native ledger helper is required" in stderr.getvalue()
