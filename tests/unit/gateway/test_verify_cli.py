#!/usr/bin/env python3
"""
Edge cases for verify_cli (moved from test_edge_cases.py)
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


class TestVerifyCliEdgeCases:
    """Test edge cases in verify_cli."""

    def test_verify_cli_direct_script_mode_imports_schema_validation_helpers(self):
        repo_root = Path(__file__).resolve().parents[3]
        pythonpath = os.pathsep.join(
            [
                str(repo_root),
                os.environ.get("PYTHONPATH", ""),
            ]
        ).rstrip(os.pathsep)
        result = subprocess.run(
            [sys.executable, "scripts/gateway/verify_cli.py", "--help"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "PYTHONPATH": pythonpath},
        )

        assert result.returncode == 0
        assert "usage:" in result.stdout.lower()
        assert "NameError" not in result.stderr

    def test_verify_nonexistent_root_dir(self, tmp_path, verify_cli, facts_dir):
        """Nonexistent root directory should be handled."""
        args = [
            "--root",
            str(tmp_path / "nonexistent"),
            "--facts",
            str(facts_dir),
        ]

        result = verify_cli.main(args)
        # Expect specific error code for missing block header
        assert isinstance(result, int)
        assert result == 1

    def test_verify_empty_day_directory(self, tmp_path, verify_cli, facts_dir):
        """Empty day directory should be handled."""
        root = tmp_path / "out"
        day_dir = root / "day"
        block_dir = root / "block"

        day_dir.mkdir(parents=True)
        block_dir.mkdir(parents=True)

        args = [
            "--root",
            str(root),
            "--facts",
            str(facts_dir),
        ]

        result = verify_cli.main(args)
        # No block header -> specific return code
        assert result == 1

    def test_verify_missing_ots_file(self, tmp_path, verify_cli, facts_dir):
        """Missing OTS file should be handled."""
        root = tmp_path / "out"
        day_dir = root / "day"

        day_dir.mkdir(parents=True)

        # Create day.cbor but no .ots file
        day_bin = day_dir / "2025-10-07.cbor"
        day_bin.write_bytes(b"test data")

        args = [
            "--root",
            str(root),
            "--facts",
            str(facts_dir),
        ]

        result = verify_cli.main(args)
        # Missing block header -> return code 1 (no block header found)
        assert result == 1

    def test_verify_merkle_root_requires_native_merkle(self, monkeypatch, verify_cli):
        monkeypatch.setattr(verify_cli, "_RUST_MERKLE", None)
        with pytest.raises(
            RuntimeError, match="trackone_core native merkle helper is required"
        ):
            verify_cli.merkle_root([b"leaf"])

    def test_verify_rejects_legacy_day_bin_artifact(
        self, tmp_path, verify_cli, facts_dir
    ):
        root = tmp_path / "out"
        day_dir = root / "day"
        blocks_dir = root / "blocks"
        day_dir.mkdir(parents=True)
        blocks_dir.mkdir(parents=True)

        day = "2025-10-07"
        (day_dir / f"{day}.bin").write_bytes(b"legacy")
        (day_dir / f"{day}.json").write_text(
            json.dumps({"date": day, "day_root": "a" * 64}),
            encoding="utf-8",
        )
        (blocks_dir / f"{day}-00.block.json").write_text(
            json.dumps({"day": day, "merkle_root": "a" * 64}),
            encoding="utf-8",
        )

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = verify_cli.main(["--root", str(root), "--facts", str(facts_dir)])
        assert result == 1
        err = stderr.getvalue()
        assert "legacy day artifact found" in err
        assert ".cbor" in err

    def test_verify_main_requires_native_ledger_for_day_canonicalization(
        self, monkeypatch, tmp_path, verify_cli, facts_dir
    ):
        root = tmp_path / "out"
        day_dir = root / "day"
        blocks_dir = root / "blocks"
        day_dir.mkdir(parents=True)
        blocks_dir.mkdir(parents=True)

        day = "2025-10-07"
        day_record = {
            "version": 1,
            "site_id": "test-site",
            "date": day,
            "prev_day_root": "00" * 32,
            "batches": [],
            "day_root": "a" * 64,
        }
        (day_dir / f"{day}.json").write_text(json.dumps(day_record), encoding="utf-8")
        (day_dir / f"{day}.cbor").write_bytes(b"placeholder")
        (blocks_dir / f"{day}-00.block.json").write_text(
            json.dumps(
                {
                    "day": day,
                    "site_id": "test-site",
                    "merkle_root": "a" * 64,
                }
            ),
            encoding="utf-8",
        )

        monkeypatch.setattr(verify_cli, "_RUST_LEDGER", None)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = verify_cli.main(["--root", str(root), "--facts", str(facts_dir)])

        assert result == 1
        assert "trackone_core native ledger helper is required" in stdout.getvalue()

    def test_verify_main_emits_summary_on_native_merkle_recompute_failure(
        self, monkeypatch, tmp_path, verify_cli
    ):
        root = tmp_path / "out"
        day_dir = root / "day"
        blocks_dir = root / "blocks"
        facts_dir = root / "facts"
        day_dir.mkdir(parents=True)
        blocks_dir.mkdir(parents=True)
        facts_dir.mkdir(parents=True)

        day = "2025-10-07"
        day_record = {
            "version": 1,
            "site_id": "test-site",
            "date": day,
            "prev_day_root": "00" * 32,
            "batches": [],
            "day_root": "a" * 64,
        }
        day_json = json.dumps(day_record)
        day_cbor = b"native-day-cbor"
        (day_dir / f"{day}.json").write_text(day_json, encoding="utf-8")
        (day_dir / f"{day}.cbor").write_bytes(day_cbor)
        (blocks_dir / f"{day}-00.block.json").write_text(
            json.dumps(
                {
                    "day": day,
                    "site_id": "test-site",
                    "merkle_root": "a" * 64,
                }
            ),
            encoding="utf-8",
        )
        (facts_dir / "fact-00000001.cbor").write_bytes(b"fact")

        class _FakeLedger:
            @staticmethod
            def canonicalize_json_to_cbor_bytes(_input_bytes):
                return day_cbor

        monkeypatch.setattr(verify_cli, "_RUST_LEDGER", _FakeLedger())

        def _raise_merkle(_leaves):
            raise RuntimeError("native merkle unavailable")

        monkeypatch.setattr(verify_cli, "merkle_root", _raise_merkle)

        stdout = io.StringIO()
        result = None
        with contextlib.redirect_stdout(stdout):
            result = verify_cli.main(
                ["--root", str(root), "--facts", str(facts_dir), "--json"]
            )

        assert result == 1
        out = stdout.getvalue()
        assert "Failed to recompute authoritative Merkle root" in out
        assert '"root_match": false' in out
