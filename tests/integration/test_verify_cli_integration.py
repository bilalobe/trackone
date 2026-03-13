"""
Verify CLI integration tests.

Tests the verify_cli module for:
- Placeholder OTS proof acceptance
- External 'ots' binary integration (mocked and real)
- End-to-end verification workflow
"""

from __future__ import annotations

import json
import shutil
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def test_verify_ots_accepts_placeholder(
    tmp_path: Path, verify_cli, write_ots_placeholder
):
    """verify_ots should accept OTS_PROOF_PLACEHOLDER files."""
    # write_ots_placeholder returns (ots_path, meta_path); unpack both for clarity
    ots_path, _meta = write_ots_placeholder(tmp_path, "2025-10-07")
    assert verify_cli.verify_ots(ots_path) is True


def test_verify_ots_missing_binary_returns_false(
    tmp_path: Path, verify_cli, monkeypatch
):
    """verify_ots should return False when 'ots' binary is not available."""
    ots_path = tmp_path / "2025-10-07.cbor.ots"
    ots_path.write_text("REAL_PROOF_BYTES\n", encoding="utf-8")

    monkeypatch.setattr(shutil, "which", lambda _: None)
    assert verify_cli.verify_ots(ots_path) is False


@patch("verify_cli.subprocess.run")
def test_verify_ots_external_success(mock_run, tmp_path: Path, verify_cli, monkeypatch):
    """verify_ots should invoke external 'ots verify' and return True on success."""
    ots_path = tmp_path / "2025-10-07.cbor.ots"
    ots_path.write_text("REAL_PROOF_BYTES\n", encoding="utf-8")

    # Create a fake 'ots' executable file
    fake_ots = tmp_path / "ots"
    fake_ots.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_ots.chmod(fake_ots.stat().st_mode | stat.S_IEXEC)

    # Mock subprocess.run to simulate successful verification
    mock_run.return_value = SimpleNamespace(returncode=0)
    monkeypatch.setattr(shutil, "which", lambda _: str(fake_ots))

    # Should return True on success
    result = verify_cli.verify_ots(ots_path)
    assert result is True


class TestVerifyCliMainPlaceholder:
    """Integration tests for verify_cli.main with placeholder OTS proofs."""

    def test_end_to_end_with_placeholder(
        self,
        tmp_path: Path,
        merkle_batcher,
        verify_cli,
        write_sample_facts_fixture,
        sample_facts,
        write_ots_placeholder,
    ):
        """Run batcher → create OTS placeholder → verify CLI."""
        facts_dir = tmp_path / "facts"
        out_dir = tmp_path / "out"
        out_dir.mkdir(parents=True, exist_ok=True)

        # Write sample facts
        write_sample_facts_fixture(facts_dir, sample_facts)

        # Run batcher to create block/day outputs
        args = [
            "--facts",
            str(facts_dir),
            "--out",
            str(out_dir),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
        ]
        assert merkle_batcher.main(args) == 0

        # Verify day.cbor exists
        day_bin = out_dir / "day" / "2025-10-07.cbor"
        assert day_bin.exists()

        # Create placeholder OTS proof and meta sidecar
        ots_path, meta_path = write_ots_placeholder(out_dir, "2025-10-07")
        assert ots_path.exists()
        assert meta_path.exists()

        # Run verify_cli against the output
        verify_args = ["--root", str(out_dir), "--facts", str(facts_dir)]
        rc = verify_cli.main(verify_args)
        assert rc == 0


def test_require_ots_rejects_placeholder(
    tmp_path: Path,
    merkle_batcher,
    verify_cli,
    write_sample_facts_fixture,
    sample_facts,
    write_ots_placeholder,
):
    """When --require-ots is set, placeholder .ots files should cause verification to fail."""
    facts_dir = tmp_path / "facts"
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    write_sample_facts_fixture(facts_dir, sample_facts)

    args = [
        "--facts",
        str(facts_dir),
        "--out",
        str(out_dir),
        "--site",
        "test-site",
        "--date",
        "2025-10-07",
    ]
    assert merkle_batcher.main(args) == 0

    # Create placeholder proof and write ots_meta into the workspace day/
    write_ots_placeholder(out_dir, "2025-10-07")

    verify_args = [
        "--root",
        str(out_dir),
        "--facts",
        str(facts_dir),
        "--require-ots",
    ]
    # require-ots should treat placeholders as invalid -> non-zero exit
    assert verify_cli.main(verify_args) != 0


def test_require_ots_accepts_real_ots(
    tmp_path: Path,
    merkle_batcher,
    verify_cli,
    write_sample_facts_fixture,
    sample_facts,
    monkeypatch,
):
    """When --require-ots is set, a real 'ots' executable that verifies should allow success."""
    facts_dir = tmp_path / "facts"
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    write_sample_facts_fixture(facts_dir, sample_facts)

    args = [
        "--facts",
        str(facts_dir),
        "--out",
        str(out_dir),
        "--site",
        "test-site",
        "--date",
        "2025-10-07",
    ]
    assert merkle_batcher.main(args) == 0

    # Create a realistic .ots file and a fake 'ots' binary that returns success
    day_bin = out_dir / "day" / "2025-10-07.cbor"
    ots_path = day_bin.with_suffix(day_bin.suffix + ".ots")
    ots_path.write_text("REAL_PROOF_BYTES\n", encoding="utf-8")

    fake_ots = tmp_path / "ots"
    fake_ots.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_ots.chmod(fake_ots.stat().st_mode | stat.S_IEXEC)

    monkeypatch.setattr(shutil, "which", lambda _: str(fake_ots))

    verify_args = [
        "--root",
        str(out_dir),
        "--facts",
        str(facts_dir),
        "--require-ots",
    ]

    rc = verify_cli.main(verify_args)
    assert rc == 0


def test_ots_failure_still_reports_public_recompute_capability(
    tmp_path: Path,
    merkle_batcher,
    verify_cli,
    write_sample_facts_fixture,
    sample_facts,
    monkeypatch,
    capsys,
):
    """Class A should still report public recompute when root/artifact checks passed."""
    facts_dir = tmp_path / "facts"
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    write_sample_facts_fixture(facts_dir, sample_facts)

    args = [
        "--facts",
        str(facts_dir),
        "--out",
        str(out_dir),
        "--site",
        "test-site",
        "--date",
        "2025-10-07",
    ]
    assert merkle_batcher.main(args) == 0

    day_cbor = out_dir / "day" / "2025-10-07.cbor"
    ots_path = day_cbor.with_suffix(day_cbor.suffix + ".ots")
    ots_path.write_text("REAL_PROOF_BYTES\n", encoding="utf-8")

    fake_ots = tmp_path / "ots"
    fake_ots.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    fake_ots.chmod(fake_ots.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(shutil, "which", lambda _: str(fake_ots))

    capsys.readouterr()
    rc = verify_cli.main(
        [
            "--root",
            str(out_dir),
            "--facts",
            str(facts_dir),
            "--json",
        ]
    )
    assert rc == verify_cli.EXIT_OTS_FAILED

    parsed = json.loads(capsys.readouterr().out)
    assert parsed["checks"]["artifact_valid"] is True
    assert parsed["checks"]["root_match"] is True
    assert parsed["verification"]["publicly_recomputable"] is True


def test_require_ots_overrides_disabled_ots_config(
    tmp_path: Path,
    merkle_batcher,
    verify_cli,
    write_sample_facts_fixture,
    sample_facts,
):
    """--require-ots must enforce OTS even when config has ots.enabled=false."""
    facts_dir = tmp_path / "facts"
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    write_sample_facts_fixture(facts_dir, sample_facts)

    args = [
        "--facts",
        str(facts_dir),
        "--out",
        str(out_dir),
        "--site",
        "test-site",
        "--date",
        "2025-10-07",
    ]
    assert merkle_batcher.main(args) == 0

    cfg_path = tmp_path / "anchoring.toml"
    cfg_path.write_text("[ots]\nenabled = false\n", encoding="utf-8")

    rc = verify_cli.main(
        [
            "--root",
            str(out_dir),
            "--facts",
            str(facts_dir),
            "--config",
            str(cfg_path),
            "--require-ots",
        ]
    )
    assert rc == 3


class TestVerifyCliTsaPeerIntegration:
    """Integration tests for TSA and peer verification."""

    def test_verify_with_tsa_warn_mode(
        self,
        tmp_path: Path,
        merkle_batcher,
        verify_cli,
        write_sample_facts_fixture,
        sample_facts,
        write_ots_placeholder,
    ):
        """Verify CLI should warn when TSA artifact missing (non-strict)."""
        facts_dir = tmp_path / "facts"
        out_dir = tmp_path / "out"
        out_dir.mkdir(parents=True, exist_ok=True)

        write_sample_facts_fixture(facts_dir, sample_facts)

        args = [
            "--facts",
            str(facts_dir),
            "--out",
            str(out_dir),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
        ]
        assert merkle_batcher.main(args) == 0

        write_ots_placeholder(out_dir, "2025-10-07")

        # Run with --verify-tsa but no TSA artifacts present
        verify_args = [
            "--root",
            str(out_dir),
            "--facts",
            str(facts_dir),
            "--verify-tsa",
        ]
        rc = verify_cli.main(verify_args)
        # Should succeed with warning (non-strict)
        assert rc == 0

    def test_verify_with_tsa_strict_mode_fails(
        self,
        tmp_path: Path,
        merkle_batcher,
        verify_cli,
        write_sample_facts_fixture,
        sample_facts,
        write_ots_placeholder,
    ):
        """Verify CLI should fail when TSA artifact missing (strict mode)."""
        facts_dir = tmp_path / "facts"
        out_dir = tmp_path / "out"
        out_dir.mkdir(parents=True, exist_ok=True)

        write_sample_facts_fixture(facts_dir, sample_facts)

        args = [
            "--facts",
            str(facts_dir),
            "--out",
            str(out_dir),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
        ]
        assert merkle_batcher.main(args) == 0

        write_ots_placeholder(out_dir, "2025-10-07")

        # Run with --verify-tsa --tsa-strict but no TSA artifacts present
        verify_args = [
            "--root",
            str(out_dir),
            "--facts",
            str(facts_dir),
            "--verify-tsa",
            "--tsa-strict",
        ]
        rc = verify_cli.main(verify_args)
        # Should fail with exit code 5
        assert rc == 5

    def test_verify_with_peers_warn_mode(
        self,
        tmp_path: Path,
        merkle_batcher,
        verify_cli,
        write_sample_facts_fixture,
        sample_facts,
        write_ots_placeholder,
    ):
        """Verify CLI should warn when peer attestation missing (non-strict)."""
        facts_dir = tmp_path / "facts"
        out_dir = tmp_path / "out"
        out_dir.mkdir(parents=True, exist_ok=True)

        write_sample_facts_fixture(facts_dir, sample_facts)

        args = [
            "--facts",
            str(facts_dir),
            "--out",
            str(out_dir),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
        ]
        assert merkle_batcher.main(args) == 0

        write_ots_placeholder(out_dir, "2025-10-07")

        # Run with --verify-peers but no peer artifacts present
        verify_args = [
            "--root",
            str(out_dir),
            "--facts",
            str(facts_dir),
            "--verify-peers",
        ]
        rc = verify_cli.main(verify_args)
        # Should succeed with warning (non-strict)
        assert rc == 0

    def test_verify_with_peers_strict_mode_fails(
        self,
        tmp_path: Path,
        merkle_batcher,
        verify_cli,
        write_sample_facts_fixture,
        sample_facts,
        write_ots_placeholder,
    ):
        """Verify CLI should fail when peer attestation missing (strict mode)."""
        facts_dir = tmp_path / "facts"
        out_dir = tmp_path / "out"
        out_dir.mkdir(parents=True, exist_ok=True)

        write_sample_facts_fixture(facts_dir, sample_facts)

        args = [
            "--facts",
            str(facts_dir),
            "--out",
            str(out_dir),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
        ]
        assert merkle_batcher.main(args) == 0

        write_ots_placeholder(out_dir, "2025-10-07")

        # Run with --verify-peers --peers-strict but no peer artifacts present
        verify_args = [
            "--root",
            str(out_dir),
            "--facts",
            str(facts_dir),
            "--verify-peers",
            "--peers-strict",
        ]
        rc = verify_cli.main(verify_args)
        # Should fail with exit code 6
        assert rc == 6


def test_disclosure_class_b_reports_non_public_recompute(
    tmp_path: Path,
    merkle_batcher,
    verify_cli,
    write_sample_facts_fixture,
    sample_facts,
    write_ots_placeholder,
    capsys,
):
    """Class B must skip fact-level recomputation and never claim public recompute."""
    facts_dir = tmp_path / "facts"
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    write_sample_facts_fixture(facts_dir, sample_facts)
    assert (
        merkle_batcher.main(
            [
                "--facts",
                str(facts_dir),
                "--out",
                str(out_dir),
                "--site",
                "test-site",
                "--date",
                "2025-10-07",
            ]
        )
        == 0
    )

    write_ots_placeholder(out_dir, "2025-10-07")
    capsys.readouterr()
    rc = verify_cli.main(
        [
            "--root",
            str(out_dir),
            "--facts",
            str(facts_dir),
            "--disclosure-class",
            "B",
            "--json",
        ]
    )
    assert rc == 0

    parsed = json.loads(capsys.readouterr().out)
    assert parsed["verification"]["disclosure_class"] == "B"
    assert parsed["verification"]["publicly_recomputable"] is False
    assert parsed["checks"]["root_match"] is None
    assert {
        "check": "fact_level_recompute",
        "reason": "disclosure-class-b",
    } in parsed["checks_skipped"]


def test_disclosure_class_c_reports_anchor_only(
    tmp_path: Path,
    merkle_batcher,
    verify_cli,
    write_sample_facts_fixture,
    sample_facts,
    write_ots_placeholder,
    capsys,
):
    """Class C must label anchor-only evidence and skip fact recomputation."""
    facts_dir = tmp_path / "facts"
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    write_sample_facts_fixture(facts_dir, sample_facts)
    assert (
        merkle_batcher.main(
            [
                "--facts",
                str(facts_dir),
                "--out",
                str(out_dir),
                "--site",
                "test-site",
                "--date",
                "2025-10-07",
            ]
        )
        == 0
    )

    write_ots_placeholder(out_dir, "2025-10-07")
    capsys.readouterr()
    rc = verify_cli.main(
        [
            "--root",
            str(out_dir),
            "--facts",
            str(facts_dir),
            "--disclosure-class",
            "C",
            "--json",
        ]
    )
    assert rc == 0

    parsed = json.loads(capsys.readouterr().out)
    assert parsed["verification"]["disclosure_class"] == "C"
    assert parsed["verification"]["disclosure_label"] == "anchor-only-evidence"
    assert parsed["verification"]["publicly_recomputable"] is False
    assert parsed["checks"]["root_match"] is None
    assert {
        "check": "fact_level_recompute",
        "reason": "disclosure-class-c",
    } in parsed["checks_skipped"]
