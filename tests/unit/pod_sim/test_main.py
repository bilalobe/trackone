#!/usr/bin/env python3
"""
Tests covering pod_sim.main CLI behavior (plain/framed/facts-out/defaults)
"""
from __future__ import annotations

import importlib.util
import json

import pytest


class TestMainFunction:
    """Test main function and CLI."""

    @staticmethod
    def _require_pynacl() -> None:
        try:
            spec = importlib.util.find_spec("nacl.bindings")
        except ModuleNotFoundError:
            spec = None
        if spec is None:
            pytest.skip("PyNaCl not installed")

    def test_main_plain_mode(self, tmp_path, pod_sim):
        out_file = tmp_path / "facts.ndjson"
        args = [
            "--device-id",
            "pod-001",
            "--site",
            "an-001",
            "--count",
            "3",
            "--out",
            str(out_file),
        ]
        assert pod_sim.main(args) == 0
        assert out_file.exists()
        lines = out_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 3
        for line in lines:
            fact = json.loads(line)
            assert fact.get("pod_id") == "0000000000000001"
            assert fact.get("kind") == "Custom"

    def test_main_framed_mode(self, tmp_path, pod_sim):
        self._require_pynacl()
        out_file = tmp_path / "frames.ndjson"
        dt_file = tmp_path / "device_table.json"
        provisioning_input = tmp_path / "provisioning" / "authoritative-input.json"
        args = [
            "--device-id",
            "pod-002",
            "--site",
            "an-001",
            "--count",
            "2",
            "--framed",
            "--out",
            str(out_file),
            "--device-table",
            str(dt_file),
            "--provisioning-input",
            str(provisioning_input),
        ]
        assert pod_sim.main(args) == 0
        assert out_file.exists() and dt_file.exists() and provisioning_input.exists()
        lines = out_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            frame = json.loads(line)
            assert {"hdr", "nonce", "ct", "tag"}.issubset(frame)
        device_table = json.loads(dt_file.read_text(encoding="utf-8"))
        assert "provisioning" not in device_table["2"]
        authoritative = json.loads(provisioning_input.read_text(encoding="utf-8"))
        assert authoritative["records"][0]["provisioning"]["site_id"] == "an-001"

    def test_main_framed_mode_requires_site_for_provisioning_input(
        self, tmp_path, pod_sim
    ):
        self._require_pynacl()
        out_file = tmp_path / "frames.ndjson"
        dt_file = tmp_path / "device_table.json"
        provisioning_input = tmp_path / "provisioning" / "authoritative-input.json"
        args = [
            "--device-id",
            "pod-002",
            "--count",
            "1",
            "--framed",
            "--out",
            str(out_file),
            "--device-table",
            str(dt_file),
            "--provisioning-input",
            str(provisioning_input),
        ]

        with pytest.raises(ValueError, match="requires a top-level site_id"):
            pod_sim.main(args)

    def test_main_with_facts_out(self, pod_sim, facts_dir, tmp_path):
        self._require_pynacl()
        frames_file = tmp_path / "frames.ndjson"
        dt_file = tmp_path / "device_table.json"
        args = [
            "--device-id",
            "pod-003",
            "--site",
            "an-001",
            "--count",
            "2",
            "--framed",
            "--out",
            str(frames_file),
            "--facts-out",
            str(facts_dir),
            "--device-table",
            str(dt_file),
        ]
        assert pod_sim.main(args) == 0
        assert frames_file.exists() and facts_dir.exists()
        # Two fact files should be written in facts_dir
        assert len(list(facts_dir.glob("*.json"))) == 2

    def test_main_default_count(self, tmp_path, pod_sim):
        out_file = tmp_path / "output.ndjson"
        args = ["--device-id", "pod-004", "--out", str(out_file)]
        assert pod_sim.main(args) == 0
        lines = out_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 10

    def test_main_creates_output_file_in_existing_dir(self, tmp_path, pod_sim):
        # main does not create parent directories for --out; ensure parent exists
        nested_dir = tmp_path / "nested" / "path"
        nested_dir.mkdir(parents=True, exist_ok=True)
        out_file = nested_dir / "output.ndjson"
        args = ["--device-id", "pod-005", "--out", str(out_file)]
        assert pod_sim.main(args) == 0
        assert out_file.exists()
