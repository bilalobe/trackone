#!/usr/bin/env python3
"""Tests covering pod_sim.main CLI behavior."""

from __future__ import annotations

import json

import pytest


class TestMainFunction:
    """Test main function and CLI."""

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

    def test_main_default_count(self, tmp_path, pod_sim):
        out_file = tmp_path / "output.ndjson"
        args = ["--device-id", "pod-004", "--out", str(out_file)]
        assert pod_sim.main(args) == 0
        lines = out_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 10

    def test_main_rejects_removed_framed_mode(self, tmp_path, pod_sim):
        out_file = tmp_path / "frames.ndjson"
        with pytest.raises(SystemExit):
            pod_sim.main(["--framed", "--out", str(out_file)])

    def test_main_creates_output_file_in_existing_dir(self, tmp_path, pod_sim):
        # main does not create parent directories for --out; ensure parent exists
        nested_dir = tmp_path / "nested" / "path"
        nested_dir.mkdir(parents=True, exist_ok=True)
        out_file = nested_dir / "output.ndjson"
        args = ["--device-id", "pod-005", "--out", str(out_file)]
        assert pod_sim.main(args) == 0
        assert out_file.exists()
