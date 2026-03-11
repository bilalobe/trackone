#!/usr/bin/env python3
"""
Test the fallback HKDF behavior by executing pod_sim.py under patched importlib.
"""
from __future__ import annotations

import runpy
import sys
from pathlib import Path
from unittest.mock import patch


def test_pod_sim_hkdf_fallback_runpath(tmp_path):
    repo_root = Path(__file__).resolve().parents[3]
    pod_sim_path = repo_root / "scripts" / "pod_sim" / "pod_sim.py"
    assert (
        pod_sim_path.exists()
    ), f"Canonical pod_sim implementation not found at {pod_sim_path}"

    # Patch importlib.util.spec_from_file_location so the attempt to load crypto_utils fails
    with patch("importlib.util.spec_from_file_location", return_value=None):
        module_locals = runpy.run_path(str(pod_sim_path))

    # The fallback defines hkdf_sha256 in the module locals
    assert "hkdf_sha256" in module_locals
    hkdf = module_locals["hkdf_sha256"]

    # Call hkdf to derive 16 bytes and verify type/length
    out = hkdf(b"input-ikm", None, None, 16)
    assert isinstance(out, bytes)
    assert len(out) == 16


def test_pod_sim_imports_without_pynacl(tmp_path, monkeypatch):
    repo_root = Path(__file__).resolve().parents[3]
    pod_sim_path = repo_root / "scripts" / "pod_sim" / "pod_sim.py"
    for key in list(sys.modules):
        if key == "nacl" or key.startswith("nacl."):
            monkeypatch.delitem(sys.modules, key, raising=False)

    module_locals = runpy.run_path(str(pod_sim_path))
    emit_fact = module_locals["emit_fact"]
    fact = emit_fact("pod-001", 1)

    assert fact["pod_id"] == "0000000000000001"
