"""Structural + regex guard against embedding OTS proofs in hashed payload JSON.

This test complements the lightweight scanner in ``scripts/lint/scan_embedded_proofs.py``.
It does a focused walk over unified schemas and example payloads and fails if it
finds suspicious keys like ``ots_proof`` in contexts that should stay proof-free.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = REPO_ROOT / "toolset" / "unified" / "schemas"
EXAMPLES_DIR = REPO_ROOT / "toolset" / "unified" / "examples"


@pytest.mark.parametrize("path", sorted(SCHEMA_DIR.glob("*.schema.json")))
def test_schemas_do_not_embed_ots_proofs_in_hashed_payloads(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))

    def walk(obj, prefix: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_path = f"{prefix}.{k}" if prefix else k
                # Disallow any property literally called ots_proof in core hashed payload schemas.
                if k == "ots_proof" and path.name == "day_record.schema.json":
                    pytest.fail(
                        f"day_record schema MUST NOT define ots_proof (found at {key_path})"
                    )
                walk(v, key_path)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                walk(item, f"{prefix}[{idx}]")

    walk(data)


@pytest.mark.parametrize("path", sorted(EXAMPLES_DIR.glob("*.json")))
def test_example_payloads_do_not_embed_ots_proofs(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))

    def walk(obj, prefix: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_path = f"{prefix}.{k}" if prefix else k
                if k == "ots_proof":
                    pytest.fail(
                        f"Example payload {path} MUST NOT embed ots_proof (found at {key_path})"
                    )
                walk(v, key_path)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                walk(item, f"{prefix}[{idx}]")

    walk(data)
