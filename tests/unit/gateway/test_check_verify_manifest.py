from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_check_verify_manifest_requires_jsonschema(
    tmp_path: Path, load_module, monkeypatch
) -> None:
    module = load_module(
        "check_verify_manifest_under_test",
        Path("scripts/gateway/check_verify_manifest.py"),
    )
    root = tmp_path / "out"
    day_dir = root / "day"
    facts_dir = root / "facts"
    day_dir.mkdir(parents=True)
    facts_dir.mkdir(parents=True)
    manifest_path = day_dir / "2025-10-07.verify.json"
    manifest_path.write_text(json.dumps({"version": 1}), encoding="utf-8")

    monkeypatch.setattr(
        module,
        "require_schema_validation",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("jsonschema is required for verification manifest checks")
        ),
    )

    with pytest.raises(
        RuntimeError, match="jsonschema is required for verification manifest checks"
    ):
        module.main(
            [
                "--root",
                str(root),
                "--facts",
                str(facts_dir),
                "--day",
                "2025-10-07",
            ]
        )
