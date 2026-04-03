from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_rewrite_meta_sidecar_requires_jsonschema(tmp_path: Path, load_module) -> None:
    module = load_module(
        "export_release_under_test",
        Path("scripts/evidence/export_release.py"),
    )
    source_meta = tmp_path / "2025-10-07.ots.meta.json"
    source_meta.write_text(
        json.dumps(
            {
                "artifact": "day/2025-10-07.cbor",
                "ots_proof": "day/2025-10-07.cbor.ots",
            }
        ),
        encoding="utf-8",
    )

    module.require_schema_validation = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("jsonschema is required for OTS metadata validation")
    )

    with pytest.raises(
        RuntimeError, match="jsonschema is required for OTS metadata validation"
    ):
        module._rewrite_meta_sidecar(
            source_meta,
            dest_root=tmp_path / "dest",
            day="2025-10-07",
        )
