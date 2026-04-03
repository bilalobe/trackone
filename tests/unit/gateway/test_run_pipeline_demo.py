from __future__ import annotations

import json
from pathlib import Path

import pytest

from trackone_core.ledger import sha256_hex


def test_artifact_manifest_emits_schema_valid_artifact(
    tmp_path: Path, load_module
) -> None:
    module = load_module(
        "run_pipeline_demo_under_test",
        Path("scripts/gateway/run_pipeline_demo.py"),
    )

    out_dir = tmp_path / "out"
    day_dir = out_dir / "day"
    blocks_dir = out_dir / "blocks"
    facts_dir = out_dir / "facts"
    provisioning_dir = out_dir / "provisioning"
    sensorthings_dir = out_dir / "sensorthings"
    day_dir.mkdir(parents=True)
    blocks_dir.mkdir(parents=True)
    facts_dir.mkdir(parents=True)
    provisioning_dir.mkdir(parents=True)
    sensorthings_dir.mkdir(parents=True)

    day_artifact = day_dir / "2025-10-07.cbor"
    day_json = day_dir / "2025-10-07.json"
    day_sha = day_dir / "2025-10-07.cbor.sha256"
    day_ots = day_dir / "2025-10-07.cbor.ots"
    block = blocks_dir / "2025-10-07-00.block.json"
    frames_file = out_dir / "frames.ndjson"
    provisioning_input = provisioning_dir / "authoritative-input.json"
    provisioning_records = provisioning_dir / "records.json"
    projection = sensorthings_dir / "2025-10-07.observations.json"

    day_artifact.write_bytes(b"day-bytes")
    day_json.write_text("{}", encoding="utf-8")
    day_sha.write_text(
        f"{sha256_hex(b'day-bytes')}  2025-10-07.cbor\n", encoding="utf-8"
    )
    day_ots.write_bytes(b"OTS_PROOF_PLACEHOLDER")
    block.write_text(
        json.dumps(
            {
                "version": 1,
                "site_id": "an-001",
                "day": "2025-10-07",
                "batch_id": "an-001-2025-10-07-00",
                "merkle_root": "a" * 64,
                "count": 0,
                "leaf_hashes": [],
            }
        ),
        encoding="utf-8",
    )
    frames_file.write_text("", encoding="utf-8")
    provisioning_input.write_text(
        json.dumps({"version": 1, "site_id": "an-001", "records": []}),
        encoding="utf-8",
    )
    provisioning_records.write_text(
        json.dumps({"version": 1, "site_id": "an-001", "records": []}),
        encoding="utf-8",
    )
    projection.write_text(
        json.dumps(
            {
                "generated_at_utc": "2025-10-07T00:00:00Z",
                "site_id": "an-001",
                "projection_mode": "read_only_canonical_fact_json",
                "things": [],
                "datastreams": [],
                "observed_properties": [],
                "observations": [],
            }
        ),
        encoding="utf-8",
    )

    manifest_path = module.artifact_manifest(
        out_dir=out_dir,
        date="2025-10-07",
        site="an-001",
        device_id="pod-003",
        frame_count=0,
        frames_file=frames_file,
        facts_dir=facts_dir,
        day_artifact=day_artifact,
        anchoring={"ots": {"status": "pending", "reason": "placeholder"}},
        provisioning_input=provisioning_input,
        provisioning_records=provisioning_records,
        sensorthings_projection=projection,
        verifier_summary={
            "artifacts": {
                "block": str(block),
                "day_cbor": str(day_artifact),
            },
            "verification": {
                "disclosure_class": "A",
                "commitment_profile_id": "trackone-canonical-cbor-v1",
            },
            "checks_executed": ["day_artifact_validation"],
            "checks_skipped": [{"check": "ots_verification", "reason": "disabled"}],
        },
    )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest_path.name == "2025-10-07.verify.json"
    assert manifest["version"] == 1
    assert manifest["artifacts"]["provisioning_input"]["path"] == (
        "provisioning/authoritative-input.json"
    )
    assert manifest["verification_bundle"]["checks_executed"] == [
        "day_artifact_validation"
    ]
    assert manifest["verifier"]["verification"]["disclosure_class"] == "A"
    assert "artifacts" not in manifest["verifier"]


def test_clean_outputs_removes_workspace_residue(tmp_path: Path, load_module) -> None:
    module = load_module(
        "run_pipeline_demo_clean_outputs_under_test",
        Path("scripts/gateway/run_pipeline_demo.py"),
    )
    out_dir = tmp_path / "out"
    frames_file = out_dir / "frames.ndjson"
    audit_dir = out_dir / "audit"
    facts_dir = out_dir / "facts"
    out_dir.mkdir(parents=True)
    audit_dir.mkdir()
    facts_dir.mkdir()
    frames_file.write_text("{}", encoding="utf-8")
    (audit_dir / "rejections.ndjson").write_text("", encoding="utf-8")
    (facts_dir / "fact.json").write_text("{}", encoding="utf-8")

    module.clean_outputs(out_dir, frames_file, keep_existing=False)

    assert not frames_file.exists()
    assert not audit_dir.exists()
    assert not facts_dir.exists()


def test_artifact_manifest_requires_jsonschema_when_schema_present(
    tmp_path: Path, load_module, monkeypatch
) -> None:
    module = load_module(
        "run_pipeline_demo_schema_requirement_under_test",
        Path("scripts/gateway/run_pipeline_demo.py"),
    )

    out_dir = tmp_path / "out"
    day_dir = out_dir / "day"
    blocks_dir = out_dir / "blocks"
    facts_dir = out_dir / "facts"
    provisioning_dir = out_dir / "provisioning"
    sensorthings_dir = out_dir / "sensorthings"
    day_dir.mkdir(parents=True)
    blocks_dir.mkdir(parents=True)
    facts_dir.mkdir(parents=True)
    provisioning_dir.mkdir(parents=True)
    sensorthings_dir.mkdir(parents=True)

    day_artifact = day_dir / "2025-10-07.cbor"
    day_json = day_dir / "2025-10-07.json"
    day_sha = day_dir / "2025-10-07.cbor.sha256"
    day_ots = day_dir / "2025-10-07.cbor.ots"
    block = blocks_dir / "2025-10-07-00.block.json"
    frames_file = out_dir / "frames.ndjson"
    provisioning_input = provisioning_dir / "authoritative-input.json"
    provisioning_records = provisioning_dir / "records.json"
    projection = sensorthings_dir / "2025-10-07.observations.json"

    day_artifact.write_bytes(b"day-bytes")
    day_json.write_text("{}", encoding="utf-8")
    day_sha.write_text(
        f"{sha256_hex(b'day-bytes')}  2025-10-07.cbor\n", encoding="utf-8"
    )
    day_ots.write_bytes(b"OTS_PROOF_PLACEHOLDER")
    block.write_text(
        json.dumps(
            {
                "version": 1,
                "site_id": "an-001",
                "day": "2025-10-07",
                "batch_id": "an-001-2025-10-07-00",
                "merkle_root": "a" * 64,
                "count": 0,
                "leaf_hashes": [],
            }
        ),
        encoding="utf-8",
    )
    frames_file.write_text("", encoding="utf-8")
    provisioning_input.write_text(
        json.dumps({"version": 1, "site_id": "an-001", "records": []}),
        encoding="utf-8",
    )
    provisioning_records.write_text(
        json.dumps({"version": 1, "site_id": "an-001", "records": []}),
        encoding="utf-8",
    )
    projection.write_text(
        json.dumps(
            {
                "generated_at_utc": "2025-10-07T00:00:00Z",
                "site_id": "an-001",
                "projection_mode": "read_only_canonical_fact_json",
                "things": [],
                "datastreams": [],
                "observed_properties": [],
                "observations": [],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "require_schema_validation",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError(
                "jsonschema is required for pipeline verification-manifest validation"
            )
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="jsonschema is required for pipeline verification-manifest validation",
    ):
        module.artifact_manifest(
            out_dir=out_dir,
            date="2025-10-07",
            site="an-001",
            device_id="pod-003",
            frame_count=0,
            frames_file=frames_file,
            facts_dir=facts_dir,
            day_artifact=day_artifact,
            anchoring={"ots": {"status": "pending", "reason": "placeholder"}},
            provisioning_input=provisioning_input,
            provisioning_records=provisioning_records,
            sensorthings_projection=projection,
            verifier_summary={
                "checks_executed": ["day_artifact_validation"],
                "checks_skipped": [{"check": "ots_verification", "reason": "disabled"}],
            },
        )
