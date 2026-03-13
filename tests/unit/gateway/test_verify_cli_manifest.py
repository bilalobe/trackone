from __future__ import annotations

import json
from pathlib import Path


def test_verify_cli_accepts_matching_pipeline_manifest(
    tmp_path: Path,
    merkle_batcher,
    verify_cli,
    write_sample_facts_fixture,
    sample_facts,
    write_ots_placeholder,
    load_module,
):
    out_dir = tmp_path / "out"
    facts_dir = out_dir / "facts"
    provisioning_dir = out_dir / "provisioning"
    projection_dir = out_dir / "sensorthings"
    out_dir.mkdir(parents=True, exist_ok=True)
    provisioning_dir.mkdir(parents=True, exist_ok=True)
    projection_dir.mkdir(parents=True, exist_ok=True)

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

    provisioning_input = provisioning_dir / "authoritative-input.json"
    provisioning_input.write_text(
        json.dumps({"version": 1, "site_id": "test-site", "records": []}),
        encoding="utf-8",
    )
    provisioning_records = provisioning_dir / "records.json"
    provisioning_records.write_text(
        json.dumps({"version": 1, "site_id": "test-site", "records": []}),
        encoding="utf-8",
    )
    projection = projection_dir / "2025-10-07.observations.json"
    projection.write_text(
        json.dumps(
            {
                "generated_at_utc": "2025-10-07T00:00:00Z",
                "site_id": "test-site",
                "projection_mode": "read_only_canonical_fact_json",
                "things": [],
                "datastreams": [],
                "observed_properties": [],
                "observations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = load_module(
        "run_pipeline_demo_manifest_helper_under_test",
        Path("scripts/gateway/run_pipeline_demo.py"),
    )
    day_artifact = out_dir / "day" / "2025-10-07.cbor"
    runner.artifact_manifest(
        out_dir=out_dir,
        date="2025-10-07",
        site="test-site",
        device_id="pod-003",
        frame_count=len(sample_facts),
        frames_file=out_dir / "frames.ndjson",
        facts_dir=facts_dir,
        day_artifact=day_artifact,
        anchoring={"ots": {"status": "verified", "reason": "placeholder"}},
        provisioning_input=provisioning_input,
        provisioning_records=provisioning_records,
        sensorthings_projection=projection,
        verifier_summary={
            "checks_executed": ["day_artifact_validation"],
            "checks_skipped": [],
        },
    )

    rc = verify_cli.main(
        [
            "--root",
            str(out_dir),
            "--facts",
            str(facts_dir),
            "--disclosure-class",
            "A",
        ]
    )
    assert rc == 0


def test_verify_cli_rejects_manifest_disclosure_class_mismatch(
    tmp_path: Path,
    merkle_batcher,
    verify_cli,
    write_sample_facts_fixture,
    sample_facts,
    write_ots_placeholder,
    load_module,
    capsys,
):
    out_dir = tmp_path / "out"
    facts_dir = out_dir / "facts"
    provisioning_dir = out_dir / "provisioning"
    projection_dir = out_dir / "sensorthings"
    out_dir.mkdir(parents=True, exist_ok=True)
    provisioning_dir.mkdir(parents=True, exist_ok=True)
    projection_dir.mkdir(parents=True, exist_ok=True)

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

    provisioning_input = provisioning_dir / "authoritative-input.json"
    provisioning_input.write_text(
        json.dumps({"version": 1, "site_id": "test-site", "records": []}),
        encoding="utf-8",
    )
    provisioning_records = provisioning_dir / "records.json"
    provisioning_records.write_text(
        json.dumps({"version": 1, "site_id": "test-site", "records": []}),
        encoding="utf-8",
    )
    projection = projection_dir / "2025-10-07.observations.json"
    projection.write_text(
        json.dumps(
            {
                "generated_at_utc": "2025-10-07T00:00:00Z",
                "site_id": "test-site",
                "projection_mode": "read_only_canonical_fact_json",
                "things": [],
                "datastreams": [],
                "observed_properties": [],
                "observations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = load_module(
        "run_pipeline_demo_manifest_mismatch_helper_under_test",
        Path("scripts/gateway/run_pipeline_demo.py"),
    )
    day_artifact = out_dir / "day" / "2025-10-07.cbor"
    manifest_path = runner.artifact_manifest(
        out_dir=out_dir,
        date="2025-10-07",
        site="test-site",
        device_id="pod-003",
        frame_count=len(sample_facts),
        frames_file=out_dir / "frames.ndjson",
        facts_dir=facts_dir,
        day_artifact=day_artifact,
        anchoring={"ots": {"status": "verified", "reason": "placeholder"}},
        provisioning_input=provisioning_input,
        provisioning_records=provisioning_records,
        sensorthings_projection=projection,
        verifier_summary={
            "checks_executed": ["day_artifact_validation"],
            "checks_skipped": [],
        },
        disclosure_class="B",
    )
    assert manifest_path.exists()

    rc = verify_cli.main(
        [
            "--root",
            str(out_dir),
            "--facts",
            str(facts_dir),
            "--disclosure-class",
            "A",
        ]
    )

    captured = capsys.readouterr()
    assert rc == verify_cli.EXIT_META_INVALID
    assert "pipeline manifest validation failed" in captured.out
    assert "disclosure_class mismatch" in captured.out


def test_verify_cli_rejects_schema_invalid_pipeline_manifest(
    tmp_path: Path,
    merkle_batcher,
    verify_cli,
    write_sample_facts_fixture,
    sample_facts,
    write_ots_placeholder,
    capsys,
):
    out_dir = tmp_path / "out"
    facts_dir = out_dir / "facts"
    day_dir = out_dir / "day"
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

    manifest_path = day_dir / "2025-10-07.pipeline-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "version": 1,
                "date": "2025-10-07",
                "site": "test-site",
                "device_id": "pod-003",
                "frame_count": len(sample_facts),
                "facts_dir": "facts",
                "anchoring": {},
                "verification_bundle": {
                    "disclosure_class": "A",
                    "commitment_profile_id": "trackone-canonical-cbor-v1",
                    "checks_executed": [],
                    "checks_skipped": [],
                },
            }
        ),
        encoding="utf-8",
    )

    rc = verify_cli.main(
        [
            "--root",
            str(out_dir),
            "--facts",
            str(facts_dir),
            "--disclosure-class",
            "A",
        ]
    )

    captured = capsys.readouterr()
    assert rc == verify_cli.EXIT_META_INVALID
    assert "pipeline manifest validation failed" in captured.out
