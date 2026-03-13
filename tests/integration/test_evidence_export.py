from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _write_projection(path: Path, *, site_id: str, day: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "generated_at_utc": f"{day}T00:00:00Z",
                "site_id": site_id,
                "projection_mode": "read_only_canonical_fact_json",
                "things": [],
                "datastreams": [],
                "observed_properties": [],
                "observations": [],
            }
        ),
        encoding="utf-8",
    )


def _write_provisioning(path: Path, *, site_id: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"version": 1, "site_id": site_id, "records": []}),
        encoding="utf-8",
    )


def test_export_release_supports_detached_bundle_verification(
    tmp_path: Path,
    merkle_batcher,
    verify_cli,
    write_sample_facts_fixture,
    sample_facts,
    write_ots_placeholder,
    load_module,
) -> None:
    day = "2025-10-07"
    site = "test-site"
    out_dir = tmp_path / "out"
    facts_dir = out_dir / "facts"
    provisioning_dir = out_dir / "provisioning"
    projection_dir = out_dir / "sensorthings"
    evidence_repo = tmp_path / "trackone-evidence"
    bundle_path = tmp_path / "trackone-evidence.bundle"
    clone_dir = tmp_path / "evidence-clone"
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
                site,
                "--date",
                day,
            ]
        )
        == 0
    )

    frames_file = out_dir / "frames.ndjson"
    frames_file.write_text("{}\n", encoding="utf-8")
    write_ots_placeholder(out_dir, day)

    provisioning_input = provisioning_dir / "authoritative-input.json"
    provisioning_records = provisioning_dir / "records.json"
    _write_provisioning(provisioning_input, site_id=site)
    _write_provisioning(provisioning_records, site_id=site)
    projection = projection_dir / f"{day}.observations.json"
    _write_projection(projection, site_id=site, day=day)

    runner = load_module(
        "run_pipeline_demo_evidence_export_under_test",
        Path("scripts/gateway/run_pipeline_demo.py"),
    )
    day_artifact = out_dir / "day" / f"{day}.cbor"
    runner.artifact_manifest(
        out_dir=out_dir,
        date=day,
        site=site,
        device_id="pod-003",
        frame_count=len(sample_facts),
        frames_file=frames_file,
        facts_dir=facts_dir,
        day_artifact=day_artifact,
        anchoring={"ots": {"status": "verified", "reason": "placeholder"}},
        provisioning_input=provisioning_input,
        provisioning_records=provisioning_records,
        sensorthings_projection=projection,
        verifier_summary={
            "checks_executed": ["day_artifact_validation", "ots_verification"],
            "checks_skipped": [],
            "artifacts": {
                "block": str(out_dir / "blocks" / f"{day}-00.block.json"),
                "day_cbor": str(day_artifact),
            },
        },
    )

    subprocess.run(["git", "init", str(evidence_repo)], check=True)
    subprocess.run(
        ["git", "-C", str(evidence_repo), "config", "user.name", "TrackOne Tests"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(evidence_repo),
            "config",
            "user.email",
            "tests@example.invalid",
        ],
        check=True,
    )

    exporter = load_module(
        "evidence_export_release_under_test",
        Path("scripts/evidence/export_release.py"),
    )
    assert (
        exporter.main(
            [
                "--pipeline-dir",
                str(out_dir),
                "--evidence-repo",
                str(evidence_repo),
                "--site",
                site,
                "--day",
                day,
                "--git-commit",
                "--bundle-out",
                str(bundle_path),
            ]
        )
        == 0
    )

    exported_root = evidence_repo / "site" / site / "day" / day
    exported_manifest = exported_root / "day" / f"{day}.pipeline-manifest.json"
    exported_meta = exported_root / "day" / f"{day}.ots.meta.json"
    assert exported_root.exists()
    assert exported_meta.exists()
    assert not (exported_root / "frames.ndjson").exists()

    manifest = json.loads(exported_manifest.read_text(encoding="utf-8"))
    assert "frames_file" not in manifest
    assert manifest["artifacts"]["day_ots_meta"]["path"] == f"day/{day}.ots.meta.json"
    assert "artifacts" not in manifest.get("verifier", {})

    meta = json.loads(exported_meta.read_text(encoding="utf-8"))
    assert "milestone" not in meta
    assert meta["artifact"] == f"day/{day}.cbor"
    assert meta["ots_proof"] == f"day/{day}.cbor.ots"

    assert bundle_path.exists()
    subprocess.run(["git", "clone", str(bundle_path), str(clone_dir)], check=True)

    detached_root = clone_dir / "site" / site / "day" / day
    rc = verify_cli.main(
        [
            "--root",
            str(detached_root),
            "--facts",
            str(detached_root / "facts"),
        ]
    )
    assert rc == 0


def test_export_release_can_include_frames(
    tmp_path: Path,
    merkle_batcher,
    write_sample_facts_fixture,
    sample_facts,
    write_ots_placeholder,
    load_module,
) -> None:
    day = "2025-10-07"
    site = "test-site"
    out_dir = tmp_path / "out"
    facts_dir = out_dir / "facts"
    provisioning_dir = out_dir / "provisioning"
    projection_dir = out_dir / "sensorthings"
    evidence_repo = tmp_path / "trackone-evidence"
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
                site,
                "--date",
                day,
            ]
        )
        == 0
    )

    frames_file = out_dir / "frames.ndjson"
    frames_file.write_text("{}\n", encoding="utf-8")
    write_ots_placeholder(out_dir, day)

    provisioning_input = provisioning_dir / "authoritative-input.json"
    provisioning_records = provisioning_dir / "records.json"
    _write_provisioning(provisioning_input, site_id=site)
    _write_provisioning(provisioning_records, site_id=site)
    projection = projection_dir / f"{day}.observations.json"
    _write_projection(projection, site_id=site, day=day)

    runner = load_module(
        "run_pipeline_demo_evidence_export_with_frames_under_test",
        Path("scripts/gateway/run_pipeline_demo.py"),
    )
    day_artifact = out_dir / "day" / f"{day}.cbor"
    runner.artifact_manifest(
        out_dir=out_dir,
        date=day,
        site=site,
        device_id="pod-003",
        frame_count=len(sample_facts),
        frames_file=frames_file,
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

    exporter = load_module(
        "evidence_export_release_with_frames_under_test",
        Path("scripts/evidence/export_release.py"),
    )
    assert (
        exporter.main(
            [
                "--pipeline-dir",
                str(out_dir),
                "--evidence-repo",
                str(evidence_repo),
                "--site",
                site,
                "--day",
                day,
                "--include-frames",
            ]
        )
        == 0
    )

    exported_root = evidence_repo / "site" / site / "day" / day
    exported_manifest = exported_root / "day" / f"{day}.pipeline-manifest.json"
    assert (exported_root / "frames.ndjson").exists()
    manifest = json.loads(exported_manifest.read_text(encoding="utf-8"))
    assert manifest["frames_file"] == "frames.ndjson"


def test_export_release_tags_and_bundles_current_export_without_git_commit_flag(
    tmp_path: Path,
    merkle_batcher,
    write_sample_facts_fixture,
    sample_facts,
    write_ots_placeholder,
    load_module,
) -> None:
    day = "2025-10-07"
    site = "test-site"
    out_dir = tmp_path / "out"
    facts_dir = out_dir / "facts"
    provisioning_dir = out_dir / "provisioning"
    projection_dir = out_dir / "sensorthings"
    evidence_repo = tmp_path / "trackone-evidence"
    bundle_path = tmp_path / "trackone-evidence.bundle"
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
                site,
                "--date",
                day,
            ]
        )
        == 0
    )

    write_ots_placeholder(out_dir, day)

    provisioning_input = provisioning_dir / "authoritative-input.json"
    provisioning_records = provisioning_dir / "records.json"
    _write_provisioning(provisioning_input, site_id=site)
    _write_provisioning(provisioning_records, site_id=site)
    projection = projection_dir / f"{day}.observations.json"
    _write_projection(projection, site_id=site, day=day)

    runner = load_module(
        "run_pipeline_demo_evidence_export_autocommit_under_test",
        Path("scripts/gateway/run_pipeline_demo.py"),
    )
    day_artifact = out_dir / "day" / f"{day}.cbor"
    runner.artifact_manifest(
        out_dir=out_dir,
        date=day,
        site=site,
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

    subprocess.run(["git", "init", str(evidence_repo)], check=True)
    subprocess.run(
        ["git", "-C", str(evidence_repo), "config", "user.name", "TrackOne Tests"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(evidence_repo),
            "config",
            "user.email",
            "tests@example.invalid",
        ],
        check=True,
    )

    exporter = load_module(
        "evidence_export_release_autocommit_under_test",
        Path("scripts/evidence/export_release.py"),
    )
    assert (
        exporter.main(
            [
                "--pipeline-dir",
                str(out_dir),
                "--evidence-repo",
                str(evidence_repo),
                "--site",
                site,
                "--day",
                day,
                "--tag",
                "--bundle-out",
                str(bundle_path),
            ]
        )
        == 0
    )

    assert bundle_path.exists()
    head = subprocess.run(
        ["git", "-C", str(evidence_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tag_target = subprocess.run(
        [
            "git",
            "-C",
            str(evidence_repo),
            "rev-list",
            "-n",
            "1",
            f"evidence/{site}/{day}",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert head == tag_target
