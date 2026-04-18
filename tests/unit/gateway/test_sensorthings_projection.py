from __future__ import annotations

import json
from pathlib import Path


def test_build_bundle_uses_provisioning_metadata_and_time_fields(load_module) -> None:
    module = load_module(
        "sensorthings_projection_under_test",
        Path("scripts/gateway/sensorthings_projection.py"),
    )

    fact = {
        "pod_id": "0000000000000003",
        "fc": 1,
        "ingest_time": 1_772_755_501,
        "ingest_time_rfc3339_utc": "2026-03-06T00:05:01Z",
        "pod_time": None,
        "kind": "Custom",
        "payload": {
            "counter": 1,
            "temp_c": 23.5,
        },
    }
    provisioning_records = {
        "version": 1,
        "records": [
            {
                "pod_id": "0000000000000003",
                "identity_pubkey": "b" * 64,
                "deployment": {
                    "sensor_keys": {
                        "temperature_air": "shtc3-ambient",
                    }
                },
            }
        ],
    }

    bundle = module.build_bundle(
        [fact], site_id="an-001", provisioning_records=provisioning_records
    )

    assert bundle["site_id"] == "an-001"
    assert bundle["things"][0]["pod_id"] == "pod-003"
    assert bundle["datastreams"][0]["id"].startswith("trackone:datastream:")
    assert bundle["datastreams"][0]["sensor_id"] == module.entity_id(
        "sensor", "pod-003", "shtc3-ambient"
    )
    assert bundle["observations"][0]["phenomenon_time"]["start_rfc3339_utc"] == (
        "2026-03-06T00:05:01Z"
    )
    assert (
        bundle["observations"][0]["result_time_rfc3339_utc"] == "2026-03-06T00:05:01Z"
    )


def test_write_bundle_emits_projection_file(tmp_path: Path, load_module) -> None:
    module = load_module(
        "sensorthings_projection_cli_under_test",
        Path("scripts/gateway/sensorthings_projection.py"),
    )

    facts_dir = tmp_path / "facts"
    facts_dir.mkdir()
    (facts_dir / "pod-003-00000001.json").write_text(
        json.dumps(
            {
                "pod_id": "0000000000000003",
                "fc": 1,
                "ingest_time": 1_772_755_501,
                "ingest_time_rfc3339_utc": "2026-03-06T00:05:01Z",
                "pod_time": None,
                "kind": "Custom",
                "payload": {"temp_c": 23.5, "bioimpedance": 78.2},
            }
        ),
        encoding="utf-8",
    )
    (facts_dir / "pod-003-00000002.json").write_text(
        json.dumps(
            {
                "pod_id": "0000000000000003",
                "fc": 2,
                "ingest_time": 1_772_755_561,
                "ingest_time_rfc3339_utc": "2026-03-06T00:06:01Z",
                "pod_time": None,
                "kind": "Custom",
                "payload": {"temp_c": 24.0},
            }
        ),
        encoding="utf-8",
    )
    provisioning_records = tmp_path / "provisioning_records.json"
    provisioning_records.write_text(
        json.dumps(
            {
                "version": 1,
                "records": [
                    {
                        "pod_id": "0000000000000003",
                        "firmware_version": "v0.0.0-test",
                        "firmware_hash": "a" * 64,
                        "identity_pubkey": "b" * 64,
                        "birth_cert_sig": "c" * 128,
                        "provisioned_at": 1_772_755_500,
                        "deployment": {
                            "deployment_sensor_key": "shtc3-ambient",
                            "sensor_keys": {
                                "temperature_air": "shtc3-ambient",
                                "bioimpedance_magnitude": "bioimpedance-pad",
                            },
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out_path = tmp_path / "sensorthings" / "2026-03-06.observations.json"

    rc = module.main(
        [
            "--facts",
            str(facts_dir),
            "--site",
            "an-001",
            "--provisioning-records",
            str(provisioning_records),
            "--out",
            str(out_path),
        ]
    )

    assert rc == 0
    bundle = json.loads(out_path.read_text(encoding="utf-8"))
    assert bundle["projection_mode"] == "read_only_canonical_fact_json"
    assert len(bundle["observations"]) == 3
    observed_keys = {item["key"] for item in bundle["observed_properties"]}
    assert observed_keys == {"temperature_air", "bioimpedance_magnitude"}


def test_build_bundle_derives_sensor_identity_from_provisioning_metadata(
    load_module,
) -> None:
    module = load_module(
        "sensorthings_projection_provisioning_under_test",
        Path("scripts/gateway/sensorthings_projection.py"),
    )

    fact = {
        "pod_id": "0000000000000003",
        "fc": 7,
        "ingest_time": 1_772_755_561,
        "ingest_time_rfc3339_utc": "2026-03-06T00:06:01Z",
        "pod_time": None,
        "kind": "Env",
        "payload": {
            "Env": {
                "sample_type": "AmbientAirTemperature",
                "value": 24.0,
                "phenomenon_time_start": "2026-03-06T00:06:00Z",
                "phenomenon_time_end": "2026-03-06T00:06:00Z",
            }
        },
    }
    provisioning_records = {
        "version": 1,
        "records": [
            {
                "pod_id": "0000000000000003",
                "firmware_version": "v0.0.0-test",
                "firmware_hash": "a" * 64,
                "identity_pubkey": "b" * 64,
                "birth_cert_sig": "c" * 128,
                "provisioned_at": 1_772_755_500,
                "deployment": {
                    "deployment_sensor_key": "shtc3-ambient",
                    "sensor_keys": {
                        "temperature_air": "shtc3-ambient",
                    },
                },
            }
        ],
    }

    bundle = module.build_bundle(
        [fact],
        site_id="an-001",
        provisioning_records=provisioning_records,
    )

    assert bundle["datastreams"][0]["sensor_id"] == module.entity_id(
        "sensor", "pod-003", "shtc3-ambient"
    )


def test_build_bundle_rejects_missing_sensor_identity_metadata(load_module) -> None:
    module = load_module(
        "sensorthings_projection_missing_identity_under_test",
        Path("scripts/gateway/sensorthings_projection.py"),
    )

    fact = {
        "pod_id": "0000000000000003",
        "fc": 8,
        "ingest_time": 1_772_755_621,
        "ingest_time_rfc3339_utc": "2026-03-06T00:07:01Z",
        "pod_time": None,
        "kind": "Custom",
        "payload": {"temp_c": 24.5},
    }

    try:
        module.build_bundle(
            [fact],
            site_id="an-001",
            provisioning_records={
                "version": 1,
                "records": [{"pod_id": "0000000000000003"}],
            },
        )
    except module.SensorIdentityResolutionError as exc:
        assert "missing provisioning/deployment-backed sensor identity" in str(exc)
    else:  # pragma: no cover - defensive branch
        raise AssertionError("expected SensorIdentityResolutionError")


def test_build_bundle_rejects_missing_canonical_pod_id_with_context(
    load_module,
) -> None:
    module = load_module(
        "sensorthings_projection_missing_pod_id_under_test",
        Path("scripts/gateway/sensorthings_projection.py"),
    )

    fact = {
        "fc": 9,
        "ingest_time": 1_772_755_622,
        "ingest_time_rfc3339_utc": "2026-03-06T00:07:02Z",
        "pod_time": None,
        "kind": "Custom",
        "payload": {"temp_c": 24.5},
    }

    try:
        module.build_bundle(
            [fact],
            site_id="an-001",
            provisioning_records={"version": 1, "records": []},
        )
    except ValueError as exc:
        assert "fc=9" in str(exc)
        assert "missing canonical pod_id" in str(exc)
    else:  # pragma: no cover - defensive branch
        raise AssertionError("expected ValueError")


def test_main_accepts_valid_provisioning_records_file(
    tmp_path: Path, load_module
) -> None:
    module = load_module(
        "sensorthings_projection_records_cli_under_test",
        Path("scripts/gateway/sensorthings_projection.py"),
    )

    facts_dir = tmp_path / "facts"
    facts_dir.mkdir()
    (facts_dir / "pod-003-00000001.json").write_text(
        json.dumps(
            {
                "pod_id": "0000000000000003",
                "fc": 1,
                "ingest_time": 1_772_755_501,
                "ingest_time_rfc3339_utc": "2026-03-06T00:05:01Z",
                "pod_time": None,
                "kind": "Custom",
                "payload": {"temp_c": 23.5},
            }
        ),
        encoding="utf-8",
    )
    provisioning_records = tmp_path / "provisioning_records.json"
    provisioning_records.write_text(
        json.dumps(
            {
                "version": 1,
                "records": [
                    {
                        "pod_id": "0000000000000003",
                        "firmware_version": "v0.0.0-test",
                        "firmware_hash": "a" * 64,
                        "identity_pubkey": "b" * 64,
                        "birth_cert_sig": "c" * 128,
                        "provisioned_at": 1_772_755_500,
                        "deployment": {
                            "deployment_sensor_key": "shtc3-ambient",
                            "sensor_keys": {"temperature_air": "shtc3-ambient"},
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out_path = tmp_path / "sensorthings" / "bundle.json"

    rc = module.main(
        [
            "--facts",
            str(facts_dir),
            "--site",
            "an-001",
            "--provisioning-records",
            str(provisioning_records),
            "--out",
            str(out_path),
        ]
    )
    assert rc == 0


def test_main_rejects_invalid_provisioning_records_file(
    tmp_path: Path, load_module
) -> None:
    module = load_module(
        "sensorthings_projection_records_validation_under_test",
        Path("scripts/gateway/sensorthings_projection.py"),
    )

    facts_dir = tmp_path / "facts"
    facts_dir.mkdir()
    (facts_dir / "pod-003-00000001.json").write_text(
        json.dumps(
            {
                "pod_id": "0000000000000003",
                "fc": 1,
                "ingest_time": 1_772_755_501,
                "ingest_time_rfc3339_utc": "2026-03-06T00:05:01Z",
                "pod_time": None,
                "kind": "Custom",
                "payload": {"temp_c": 23.5},
            }
        ),
        encoding="utf-8",
    )
    invalid_records = tmp_path / "provisioning_records_invalid.json"
    invalid_records.write_text(
        json.dumps({"version": 1, "records": [{"pod_id": "0000000000000003"}]}),
        encoding="utf-8",
    )
    out_path = tmp_path / "sensorthings" / "bundle.json"

    rc = module.main(
        [
            "--facts",
            str(facts_dir),
            "--site",
            "an-001",
            "--provisioning-records",
            str(invalid_records),
            "--out",
            str(out_path),
        ]
    )
    assert rc == 2
