from __future__ import annotations

import json
from pathlib import Path


def test_build_bundle_uses_device_metadata_and_time_fields(load_module) -> None:
    module = load_module(
        "sensorthings_projection_under_test",
        Path("scripts/gateway/sensorthings_projection.py"),
    )

    fact = {
        "device_id": "pod-003",
        "timestamp": "2026-03-06T00:05:01Z",
        "nonce": "abc",
        "payload": {
            "counter": 1,
            "temp_c": 23.5,
        },
    }
    device_table = {
        "3": {
            "sensor_keys": {
                "temperature_air": "shtc3-ambient",
            }
        }
    }

    bundle = module.build_bundle([fact], site_id="an-001", device_table=device_table)

    assert bundle["site_id"] == "an-001"
    assert bundle["things"][0]["pod_id"] == "pod-003"
    assert bundle["datastreams"][0]["id"].startswith("trackone:datastream:")
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
                "device_id": "pod-003",
                "timestamp": "2026-03-06T00:05:01Z",
                "nonce": "abc",
                "payload": {"temp_c": 23.5, "bioimpedance": 78.2},
            }
        ),
        encoding="utf-8",
    )
    device_table = tmp_path / "device_table.json"
    device_table.write_text(
        json.dumps(
            {
                "3": {
                    "sensor_keys": {
                        "temperature_air": "shtc3-ambient",
                        "bioimpedance_magnitude": "bioimpedance-pad",
                    }
                }
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
            "--device-table",
            str(device_table),
            "--out",
            str(out_path),
        ]
    )

    assert rc == 0
    bundle = json.loads(out_path.read_text(encoding="utf-8"))
    assert len(bundle["observations"]) == 2
    observed_keys = {item["key"] for item in bundle["observed_properties"]}
    assert observed_keys == {"temperature_air", "bioimpedance_magnitude"}
