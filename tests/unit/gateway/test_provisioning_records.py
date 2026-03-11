from __future__ import annotations

import json
from pathlib import Path


def test_main_writes_canonical_bundle(tmp_path: Path, load_module) -> None:
    module = load_module(
        "provisioning_records_under_test",
        Path("scripts/gateway/provisioning_records.py"),
    )
    device_table = tmp_path / "device_table.json"
    device_table.write_text(
        json.dumps(
            {
                "_meta": {"master_seed": "AA==", "version": "1.0"},
                "3": {
                    "salt8": "AA==",
                    "ck_up": "AA==",
                    "deployment": {
                        "deployment_sensor_key": "shtc3-ambient",
                        "sensor_keys": {"temperature_air": "shtc3-ambient"},
                    },
                    "provisioning": {
                        "identity_pubkey": "a" * 64,
                        "firmware_version": "v1.2.3",
                        "firmware_hash": "b" * 64,
                        "birth_cert_sig": "c" * 128,
                        "provisioned_at": 1_772_755_500,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    out_path = tmp_path / "provisioning" / "records.json"

    rc = module.main(
        [
            "--device-table",
            str(device_table),
            "--site",
            "an-001",
            "--out",
            str(out_path),
        ]
    )

    assert rc == 0
    bundle = json.loads(out_path.read_text(encoding="utf-8"))
    assert bundle["version"] == 1
    assert isinstance(bundle["records"], list) and len(bundle["records"]) == 1
    record = bundle["records"][0]
    assert record["pod_id"] == "0000000000000003"
    assert record["deployment"]["deployment_sensor_key"] == "shtc3-ambient"
    assert record["identity_pubkey"] == "a" * 64


def test_main_fails_when_device_table_lacks_authoritative_metadata(
    tmp_path: Path, load_module
) -> None:
    module = load_module(
        "provisioning_records_missing_metadata_under_test",
        Path("scripts/gateway/provisioning_records.py"),
    )
    device_table = tmp_path / "device_table.json"
    device_table.write_text(
        json.dumps(
            {
                "_meta": {"master_seed": "AA==", "version": "1.0"},
                "3": {"salt8": "AA==", "ck_up": "AA=="},
            }
        ),
        encoding="utf-8",
    )
    out_path = tmp_path / "provisioning" / "records.json"

    rc = module.main(
        [
            "--device-table",
            str(device_table),
            "--site",
            "an-001",
            "--out",
            str(out_path),
        ]
    )

    assert rc == 2


def test_main_fails_when_provisioning_hex_is_malformed(
    tmp_path: Path, load_module
) -> None:
    module = load_module(
        "provisioning_records_bad_hex_under_test",
        Path("scripts/gateway/provisioning_records.py"),
    )
    device_table = tmp_path / "device_table.json"
    device_table.write_text(
        json.dumps(
            {
                "_meta": {"master_seed": "AA==", "version": "1.0"},
                "3": {
                    "salt8": "AA==",
                    "ck_up": "AA==",
                    "deployment": {
                        "deployment_sensor_key": "shtc3-ambient",
                        "sensor_keys": {"temperature_air": "shtc3-ambient"},
                    },
                    "provisioning": {
                        "identity_pubkey": "z" * 64,
                        "firmware_version": "v1.2.3",
                        "firmware_hash": "g" * 64,
                        "birth_cert_sig": "h" * 128,
                        "provisioned_at": 1_772_755_500,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    out_path = tmp_path / "provisioning" / "records.json"

    rc = module.main(
        [
            "--device-table",
            str(device_table),
            "--site",
            "an-001",
            "--out",
            str(out_path),
        ]
    )

    assert rc == 2


def test_main_fails_when_device_table_missing(tmp_path: Path, load_module) -> None:
    module = load_module(
        "provisioning_records_error_under_test",
        Path("scripts/gateway/provisioning_records.py"),
    )
    out_path = tmp_path / "provisioning" / "records.json"

    rc = module.main(
        [
            "--device-table",
            str(tmp_path / "missing.json"),
            "--site",
            "an-001",
            "--out",
            str(out_path),
        ]
    )
    assert rc == 2
