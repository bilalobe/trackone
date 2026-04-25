from __future__ import annotations

import json
from pathlib import Path

from scripts.gateway.input_integrity import write_sha256_sidecar
from trackone_core.sensorthings import (
    build_provisioning_bundle,
    validate_provisioning_bundle_shape,
)


def _write_authoritative_input(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")
    write_sha256_sidecar(path)


def test_main_writes_canonical_bundle(tmp_path: Path, load_module) -> None:
    module = load_module(
        "provisioning_records_under_test",
        Path("scripts/gateway/provisioning_records.py"),
    )
    authoritative_input = tmp_path / "provisioning-input.json"
    _write_authoritative_input(
        authoritative_input,
        {
            "version": 1,
            "site_id": "an-001",
            "records": [
                {
                    "pod_id": "0000000000000003",
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
                }
            ],
        },
    )
    out_path = tmp_path / "provisioning" / "records.json"

    rc = module.main(
        [
            "--authoritative-input",
            str(authoritative_input),
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


def test_public_sensorthings_surface_builds_provisioning_bundle() -> None:
    bundle = build_provisioning_bundle(
        authoritative_input={
            "version": 1,
            "site_id": "an-001",
            "records": [
                {
                    "pod_id": "0000000000000003",
                    "deployment": {
                        "deployment_sensor_key": "shtc3-ambient",
                        "sensor_keys": {"temperature_air": "shtc3-ambient"},
                    },
                    "provisioning": {
                        "identity_pubkey": "A" * 64,
                        "firmware_version": "v1.2.3",
                        "firmware_hash": "B" * 64,
                        "birth_cert_sig": "C" * 128,
                        "provisioned_at": 1_772_755_500,
                    },
                }
            ],
        },
        site_id="an-001",
        generated_at_utc="2026-04-25T12:00:00+00:00",
    )

    validate_provisioning_bundle_shape(bundle)
    assert bundle["generated_at_utc"] == "2026-04-25T12:00:00+00:00"
    assert bundle["records"][0]["identity_pubkey"] == "a" * 64
    assert bundle["records"][0]["firmware_hash"] == "b" * 64


def test_main_fails_when_input_lacks_authoritative_metadata(
    tmp_path: Path, load_module
) -> None:
    module = load_module(
        "provisioning_records_missing_metadata_under_test",
        Path("scripts/gateway/provisioning_records.py"),
    )
    authoritative_input = tmp_path / "provisioning-input.json"
    _write_authoritative_input(
        authoritative_input,
        {
            "version": 1,
            "site_id": "an-001",
            "records": [{"pod_id": "0000000000000003"}],
        },
    )
    out_path = tmp_path / "provisioning" / "records.json"

    rc = module.main(
        [
            "--authoritative-input",
            str(authoritative_input),
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
    authoritative_input = tmp_path / "provisioning-input.json"
    _write_authoritative_input(
        authoritative_input,
        {
            "version": 1,
            "site_id": "an-001",
            "records": [
                {
                    "pod_id": "0000000000000003",
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
                }
            ],
        },
    )
    out_path = tmp_path / "provisioning" / "records.json"

    rc = module.main(
        [
            "--authoritative-input",
            str(authoritative_input),
            "--site",
            "an-001",
            "--out",
            str(out_path),
        ]
    )

    assert rc == 2


def test_main_fails_when_authoritative_input_missing(
    tmp_path: Path, load_module
) -> None:
    module = load_module(
        "provisioning_records_error_under_test",
        Path("scripts/gateway/provisioning_records.py"),
    )
    out_path = tmp_path / "provisioning" / "records.json"

    rc = module.main(
        [
            "--authoritative-input",
            str(tmp_path / "missing.json"),
            "--site",
            "an-001",
            "--out",
            str(out_path),
        ]
    )
    assert rc == 2


def test_main_fails_when_authoritative_input_sha256_sidecar_missing(
    tmp_path: Path, load_module
) -> None:
    module = load_module(
        "provisioning_records_missing_sha_under_test",
        Path("scripts/gateway/provisioning_records.py"),
    )
    authoritative_input = tmp_path / "provisioning-input.json"
    authoritative_input.write_text(
        json.dumps({"version": 1, "site_id": "an-001", "records": []}),
        encoding="utf-8",
    )
    out_path = tmp_path / "provisioning" / "records.json"

    rc = module.main(
        [
            "--authoritative-input",
            str(authoritative_input),
            "--site",
            "an-001",
            "--out",
            str(out_path),
        ]
    )

    assert rc == 2
