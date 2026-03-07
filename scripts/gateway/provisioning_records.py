#!/usr/bin/env python3
"""Materialize canonical provisioning records for projection consumers."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class ProvisioningRecordsError(ValueError):
    """Raised when provisioning records cannot be materialized safely."""


def load_device_table(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ProvisioningRecordsError(f"device table not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProvisioningRecordsError(
            f"failed to parse device table {path}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise ProvisioningRecordsError("device table must be a JSON object")
    return data


def _pod_id_hex_from_device_key(device_key: str) -> str:
    value = int(device_key, 10)
    return f"{value & 0xFFFF:016x}"


def _default_sensor_keys(device_label: str) -> dict[str, str]:
    return {
        "temperature_air": f"{device_label}-temperature-air",
        "bioimpedance_magnitude": f"{device_label}-bioimpedance-magnitude",
        "relative_humidity": f"{device_label}-relative-humidity",
    }


def _derive_identity_pubkey(device_key: str, entry: dict[str, Any]) -> str:
    provisioning = entry.get("provisioning")
    if isinstance(provisioning, dict):
        candidate = provisioning.get("identity_pubkey")
        if isinstance(candidate, str) and len(candidate) == 64:
            return candidate.lower()

    raw_ck = entry.get("ck_up")
    ck_seed = b""
    if isinstance(raw_ck, str):
        try:
            ck_seed = base64.b64decode(raw_ck)
        except (ValueError, TypeError):
            ck_seed = b""
    seed = b"trackone:provisioning-identity:" + device_key.encode("ascii") + ck_seed
    return hashlib.sha256(seed).hexdigest()


def _deployment_object(
    *,
    device_label: str,
    entry: dict[str, Any],
) -> dict[str, Any]:
    deployment = entry.get("deployment")
    deployment_obj = deployment if isinstance(deployment, dict) else {}

    sensor_keys = deployment_obj.get("sensor_keys")
    if isinstance(sensor_keys, dict):
        clean_sensor_keys = {
            str(k): str(v).strip()
            for k, v in sensor_keys.items()
            if isinstance(k, str) and isinstance(v, str) and v.strip()
        }
    else:
        entry_sensor_keys = entry.get("sensor_keys")
        if isinstance(entry_sensor_keys, dict):
            clean_sensor_keys = {
                str(k): str(v).strip()
                for k, v in entry_sensor_keys.items()
                if isinstance(k, str) and isinstance(v, str) and v.strip()
            }
        else:
            clean_sensor_keys = {}

    if not clean_sensor_keys:
        clean_sensor_keys = _default_sensor_keys(device_label)

    deployment_sensor_key = deployment_obj.get("deployment_sensor_key")
    if not isinstance(deployment_sensor_key, str) or not deployment_sensor_key.strip():
        deployment_sensor_key = clean_sensor_keys.get("temperature_air")
    if not isinstance(deployment_sensor_key, str) or not deployment_sensor_key.strip():
        deployment_sensor_key = f"{device_label}-sensor-default"

    out: dict[str, Any] = {
        "deployment_sensor_key": deployment_sensor_key.strip(),
        "sensor_keys": clean_sensor_keys,
    }
    sensors = deployment_obj.get("sensors")
    if isinstance(sensors, (list, dict)):
        out["sensors"] = sensors
    return out


def _build_record(
    *,
    device_key: str,
    entry: dict[str, Any],
    site_id: str,
) -> dict[str, Any]:
    pod_id = _pod_id_hex_from_device_key(device_key)
    device_label = f"pod-{int(device_key):03d}"
    identity_pubkey = _derive_identity_pubkey(device_key, entry)
    firmware_version = "v0.0.0-unknown"
    firmware_hash = hashlib.sha256(firmware_version.encode("utf-8")).hexdigest()
    birth_cert_sig = (
        hashlib.sha256(
            (identity_pubkey + firmware_hash + device_key).encode("utf-8")
        ).digest()
        * 2
    ).hex()

    provisioned_at = entry.get("provisioned_at")
    if not isinstance(provisioned_at, int):
        provisioned_at = 0

    site_override = entry.get("site_id")
    if isinstance(site_override, str):
        record_site_id: str | None = site_override
    else:
        record_site_id = site_id

    return {
        "pod_id": pod_id,
        "firmware_version": firmware_version,
        "firmware_hash": firmware_hash,
        "identity_pubkey": identity_pubkey,
        "birth_cert_sig": birth_cert_sig,
        "provisioned_at": int(provisioned_at),
        "site_id": record_site_id,
        "deployment": _deployment_object(device_label=device_label, entry=entry),
    }


def build_provisioning_bundle(
    *,
    device_table: dict[str, Any],
    site_id: str,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for key, entry in sorted(device_table.items()):
        if not (isinstance(key, str) and key.isdigit()):
            continue
        if not isinstance(entry, dict):
            continue
        records.append(_build_record(device_key=key, entry=entry, site_id=site_id))

    return {
        "version": 1,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "site_id": site_id,
        "records": records,
    }


def _validate_bundle_shape(bundle: dict[str, Any]) -> None:
    records = bundle.get("records")
    if not isinstance(records, list):
        raise ProvisioningRecordsError("provisioning bundle must contain records[]")
    for idx, record in enumerate(records):
        if not isinstance(record, dict):
            raise ProvisioningRecordsError(f"records[{idx}] must be an object")
        for key in (
            "pod_id",
            "firmware_version",
            "firmware_hash",
            "identity_pubkey",
            "birth_cert_sig",
            "provisioned_at",
            "deployment",
        ):
            if key not in record:
                raise ProvisioningRecordsError(f"records[{idx}] missing field: {key}")
        deployment = record["deployment"]
        if not isinstance(deployment, dict):
            raise ProvisioningRecordsError(f"records[{idx}].deployment must be object")
        deployment_sensor_key = deployment.get("deployment_sensor_key")
        if (
            not isinstance(deployment_sensor_key, str)
            or not deployment_sensor_key.strip()
        ):
            raise ProvisioningRecordsError(
                f"records[{idx}].deployment.deployment_sensor_key must be non-empty"
            )


def write_bundle(path: Path, bundle: dict[str, Any]) -> Path:
    _validate_bundle_shape(bundle)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate canonical provisioning records from gateway device_table.json"
    )
    parser.add_argument("--device-table", type=Path, required=True)
    parser.add_argument("--site", required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        device_table = load_device_table(args.device_table)
        bundle = build_provisioning_bundle(device_table=device_table, site_id=args.site)
        write_bundle(args.out, bundle)
    except ProvisioningRecordsError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
