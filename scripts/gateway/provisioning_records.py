#!/usr/bin/env python3
"""Materialize canonical provisioning records for projection consumers."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:  # Support both package imports and direct script execution.
    from .schema_validation import load_schema, validate_instance
except ImportError:  # pragma: no cover - fallback when run as a script
    from schema_validation import load_schema, validate_instance  # type: ignore

jsonschema: Any | None
try:
    import jsonschema

    JSONSCHEMA_AVAILABLE = True
except ImportError:
    jsonschema = None
    JSONSCHEMA_AVAILABLE = False


class ProvisioningRecordsError(ValueError):
    """Raised when provisioning records cannot be materialized safely."""


_HEX_64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX_128_RE = re.compile(r"^[0-9a-fA-F]{128}$")


def _validate_against_schema(payload: dict[str, Any], schema_name: str) -> None:
    if not JSONSCHEMA_AVAILABLE or jsonschema is None:
        return
    schema = load_schema(schema_name)
    if schema is None:
        return
    try:
        validate_instance(payload, schema)
    except (jsonschema.ValidationError, jsonschema.SchemaError) as exc:
        raise ProvisioningRecordsError(
            f"{schema_name}.schema.json validation failed: {exc}"
        ) from exc


def load_authoritative_input(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ProvisioningRecordsError(
            f"authoritative provisioning input not found: {path}"
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProvisioningRecordsError(
            f"failed to parse authoritative provisioning input {path}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise ProvisioningRecordsError(
            "authoritative provisioning input must be a JSON object"
        )
    _validate_against_schema(data, "provisioning_input")
    return data


def _require_provisioning_object(entry: dict[str, Any], pod_id: str) -> dict[str, Any]:
    provisioning = entry.get("provisioning")
    if not isinstance(provisioning, dict):
        raise ProvisioningRecordsError(f"record {pod_id} missing provisioning metadata")
    return provisioning


def _deployment_object(
    *,
    pod_id: str,
    entry: dict[str, Any],
) -> dict[str, Any]:
    deployment = entry.get("deployment")
    if not isinstance(deployment, dict):
        raise ProvisioningRecordsError(f"record {pod_id} missing deployment metadata")
    deployment_obj = deployment

    sensor_keys = deployment_obj.get("sensor_keys")
    clean_sensor_keys: dict[str, str] | None = None
    if isinstance(sensor_keys, dict):
        clean_sensor_keys = {
            str(k): str(v).strip()
            for k, v in sensor_keys.items()
            if isinstance(k, str) and isinstance(v, str) and v.strip()
        }
        if not clean_sensor_keys:
            clean_sensor_keys = None

    deployment_sensor_key = deployment_obj.get("deployment_sensor_key")
    if not isinstance(deployment_sensor_key, str) or not deployment_sensor_key.strip():
        raise ProvisioningRecordsError(
            f"record {pod_id} deployment missing deployment_sensor_key"
        )

    out: dict[str, Any] = {
        "deployment_sensor_key": deployment_sensor_key.strip(),
    }
    if clean_sensor_keys is not None:
        out["sensor_keys"] = clean_sensor_keys
    sensors = deployment_obj.get("sensors")
    if isinstance(sensors, list | dict):
        out["sensors"] = sensors
    return out


def _build_record(
    *,
    pod_id: str,
    entry: dict[str, Any],
    site_id: str,
) -> dict[str, Any]:
    provisioning = _require_provisioning_object(entry, pod_id)
    identity_pubkey = provisioning.get("identity_pubkey")
    firmware_version = provisioning.get("firmware_version")
    firmware_hash = provisioning.get("firmware_hash")
    birth_cert_sig = provisioning.get("birth_cert_sig")
    provisioned_at = provisioning.get("provisioned_at")
    if (
        not isinstance(identity_pubkey, str)
        or _HEX_64_RE.fullmatch(identity_pubkey) is None
    ):
        raise ProvisioningRecordsError(
            f"record {pod_id} provisioning.identity_pubkey must be 64 hex chars"
        )
    if not isinstance(firmware_version, str) or not firmware_version.strip():
        raise ProvisioningRecordsError(
            f"record {pod_id} provisioning.firmware_version must be non-empty"
        )
    if (
        not isinstance(firmware_hash, str)
        or _HEX_64_RE.fullmatch(firmware_hash) is None
    ):
        raise ProvisioningRecordsError(
            f"record {pod_id} provisioning.firmware_hash must be 64 hex chars"
        )
    if (
        not isinstance(birth_cert_sig, str)
        or _HEX_128_RE.fullmatch(birth_cert_sig) is None
    ):
        raise ProvisioningRecordsError(
            f"record {pod_id} provisioning.birth_cert_sig must be 128 hex chars"
        )
    if not isinstance(provisioned_at, int):
        raise ProvisioningRecordsError(
            f"record {pod_id} provisioning.provisioned_at must be an integer"
        )

    site_override = provisioning.get("site_id")
    if isinstance(site_override, str):
        record_site_id: str | None = site_override
    else:
        record_site_id = site_id

    return {
        "pod_id": pod_id,
        "firmware_version": firmware_version.strip(),
        "firmware_hash": firmware_hash.lower(),
        "identity_pubkey": identity_pubkey.lower(),
        "birth_cert_sig": birth_cert_sig.lower(),
        "provisioned_at": provisioned_at,
        "site_id": record_site_id,
        "deployment": _deployment_object(pod_id=pod_id, entry=entry),
    }


def build_provisioning_bundle(
    *,
    authoritative_input: dict[str, Any],
    site_id: str,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    source_records = authoritative_input.get("records")
    if not isinstance(source_records, list):
        raise ProvisioningRecordsError(
            "authoritative provisioning input must contain records[]"
        )
    for entry in source_records:
        if not isinstance(entry, dict):
            continue
        pod_id = entry.get("pod_id")
        if not isinstance(pod_id, str) or not pod_id:
            continue
        records.append(
            _build_record(
                pod_id=pod_id,
                entry=entry,
                site_id=site_id,
            )
        )

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
    _validate_against_schema(bundle, "provisioning_records")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate canonical provisioning records from authoritative provisioning input"
    )
    parser.add_argument("--authoritative-input", type=Path, required=True)
    parser.add_argument("--site", required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        authoritative_input = load_authoritative_input(args.authoritative_input)
        bundle = build_provisioning_bundle(
            authoritative_input=authoritative_input,
            site_id=args.site,
        )
        write_bundle(args.out, bundle)
    except ProvisioningRecordsError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
