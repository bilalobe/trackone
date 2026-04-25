#!/usr/bin/env python3
"""Materialize canonical provisioning records for projection consumers."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from trackone_core.sensorthings import (
    ProvisioningRecordsError,
    build_provisioning_bundle,
    validate_provisioning_bundle_shape,
)

try:  # Support both package imports and direct script execution.
    from .input_integrity import require_sha256_sidecar
    from .schema_validation import (
        SCHEMA_VALIDATION_EXCEPTIONS,
        load_schema,
        schema_validation_available,
        validate_instance_if_available,
    )
except ImportError:  # pragma: no cover - fallback when run as a script
    from input_integrity import require_sha256_sidecar  # type: ignore
    from schema_validation import (  # type: ignore
        SCHEMA_VALIDATION_EXCEPTIONS,
        load_schema,
        schema_validation_available,
        validate_instance_if_available,
    )


def _validate_against_schema(payload: dict[str, Any], schema_name: str) -> None:
    schema = load_schema(schema_name)
    if schema is None:
        return
    try:
        validated = validate_instance_if_available(payload, schema)
    except SCHEMA_VALIDATION_EXCEPTIONS as exc:
        raise ProvisioningRecordsError(
            f"{schema_name}.schema.json validation failed: {exc}"
        ) from exc
    if not validated and not schema_validation_available():
        print(
            f"[WARN] jsonschema unavailable; {schema_name}.schema.json validation skipped.",
            file=sys.stderr,
        )


def load_authoritative_input(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ProvisioningRecordsError(
            f"authoritative provisioning input not found: {path}"
        )
    try:
        require_sha256_sidecar(path, label="authoritative provisioning input")
    except ValueError as exc:
        raise ProvisioningRecordsError(str(exc)) from exc
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


def write_bundle(path: Path, bundle: dict[str, Any]) -> Path:
    validate_provisioning_bundle_shape(bundle)
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
