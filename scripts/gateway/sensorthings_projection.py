#!/usr/bin/env python3
"""Build a read-only SensorThings projection from gateway fact artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from trackone_core.sensorthings import (
    ProjectionError,
    SensorIdentityResolutionError,
    _entity_id,
    build_bundle,
)

__all__ = [
    "ProjectionError",
    "SensorIdentityResolutionError",
    "_entity_id",
    "build_bundle",
    "load_facts",
    "load_provisioning_records",
    "main",
    "parse_args",
    "write_bundle",
]

try:  # Support both package imports and direct script execution.
    from .schema_validation import (
        SCHEMA_VALIDATION_EXCEPTIONS,
        load_schema,
        schema_validation_available,
        validate_instance_if_available,
    )
except ImportError:  # pragma: no cover - fallback when run as a script
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
        raise ProjectionError(
            f"{schema_name}.schema.json validation failed: {exc}"
        ) from exc
    if not validated and not schema_validation_available():
        print(
            f"[WARN] jsonschema unavailable; {schema_name}.schema.json validation skipped.",
            file=sys.stderr,
        )


def load_provisioning_records(path: Path | None) -> dict[str, Any]:
    if path is None:
        raise ProjectionError("--provisioning-records is required")
    if not path.exists():
        raise ProjectionError(f"provisioning records file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProjectionError(
            f"unable to read provisioning records file: {path}"
        ) from exc
    if not isinstance(data, dict):
        raise ProjectionError("provisioning records must be a JSON object")
    _validate_against_schema(data, "provisioning_records")
    return data


def load_facts(facts_dir: Path) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    for path in sorted(facts_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            facts.append(data)
    return facts


def write_bundle(
    *,
    facts_dir: Path,
    provisioning_records_path: Path | None,
    site_id: str,
    out_path: Path,
) -> Path:
    bundle = build_bundle(
        load_facts(facts_dir),
        site_id=site_id,
        provisioning_records=load_provisioning_records(provisioning_records_path),
    )
    _validate_against_schema(bundle, "sensorthings_projection")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return out_path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a read-only SensorThings projection artifact."
    )
    parser.add_argument("--facts", type=Path, required=True)
    parser.add_argument("--site", required=True)
    parser.add_argument("--provisioning-records", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        write_bundle(
            facts_dir=args.facts,
            provisioning_records_path=args.provisioning_records,
            site_id=args.site,
            out_path=args.out,
        )
    except ProjectionError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
