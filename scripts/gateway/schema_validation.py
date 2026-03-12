#!/usr/bin/env python3
"""Shared JSON Schema loading and validation helpers."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

SCHEMA_DIR = Path(__file__).parent.parent.parent / "toolset" / "unified" / "schemas"


def schema_path(name: str) -> Path:
    return SCHEMA_DIR / f"{name}.schema.json"


def _load_schema_path(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def load_schema(name: str) -> dict[str, Any] | None:
    return _load_schema_path(schema_path(name))


def load_all_schemas() -> dict[str, dict[str, Any]]:
    schemas: dict[str, dict[str, Any]] = {}
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        schema = _load_schema_path(path)
        if schema is None:
            continue
        schemas[path.stem.replace(".schema", "")] = schema
    return schemas


@lru_cache(maxsize=1)
def schema_registry() -> Any:
    from referencing import Registry, Resource

    registry = Registry()
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        schema = _load_schema_path(path)
        if schema is None:
            continue
        schema_id = schema.get("$id")
        if not isinstance(schema_id, str) or not schema_id:
            continue
        registry = registry.with_resource(schema_id, Resource.from_contents(schema))
    return registry


def validate_instance(instance: Any, schema: dict[str, Any]) -> None:
    import jsonschema

    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema, registry=schema_registry())
    validator.validate(instance)


def validate_schema_document(schema: dict[str, Any]) -> None:
    import jsonschema

    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
