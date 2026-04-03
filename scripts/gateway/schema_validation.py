#!/usr/bin/env python3
"""Shared JSON Schema loading and validation helpers."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

SCHEMA_DIR = Path(__file__).parent.parent.parent / "toolset" / "unified" / "schemas"
SCHEMA_VALIDATION_SKIP_REASON = "dependency-unavailable-jsonschema"

try:
    import jsonschema as _jsonschema

    JSONSCHEMA_AVAILABLE = True
    SCHEMA_VALIDATION_EXCEPTIONS: tuple[type[BaseException], ...] = (
        _jsonschema.ValidationError,
        _jsonschema.SchemaError,
    )
except ImportError:
    _jsonschema = None  # type: ignore[assignment]
    JSONSCHEMA_AVAILABLE = False
    SCHEMA_VALIDATION_EXCEPTIONS = ()


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


def load_schema_from_path(path: Path) -> dict[str, Any] | None:
    """Load a JSON schema from an explicit filesystem path.

    Returns None if the file does not exist.
    Raises OSError, UnicodeDecodeError, or json.JSONDecodeError on read/parse failures.
    Raises ValueError if the schema root is not a JSON object.
    """
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Schema at '{path}' must be a JSON object")
    return data


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


def schema_validation_available() -> bool:
    return JSONSCHEMA_AVAILABLE and _jsonschema is not None


def require_schema_validation(context: str = "schema validation") -> None:
    if schema_validation_available():
        return
    raise RuntimeError(
        f"jsonschema is required for {context}. "
        "Install trackone[validation] or trackone[test]."
    )


def validate_instance(instance: Any, schema: dict[str, Any]) -> None:
    require_schema_validation("JSON Schema validation")
    assert _jsonschema is not None
    validator_cls = _jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema, registry=schema_registry())
    validator.validate(instance)


def validate_instance_if_available(instance: Any, schema: dict[str, Any]) -> bool:
    if not schema_validation_available():
        return False
    validate_instance(instance, schema)
    return True


def validate_schema_document(schema: dict[str, Any]) -> None:
    require_schema_validation("schema document validation")
    assert _jsonschema is not None
    validator_cls = _jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
