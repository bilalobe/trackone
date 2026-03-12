#!/usr/bin/env python3
"""Pre-commit/CI guardrail for unified JSON Schema policy.

Enforces:
  - all checked-in unified schemas declare JSON Schema draft 2020-12
  - schemas use `$defs` instead of legacy `definitions`

Exit 1 on findings, 0 otherwise.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path

EXPECTED_DRAFT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_ROOT = Path("toolset/unified/schemas")


def _iter_targets(argv: Sequence[str]) -> list[Path]:
    if argv:
        candidates = [Path(arg) for arg in argv]
    else:
        candidates = sorted(SCHEMA_ROOT.glob("*.schema.json"))
    return [
        path
        for path in candidates
        if path.suffix == ".json"
        and path.name.endswith(".schema.json")
        and SCHEMA_ROOT.resolve() in path.resolve().parents
    ]


def _load_json(path: Path) -> dict[str, object] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"[schema-draft] {path}: failed to read JSON: {exc}", file=sys.stderr)
        return None
    if not isinstance(data, dict):
        print(
            f"[schema-draft] {path}: schema root must be a JSON object", file=sys.stderr
        )
        return None
    return data


def main(argv: Sequence[str]) -> int:
    failures = 0
    for path in _iter_targets(argv):
        data = _load_json(path)
        if data is None:
            failures += 1
            continue

        declared = data.get("$schema")
        if declared != EXPECTED_DRAFT:
            print(
                f"[schema-draft] {path}: expected $schema={EXPECTED_DRAFT!r}, got {declared!r}",
                file=sys.stderr,
            )
            failures += 1

        if "definitions" in data:
            print(
                f"[schema-draft] {path}: legacy 'definitions' found; use '$defs' instead",
                file=sys.stderr,
            )
            failures += 1

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
