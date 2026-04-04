#!/usr/bin/env python3
"""Fail-fast verification-manifest checks for demo/CI paths."""

from __future__ import annotations

import argparse
import io
import json
from contextlib import redirect_stdout
from pathlib import Path

try:  # Support both package imports and direct script execution.
    from . import verify_cli
    from .schema_validation import (
        load_schema,
        require_schema_validation,
        validate_instance,
    )
    from .verification_manifest import verify_manifest_path
except ImportError:  # pragma: no cover - fallback when run as a script
    import verify_cli  # type: ignore
    from schema_validation import (  # type: ignore
        load_schema,
        require_schema_validation,
        validate_instance,
    )
    from verification_manifest import verify_manifest_path  # type: ignore


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Assert that the verifier-facing manifest exists and is usable."
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--facts", type=Path, required=True)
    parser.add_argument("--day", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    manifest_path = verify_manifest_path(args.root / "day", args.day)
    if not manifest_path.exists():
        raise SystemExit(f"missing verification manifest: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    schema = load_schema("verify_manifest")
    if schema is not None:
        require_schema_validation("verification manifest checks")
        validate_instance(manifest, schema)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = verify_cli.main(
            [
                "--root",
                str(args.root),
                "--facts",
                str(args.facts),
                "--json",
            ]
        )
    raw_output = buf.getvalue()
    try:
        summary = json.loads(raw_output)
    except json.JSONDecodeError:
        stripped_output = raw_output.strip()
        parts = [
            "verify_cli did not produce valid JSON on stdout",
            f"exit code: {rc}",
        ]
        if stripped_output:
            parts += ["stdout:", stripped_output]
        raise SystemExit("\n".join(parts)) from None
    manifest_summary = summary.get("manifest", {})
    if manifest_summary.get("status") != "present":
        raise SystemExit("verify_cli did not report a present verification manifest")
    if manifest_summary.get("source") != manifest_path.name:
        raise SystemExit(
            "verify_cli reported the wrong verification manifest source: "
            f"{manifest_summary.get('source')!r}"
        )
    if rc == verify_cli.EXIT_META_INVALID:
        raise SystemExit(rc)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from None
