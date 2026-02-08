"""Repo-wide scanner to detect suspicious embedded OTS proofs in JSON payloads.

This is a defensive lint tool: it walks JSON files and flags keys that are
likely to contain OpenTimestamps proofs or other large proof blobs inside
payloads that should remain immutable once hashed.

It is intentionally conservative and can be extended or tightened over time.
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable
from pathlib import Path

SUSPICIOUS_KEY_RE = re.compile(r"(^|_)ots(_|$)|(^|_)proof(_|$)", re.IGNORECASE)


def iter_json_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*.json"):
        # Allow OTS metadata sidecars under proofs/ by default.
        if "proofs" in path.parts:
            continue
        yield path


def scan_file(path: Path) -> list[str]:
    issues: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:  # pragma: no cover - defensive
        issues.append(f"{path}: failed to parse JSON or read file: {exc}")
        return issues

    def walk(obj, prefix: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_path = f"{prefix}.{k}" if prefix else k
                if isinstance(k, str) and SUSPICIOUS_KEY_RE.search(k):
                    # Heuristic: large string values are more likely to be embedded proofs.
                    if isinstance(v, str) and len(v) > 256:
                        issues.append(
                            f"{path}: suspicious key '{key_path}' with large string value (len={len(v)})"
                        )
                    else:
                        issues.append(f"{path}: suspicious key '{key_path}'")
                walk(v, key_path)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                walk(item, f"{prefix}[{idx}]")

    walk(data)
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan JSON files for embedded OTS proofs."
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="Root directory to scan (default: current directory)",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    all_issues: list[str] = []
    for path in iter_json_files(root):
        all_issues.extend(scan_file(path))

    if all_issues:
        for line in sorted(all_issues):
            print(line)
        return 1

    print("No suspicious embedded proofs found.")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
