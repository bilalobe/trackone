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
import sys
from collections.abc import Iterable
from pathlib import Path

SUSPICIOUS_KEY_RE = re.compile(r"(^|_)ots(_|$)|(^|_)proof(_|$)", re.IGNORECASE)
OTS_MAGIC_PATTERNS = (
    "AE9wZW5UaW1lc3RhbXBz",  # base64("\x00OpenTimestamps")
    "004f70656e54696d657374616d7073",  # hex("\x00OpenTimestamps")
)


def iter_json_files(root: Path, excluded_dirs: set[str]) -> Iterable[Path]:
    for path in root.rglob("*.json"):
        # Allow OTS metadata sidecars under proofs/ by default.
        if excluded_dirs.intersection(path.parts):
            continue
        yield path


def scan_file(path: Path, *, min_blob_len: int, report_key_names: bool) -> list[str]:
    issues: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - defensive
        issues.append(f"{path}: failed to parse JSON: {exc}")
        return issues

    def walk(obj, prefix: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_path = f"{prefix}.{k}" if prefix else k
                if isinstance(k, str) and SUSPICIOUS_KEY_RE.search(k):
                    if isinstance(v, str) and len(v) >= min_blob_len:
                        issues.append(
                            f"{path}: suspicious key '{key_path}' with large string value (len={len(v)})"
                        )
                    elif (
                        isinstance(v, list)
                        and len(v) >= min_blob_len
                        and all(
                            isinstance(item, int) and 0 <= item <= 255 for item in v
                        )
                    ):
                        issues.append(
                            f"{path}: suspicious key '{key_path}' with large byte-array-like list (len={len(v)})"
                        )
                    elif report_key_names:
                        issues.append(f"{path}: suspicious key '{key_path}'")

                if isinstance(v, str) and len(v) >= min_blob_len:
                    for magic in OTS_MAGIC_PATTERNS:
                        if magic in v:
                            issues.append(
                                f"{path}: key '{key_path}' value contains OTS magic header"
                            )
                            break
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
        nargs="*",
        default=["."],
        help="Files or directories to scan (default: current directory)",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=["proofs"],
        help="Directory name(s) to skip (may be repeated, default: proofs).",
    )
    parser.add_argument(
        "--min-blob-len",
        type=int,
        default=256,
        help="Minimum string/list length to treat as a suspicious proof blob.",
    )
    parser.add_argument(
        "--report-key-names",
        action="store_true",
        help="Also report suspicious key names even when values are not blob-like.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Do not print the 'clean' message on success.",
    )
    args = parser.parse_args()

    excluded_dirs = set(args.exclude_dir)
    all_issues: list[str] = []
    for target in args.root:
        resolved = Path(target).resolve()
        if excluded_dirs.intersection(resolved.parts):
            continue

        if resolved.is_file():
            all_issues.extend(
                scan_file(
                    resolved,
                    min_blob_len=args.min_blob_len,
                    report_key_names=args.report_key_names,
                )
            )
        elif resolved.is_dir():
            for path in iter_json_files(resolved, excluded_dirs):
                all_issues.extend(
                    scan_file(
                        path,
                        min_blob_len=args.min_blob_len,
                        report_key_names=args.report_key_names,
                    )
                )
        else:
            print(f"Warning: {target} not found, skipping.", file=sys.stderr)

    if all_issues:
        for line in sorted(all_issues):
            print(line)
        return 1

    if not args.quiet:
        print("No suspicious embedded proofs found.")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
