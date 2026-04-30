#!/usr/bin/env python3
"""Native-first OpenTimestamps proof inspection for CI.

This helper intentionally uses the public ``trackone_core.ots`` shim. It only
classifies detached proof structure and attestation heights; strict proof
verification still converges through ``ots verify`` in ``ots_verify.sh``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

BITCOIN_ATTESTATION_RE = re.compile(r"verify BitcoinBlockHeaderAttestation\((\d+)\)")
PENDING_ATTESTATION_RE = re.compile(r"verify PendingAttestation\(")


def _proof_paths(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if root.suffix == ".ots" else []
    if not root.exists():
        return []
    return sorted(path for path in root.glob("*.ots") if path.is_file())


def _stage_from_steps(steps: Iterable[str]) -> tuple[str, str, list[int]]:
    heights: list[int] = []
    pending = False
    for step in steps:
        if match := BITCOIN_ATTESTATION_RE.search(step):
            heights.append(int(match.group(1)))
        if PENDING_ATTESTATION_RE.search(step):
            pending = True

    if heights:
        return "headers_wait_block_sync", "sync-blocks", sorted(set(heights))
    if pending:
        return "calendar_pending", "upgrade", []
    return "pending", "upgrade", []


def inspect_file(path: Path, ots_module: Any) -> dict[str, Any]:
    try:
        steps = list(ots_module.describe_ots_proof(str(path), None))
    except Exception as exc:  # noqa: BLE001 - fallback reason is diagnostic only.
        return {
            "file": str(path),
            "status": "native_unsupported",
            "stage": "unknown",
            "next_trigger": "ots-info",
            "heights": [],
            "reason": str(exc),
        }

    stage, next_trigger, heights = _stage_from_steps(steps)
    return {
        "file": str(path),
        "status": "native_parsed",
        "stage": stage,
        "next_trigger": next_trigger,
        "heights": heights,
        "steps": steps,
    }


def inspect_root(root: Path, ots_module: Any) -> dict[str, Any]:
    files = [inspect_file(path, ots_module) for path in _proof_paths(root)]
    heights = sorted({height for item in files for height in item["heights"]})
    return {"root": str(root), "heights": heights, "files": files}


def emit_shell(summary: dict[str, Any]) -> None:
    for height in summary["heights"]:
        print(f"height={height}")
    for item in summary["files"]:
        print(
            "\t".join(
                [
                    "file",
                    item["file"],
                    item["status"],
                    item["stage"],
                    item["next_trigger"],
                ]
            )
        )


def emit_summary(summary: dict[str, Any]) -> None:
    files = summary["files"]
    if not files:
        print(f"No .ots files found in {summary['root']}.")
        return
    heights = ",".join(str(height) for height in summary["heights"]) or "(none)"
    print(f"Native OTS inspection files={len(files)} heights={heights}")
    for item in files:
        print(
            f"{item['file']}: status={item['status']} "
            f"stage={item['stage']} next_trigger={item['next_trigger']}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root", nargs="?", default=".", help="Directory or .ots file to inspect"
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON"
    )
    parser.add_argument(
        "--shell", action="store_true", help="Emit shell-friendly lines"
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo_root / "src"))
    sys.path.insert(0, str(repo_root))

    from trackone_core import ots

    summary = inspect_root(Path(args.root), ots)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    elif args.shell:
        emit_shell(summary)
    else:
        emit_summary(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
