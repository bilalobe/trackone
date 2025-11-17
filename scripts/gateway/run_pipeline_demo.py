#!/usr/bin/env python3
"""Deterministic TrackOne pipeline runner writing artifacts to out/site_demo."""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT_DIR = "out/site_demo"
DEFAULT_DATE = "2025-10-07"
DEFAULT_DEVICE_ID = "pod-003"
DEFAULT_SITE = "an-001"
DEFAULT_FRAME_COUNT = 7
DEFAULT_FRAME_WINDOW = 64


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def run_cmd(label: str, cmd: Iterable[str], *, cwd: Path) -> None:
    printable = " ".join(shlex.quote(str(part)) for part in cmd)
    print(f"[pipeline] {label}\n[pipeline] → {printable}")
    subprocess.run(list(cmd), check=True, cwd=cwd)


def clean_outputs(out_dir: Path, frames_file: Path, *, keep_existing: bool) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    if keep_existing:
        return
    for path in (
        frames_file,
        out_dir / "frames.ndjson",
    ):
        if Path(path).is_file():
            Path(path).unlink()
    for subdir in ("facts", "blocks", "day"):
        target = out_dir / subdir
        if target.exists():
            shutil.rmtree(target)


def ensure_dirs(*paths: Path) -> None:
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)


def artifact_manifest(
    date: str,
    site: str,
    device_id: str,
    frame_count: int,
    frames_file: Path,
    facts_dir: Path,
    day_bin: Path,
    out_dir: Path,
) -> Path:
    manifest = {
        "date": date,
        "site": site,
        "device_id": device_id,
        "frame_count": frame_count,
        "frames_file": rel(frames_file),
        "facts_dir": rel(facts_dir),
        "artifacts": {
            "day_bin": rel(day_bin),
            "day_json": rel(day_bin.with_suffix(".json")),
            "day_sha256": rel(day_bin.with_suffix(".bin.sha256")),
            "day_ots": rel(Path(f"{day_bin}.ots")),
            "block": rel(out_dir / "blocks" / f"{date}-00.block.json"),
        },
    }
    manifest_path = day_bin.parent / f"{date}.pipeline-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the deterministic TrackOne pipeline demo."
    )
    parser.add_argument(
        "--out-dir", default=os.environ.get("PIPELINE_OUT_DIR", DEFAULT_OUT_DIR)
    )
    parser.add_argument("--date", default=os.environ.get("PIPELINE_DATE", DEFAULT_DATE))
    parser.add_argument(
        "--device-id", default=os.environ.get("PIPELINE_DEVICE_ID", DEFAULT_DEVICE_ID)
    )
    parser.add_argument("--site", default=os.environ.get("PIPELINE_SITE", DEFAULT_SITE))
    parser.add_argument(
        "--frame-count",
        type=int,
        default=int(os.environ.get("PIPELINE_FRAME_COUNT", DEFAULT_FRAME_COUNT)),
    )
    parser.add_argument(
        "--frame-window",
        type=int,
        default=int(os.environ.get("PIPELINE_FRAME_WINDOW", DEFAULT_FRAME_WINDOW)),
    )
    parser.add_argument(
        "--keep-existing",
        action="store_true",
        help="Retain existing artifacts instead of cleaning the out directory.",
    )
    parser.add_argument(
        "--skip-verify-cli",
        action="store_true",
        help="Skip verify_cli. Useful when only artifacts are required.",
    )
    parser.add_argument(
        "--skip-validate",
        action="store_true",
        help="Skip schema validation in merkle_batcher.",
    )
    parser.add_argument(
        "--fail-on-verify",
        action="store_true",
        help="Treat verify_cli failures as fatal (default: warn only).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = (REPO_ROOT / out_dir).resolve()

    frames_file = out_dir / "frames.ndjson"
    facts_dir = out_dir / "facts"
    device_table = out_dir / "device_table.json"
    day_dir = out_dir / "day"
    day_bin = day_dir / f"{args.date}.bin"

    clean_outputs(out_dir, frames_file, keep_existing=args.keep_existing)
    ensure_dirs(out_dir, facts_dir, day_dir)

    scripts_dir = REPO_ROOT / "scripts"
    gateway_dir = scripts_dir / "gateway"

    run_cmd(
        "Generating framed telemetry",
        [
            sys.executable,
            str(scripts_dir / "pod_sim" / "pod_sim.py"),
            "--framed",
            "--device-id",
            args.device_id,
            "--count",
            str(args.frame_count),
            "--device-table",
            str(device_table),
            "--out",
            str(frames_file),
        ],
        cwd=REPO_ROOT,
    )

    run_cmd(
        "Deriving facts",
        [
            sys.executable,
            str(gateway_dir / "frame_verifier.py"),
            "--in",
            str(frames_file),
            "--out-facts",
            str(facts_dir),
            "--device-table",
            str(device_table),
            "--window",
            str(args.frame_window),
        ],
        cwd=REPO_ROOT,
    )

    merkle_cmd = [
        sys.executable,
        str(gateway_dir / "merkle_batcher.py"),
        "--facts",
        str(facts_dir),
        "--out",
        str(out_dir),
        "--site",
        args.site,
        "--date",
        args.date,
    ]
    if not args.skip_validate:
        merkle_cmd.append("--validate-schemas")

    run_cmd("Batching facts", merkle_cmd, cwd=REPO_ROOT)

    run_cmd(
        "Anchoring day blob",
        [
            sys.executable,
            str(gateway_dir / "ots_anchor.py"),
            str(day_bin),
        ],
        cwd=REPO_ROOT,
    )

    if not args.skip_verify_cli:
        try:
            run_cmd(
                "Verifying pipeline outputs",
                [
                    sys.executable,
                    str(gateway_dir / "verify_cli.py"),
                    "--root",
                    str(out_dir),
                    "--facts",
                    str(facts_dir),
                ],
                cwd=REPO_ROOT,
            )
        except subprocess.CalledProcessError as exc:
            if args.fail_on_verify:
                raise
            print(
                "[pipeline] WARN: verify_cli failed but continuing (set --fail-on-verify to enforce).",
                file=sys.stderr,
            )
            print(
                f"[pipeline] WARN: verify_cli exited with code {exc.returncode}",
                file=sys.stderr,
            )

    expected_artifacts = [
        day_bin,
        day_bin.with_suffix(".json"),
        day_bin.with_suffix(".bin.sha256"),
        Path(f"{day_bin}.ots"),
    ]
    missing = [p for p in expected_artifacts if not p.exists()]
    if missing:
        missing_str = ", ".join(rel(p) for p in missing)
        raise RuntimeError(f"Missing expected artifacts: {missing_str}")

    manifest_path = artifact_manifest(
        args.date,
        args.site,
        args.device_id,
        args.frame_count,
        frames_file,
        facts_dir,
        day_bin,
        out_dir,
    )

    print("[pipeline] ✓ Pipeline completed successfully")
    for path in expected_artifacts + [manifest_path]:
        print(f"[pipeline]   - {rel(path)}")


if __name__ == "__main__":
    main()
