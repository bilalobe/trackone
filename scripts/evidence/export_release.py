#!/usr/bin/env python3
"""Wrapper for the Rust-native TrackOne evidence export contract."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _rust_export_cmd(
    pipeline_dir: Path,
    evidence_repo: Path,
    *,
    site: str,
    day: str,
    include_frames: bool = False,
    git_commit: bool = False,
    sign: bool = False,
    tag: bool = False,
    tag_name: str | None = None,
    bundle_out: Path | None = None,
) -> list[str]:
    cmd = [
        "cargo",
        "run",
        "--quiet",
        "--package",
        "trackone-evidence",
        "--",
        "export",
        "--pipeline-dir",
        str(pipeline_dir),
        "--evidence-repo",
        str(evidence_repo),
        "--site",
        site,
        "--day",
        day,
    ]
    if include_frames:
        cmd.append("--include-frames")
    if git_commit:
        cmd.append("--git-commit")
    if sign:
        cmd.append("--sign")
    if tag:
        cmd.append("--tag")
    if tag_name is not None:
        cmd.extend(["--tag-name", tag_name])
    if bundle_out is not None:
        cmd.extend(["--bundle-out", str(bundle_out)])
    return cmd


def _run_rust_export(cmd: list[str]) -> Path:
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.stderr:
        print(proc.stderr.strip(), file=sys.stderr)
    if proc.returncode != 0:
        if "fresh verification failed" in proc.stderr:
            raise ValueError(proc.stderr.strip())
        raise RuntimeError("Rust evidence export failed")
    out = proc.stdout.strip().splitlines()
    if not out:
        raise RuntimeError("Rust evidence export did not report an output path")
    return Path(out[-1])


def export_release(
    pipeline_dir: Path,
    evidence_repo: Path,
    *,
    site: str,
    day: str,
    include_frames: bool = False,
    tag_name: str | None = None,
) -> Path:
    return _run_rust_export(
        _rust_export_cmd(
            pipeline_dir,
            evidence_repo,
            site=site,
            day=day,
            include_frames=include_frames,
            tag=tag_name is not None,
            tag_name=tag_name,
        )
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export a publishable evidence bundle using the Rust contract."
    )
    parser.add_argument("--pipeline-dir", type=Path, required=True)
    parser.add_argument("--evidence-repo", type=Path, required=True)
    parser.add_argument("--site", required=True)
    parser.add_argument("--day", required=True)
    parser.add_argument(
        "--include-frames",
        action="store_true",
        help="Include frames.ndjson in the exported evidence set.",
    )
    parser.add_argument(
        "--git-commit",
        action="store_true",
        help="Commit the exported evidence into the target git repository.",
    )
    parser.add_argument(
        "--sign",
        action="store_true",
        help="Sign git commits/tags created by this command.",
    )
    parser.add_argument(
        "--tag",
        action="store_true",
        help="Create an evidence tag after export.",
    )
    parser.add_argument(
        "--tag-name",
        default=None,
        help="Override the evidence tag name (default: evidence/<site>/<day>).",
    )
    parser.add_argument(
        "--bundle-out",
        type=Path,
        default=None,
        help="Optional path to write a git bundle after export.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    tag_name = args.tag_name or f"evidence/{args.site}/{args.day}"
    _run_rust_export(
        _rust_export_cmd(
            args.pipeline_dir,
            args.evidence_repo,
            site=args.site,
            day=args.day,
            include_frames=args.include_frames,
            git_commit=args.git_commit,
            sign=args.sign,
            tag=args.tag,
            tag_name=tag_name if args.tag else None,
            bundle_out=args.bundle_out,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
