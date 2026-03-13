#!/usr/bin/env python3
"""Export a publishable evidence bundle from a completed pipeline run."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.gateway.schema_validation import (  # noqa: E402
    load_schema,
    validate_instance,
)


def _read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"JSON object required: {path}")
    return data


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _artifact_ref(path: Path, *, root: Path) -> dict[str, str]:
    return {
        "path": str(path.relative_to(root)),
        "sha256": sha256(path.read_bytes()).hexdigest(),
    }


def _copy_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _copy_dir(src: Path, dst: Path) -> None:
    shutil.copytree(src, dst, dirs_exist_ok=True)


def _find_meta_sidecar(pipeline_dir: Path, day: str) -> Path:
    candidates: list[Path] = [pipeline_dir / "day" / f"{day}.ots.meta.json"]
    for base in (pipeline_dir, *pipeline_dir.parents):
        candidates.append(base / "proofs" / f"{day}.ots.meta.json")

    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if candidate.exists():
            return candidate

    raise FileNotFoundError(f"OTS metadata sidecar not found for {day}")


def _copy_manifest_artifacts(
    pipeline_dir: Path,
    dest_root: Path,
    manifest: dict[str, Any],
) -> None:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("pipeline manifest missing artifacts")

    pipeline_dir_resolved = pipeline_dir.resolve()
    for artifact in artifacts.values():
        if not isinstance(artifact, dict):
            raise ValueError("pipeline manifest artifact must be an object")
        rel_path = artifact.get("path")
        if not isinstance(rel_path, str) or not rel_path:
            raise ValueError("pipeline manifest artifact missing path")
        src = (pipeline_dir / rel_path).resolve()
        try:
            src.relative_to(pipeline_dir_resolved)
        except ValueError:
            raise ValueError(
                f"manifest artifact path escapes pipeline directory: {rel_path!r}"
            ) from None
        if not src.exists():
            raise FileNotFoundError(f"manifest artifact missing on disk: {src}")
        _copy_file(src, dest_root / rel_path)


def _rewrite_meta_sidecar(
    source_meta: Path,
    *,
    dest_root: Path,
    day: str,
) -> Path:
    meta = _read_json(source_meta)
    meta.pop("milestone", None)
    meta["artifact"] = f"day/{day}.cbor"
    meta["ots_proof"] = f"day/{day}.cbor.ots"
    dest_meta = dest_root / "day" / f"{day}.ots.meta.json"
    _write_json(dest_meta, meta)

    schema = load_schema("ots_meta")
    if schema is not None:
        validate_instance(meta, schema)
    return dest_meta


def _rewrite_exported_manifest(
    manifest_path: Path,
    *,
    dest_root: Path,
    day: str,
    include_frames: bool,
    meta_path: Path,
) -> None:
    manifest = _read_json(manifest_path)

    if not include_frames:
        manifest.pop("frames_file", None)

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("exported manifest missing artifacts")
    artifacts["day_ots_meta"] = _artifact_ref(meta_path, root=dest_root)

    schema = load_schema("pipeline_manifest")
    if schema is not None:
        validate_instance(manifest, schema)
    _write_json(manifest_path, manifest)


def _update_index(
    evidence_repo: Path,
    *,
    site: str,
    day: str,
    bundle_root: Path,
    manifest_path: Path,
    frames_included: bool,
    tag_name: str | None,
) -> None:
    index_path = evidence_repo / "index.json"
    if index_path.exists():
        index = _read_json(index_path)
    else:
        index = {"version": 1, "exports": []}

    exports = index.setdefault("exports", [])
    if not isinstance(exports, list):
        raise ValueError("index.json exports must be an array")

    rel_bundle_root = str(bundle_root.relative_to(evidence_repo))
    rel_manifest = str(manifest_path.relative_to(evidence_repo))
    entry = {
        "site": site,
        "day": day,
        "bundle_root": rel_bundle_root,
        "manifest": rel_manifest,
        "frames_included": frames_included,
    }
    if tag_name is not None:
        entry["tag"] = tag_name

    filtered = [
        item
        for item in exports
        if not (
            isinstance(item, dict)
            and item.get("site") == site
            and item.get("day") == day
        )
    ]
    filtered.append(entry)
    filtered.sort(
        key=lambda item: (str(item.get("site", "")), str(item.get("day", "")))
    )
    index["exports"] = filtered
    _write_json(index_path, index)


def export_release(
    pipeline_dir: Path,
    evidence_repo: Path,
    *,
    site: str,
    day: str,
    include_frames: bool = False,
    tag_name: str | None = None,
) -> Path:
    manifest_path = pipeline_dir / "day" / f"{day}.pipeline-manifest.json"
    manifest = _read_json(manifest_path)
    if manifest.get("site") != site:
        raise ValueError(
            f"pipeline manifest site mismatch: expected {site}, got {manifest.get('site')}"
        )
    if manifest.get("date") != day:
        raise ValueError(
            f"pipeline manifest date mismatch: expected {day}, got {manifest.get('date')}"
        )

    facts_dir = manifest.get("facts_dir")
    if not isinstance(facts_dir, str) or not facts_dir:
        raise ValueError("pipeline manifest missing facts_dir")

    dest_root = evidence_repo / "site" / site / "day" / day
    if dest_root.exists():
        shutil.rmtree(dest_root)
    dest_root.mkdir(parents=True, exist_ok=True)

    _copy_dir(pipeline_dir / facts_dir, dest_root / "facts")
    _copy_manifest_artifacts(pipeline_dir, dest_root, manifest)
    exported_manifest = dest_root / "day" / f"{day}.pipeline-manifest.json"
    _copy_file(manifest_path, exported_manifest)

    if include_frames:
        frames_file = manifest.get("frames_file")
        if not isinstance(frames_file, str) or not frames_file:
            raise ValueError("pipeline manifest missing frames_file for frame export")
        _copy_file(pipeline_dir / frames_file, dest_root / "frames.ndjson")

    source_meta = _find_meta_sidecar(pipeline_dir, day)
    exported_meta = _rewrite_meta_sidecar(source_meta, dest_root=dest_root, day=day)

    _rewrite_exported_manifest(
        exported_manifest,
        dest_root=dest_root,
        day=day,
        include_frames=include_frames,
        meta_path=exported_meta,
    )
    _update_index(
        evidence_repo,
        site=site,
        day=day,
        bundle_root=dest_root,
        manifest_path=exported_manifest,
        frames_included=include_frames,
        tag_name=tag_name,
    )
    return dest_root


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _ensure_git_repo(repo: Path) -> None:
    if (repo / ".git").exists():
        return
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init")


def _has_head(repo: Path) -> bool:
    try:
        _git(repo, "rev-parse", "--verify", "HEAD")
        return True
    except subprocess.CalledProcessError:
        return False


def _maybe_commit(
    repo: Path,
    *,
    site: str,
    day: str,
    sign: bool,
) -> None:
    status = _git(repo, "status", "--short")
    if not status.strip():
        return

    _git(repo, "add", ".")
    cmd: list[str] = []
    if sign:
        cmd.extend(["commit", "-S"])
    else:
        cmd.extend(["-c", "commit.gpgsign=false", "commit"])
    cmd.extend(["-m", f"evidence: {site} {day}"])
    _git(repo, *cmd)


def _maybe_tag(
    repo: Path,
    *,
    tag_name: str,
    sign: bool,
) -> None:
    if not _has_head(repo):
        raise RuntimeError("cannot create a tag before the evidence repo has a commit")

    existing = _git(repo, "tag", "--list", tag_name)
    if existing.strip():
        raise RuntimeError(f"tag already exists: {tag_name}")

    if sign:
        _git(repo, "tag", "-s", tag_name, "-m", tag_name)
    else:
        _git(repo, "-c", "tag.gpgSign=false", "tag", "-a", tag_name, "-m", tag_name)


def _maybe_bundle(repo: Path, bundle_out: Path) -> None:
    if not _has_head(repo):
        raise RuntimeError(
            "cannot create a git bundle before the evidence repo has a commit"
        )
    bundle_out.parent.mkdir(parents=True, exist_ok=True)
    _git(repo, "bundle", "create", str(bundle_out), "--all")


def _ensure_committed_export(
    repo: Path,
    *,
    site: str,
    day: str,
    sign: bool,
) -> None:
    """Ensure exported working-tree changes are committed before tagging/bundling."""
    _maybe_commit(repo, site=site, day=day, sign=sign)
    if not _has_head(repo):
        raise RuntimeError(
            "cannot tag or bundle exported evidence before the evidence repo has a commit"
        )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export a publishable evidence bundle from a pipeline run."
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

    export_release(
        args.pipeline_dir,
        args.evidence_repo,
        site=args.site,
        day=args.day,
        include_frames=args.include_frames,
        tag_name=tag_name if args.tag else None,
    )

    if args.git_commit or args.tag or args.bundle_out is not None:
        _ensure_git_repo(args.evidence_repo)
    if args.git_commit:
        _maybe_commit(args.evidence_repo, site=args.site, day=args.day, sign=args.sign)
    elif args.tag or args.bundle_out is not None:
        _ensure_committed_export(
            args.evidence_repo,
            site=args.site,
            day=args.day,
            sign=args.sign,
        )
    if args.tag:
        _maybe_tag(args.evidence_repo, tag_name=tag_name, sign=args.sign)
    if args.bundle_out is not None:
        _maybe_bundle(args.evidence_repo, args.bundle_out)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
