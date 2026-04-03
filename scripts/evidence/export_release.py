#!/usr/bin/env python3
"""Export a publishable evidence bundle from a completed pipeline run."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.gateway import verify_cli as verify_cli_module  # noqa: E402
from scripts.gateway.schema_validation import (  # noqa: E402
    load_schema,
    require_schema_validation,
    validate_instance,
)
from scripts.gateway.verification_gate import local_verification_failure  # noqa: E402
from scripts.gateway.verification_manifest import verify_manifest_path  # noqa: E402
from trackone_core.ledger import sha256_hex  # noqa: E402


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
        "sha256": sha256_hex(path.read_bytes()),
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
        raise ValueError("verification manifest missing artifacts")

    pipeline_dir_resolved = pipeline_dir.resolve()
    for artifact in artifacts.values():
        if not isinstance(artifact, dict):
            raise ValueError("verification manifest artifact must be an object")
        rel_path = artifact.get("path")
        if not isinstance(rel_path, str) or not rel_path:
            raise ValueError("verification manifest artifact missing path")
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
        require_schema_validation("OTS metadata validation")
        validate_instance(meta, schema)
    return dest_meta


def _rewrite_exported_manifest(
    manifest_path: Path,
    *,
    dest_root: Path,
    day: str,
    include_frames: bool,
    meta_path: Path,
    verifier_summary: dict[str, Any],
) -> None:
    manifest = _read_json(manifest_path)

    if not include_frames:
        manifest.pop("frames_file", None)

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("exported manifest missing artifacts")
    artifacts["day_ots_meta"] = _artifact_ref(meta_path, root=dest_root)
    manifest["verifier"] = _portable_verifier_summary(verifier_summary)

    verification_bundle = manifest.get("verification_bundle")
    if not isinstance(verification_bundle, dict):
        raise ValueError("exported manifest missing verification_bundle")
    verification = verifier_summary.get("verification")
    if isinstance(verification, dict):
        disclosure_class = verification.get("disclosure_class")
        commitment_profile_id = verification.get("commitment_profile_id")
        if isinstance(disclosure_class, str):
            verification_bundle["disclosure_class"] = disclosure_class
        if isinstance(commitment_profile_id, str):
            verification_bundle["commitment_profile_id"] = commitment_profile_id
    checks_executed = verifier_summary.get("checks_executed")
    checks_skipped = verifier_summary.get("checks_skipped")
    if isinstance(checks_executed, list):
        verification_bundle["checks_executed"] = checks_executed
    if isinstance(checks_skipped, list):
        verification_bundle["checks_skipped"] = checks_skipped

    schema = load_schema("verify_manifest")
    if schema is not None:
        require_schema_validation("verification manifest export validation")
        validate_instance(manifest, schema)
    _write_json(manifest_path, manifest)


def _portable_verifier_summary(summary: dict[str, Any]) -> dict[str, Any]:
    portable: dict[str, Any] = {}
    for key in (
        "policy",
        "verification",
        "checks",
        "verification_scope_exercised",
        "checks_executed",
        "checks_skipped",
        "channels",
        "manifest",
        "overall",
    ):
        value = summary.get(key)
        if value is not None:
            portable[key] = json.loads(json.dumps(value))
    return portable


def _require_fresh_verification(
    pipeline_dir: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    facts_dir = manifest.get("facts_dir")
    if not isinstance(facts_dir, str) or not facts_dir:
        raise ValueError("verification manifest missing facts_dir")

    verification_bundle = manifest.get("verification_bundle")
    if not isinstance(verification_bundle, dict):
        raise ValueError("verification manifest missing verification_bundle")
    disclosure_class = verification_bundle.get("disclosure_class")
    commitment_profile_id = verification_bundle.get("commitment_profile_id")
    if not isinstance(disclosure_class, str) or not disclosure_class:
        raise ValueError("verification manifest missing disclosure_class")
    if not isinstance(commitment_profile_id, str) or not commitment_profile_id:
        raise ValueError("verification manifest missing commitment_profile_id")

    anchoring = manifest.get("anchoring")
    policy_mode: str | None = None
    env_overrides: dict[str, str] = {}
    if isinstance(anchoring, dict):
        policy = anchoring.get("policy")
        if isinstance(policy, dict):
            mode = policy.get("mode")
            if isinstance(mode, str) and mode:
                policy_mode = mode
        channels = anchoring.get("channels")
        if isinstance(channels, dict):
            for name, env_name in (
                ("ots", "ANCHOR_OTS_ENABLED"),
                ("tsa", "ANCHOR_TSA_ENABLED"),
                ("peers", "ANCHOR_PEERS_ENABLED"),
            ):
                channel = channels.get(name)
                if isinstance(channel, dict):
                    enabled = channel.get("enabled")
                    if isinstance(enabled, bool):
                        env_overrides[env_name] = "1" if enabled else "0"

    verify_args = [
        "--root",
        str(pipeline_dir),
        "--facts",
        str(pipeline_dir / facts_dir),
        "--json",
        "--disclosure-class",
        disclosure_class,
        "--commitment-profile-id",
        commitment_profile_id,
    ]
    if policy_mode:
        verify_args.extend(["--policy-mode", policy_mode])

    stdout = io.StringIO()
    stderr = io.StringIO()
    with (
        patch.dict(os.environ, env_overrides, clear=False),
        contextlib.redirect_stdout(stdout),
        contextlib.redirect_stderr(stderr),
    ):
        rc = verify_cli_module.main(verify_args)
    err_text = stderr.getvalue().strip()
    if err_text:
        print(err_text, file=sys.stderr)

    out_text = stdout.getvalue().strip()
    if not out_text:
        raise ValueError(
            "fresh verification failed; refusing to export unverified evidence"
        )
    try:
        summary = json.loads(out_text)
    except json.JSONDecodeError as exc:
        if rc != 0:
            raise ValueError(
                "fresh verification failed; refusing to export unverified evidence"
            ) from exc
        raise ValueError(f"verify_cli emitted invalid JSON summary: {exc}") from exc
    if not isinstance(summary, dict):
        raise ValueError("verify_cli summary must be a JSON object")
    local_failure = local_verification_failure(summary)
    if local_failure is not None:
        raise ValueError(
            "fresh verification failed; refusing to export unverified evidence"
        )
    return summary


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
    manifest_path = verify_manifest_path(pipeline_dir / "day", day)
    manifest = _read_json(manifest_path)
    if manifest.get("site") != site:
        raise ValueError(
            "verification manifest site mismatch: "
            f"expected {site}, got {manifest.get('site')}"
        )
    if manifest.get("date") != day:
        raise ValueError(
            "verification manifest date mismatch: "
            f"expected {day}, got {manifest.get('date')}"
        )

    facts_dir = manifest.get("facts_dir")
    if not isinstance(facts_dir, str) or not facts_dir:
        raise ValueError("verification manifest missing facts_dir")
    verifier_summary = _require_fresh_verification(pipeline_dir, manifest)

    dest_root = evidence_repo / "site" / site / "day" / day
    if dest_root.exists():
        shutil.rmtree(dest_root)
    dest_root.mkdir(parents=True, exist_ok=True)

    _copy_dir(pipeline_dir / facts_dir, dest_root / "facts")
    _copy_manifest_artifacts(pipeline_dir, dest_root, manifest)
    exported_manifest = verify_manifest_path(dest_root / "day", day)
    _copy_file(manifest_path, exported_manifest)

    if include_frames:
        frames_file = manifest.get("frames_file")
        if not isinstance(frames_file, str) or not frames_file:
            raise ValueError(
                "verification manifest missing frames_file for frame export"
            )
        _copy_file(pipeline_dir / frames_file, dest_root / "frames.ndjson")

    source_meta = _find_meta_sidecar(pipeline_dir, day)
    exported_meta = _rewrite_meta_sidecar(source_meta, dest_root=dest_root, day=day)

    _rewrite_exported_manifest(
        exported_manifest,
        dest_root=dest_root,
        day=day,
        include_frames=include_frames,
        meta_path=exported_meta,
        verifier_summary=verifier_summary,
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
