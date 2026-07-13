#!/usr/bin/env python3
"""Assemble the deterministic TrackOne conformance archive v2 carrier."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any


ARTIFACT_TYPE = "application/vnd.trackone.conformance.archive.v2+tar"
SCHEMA_URI = (
    "https://raw.githubusercontent.com/bilalobe/trackone/main/"
    "toolset/unified/schemas/conformance_archive_manifest_v2.schema.json"
)


class BuildError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def reject_symlinks(root: Path) -> None:
    for path in [root, *root.rglob("*")]:
        if path.is_symlink():
            raise BuildError(f"archive inputs must not contain symlinks: {path}")


def copy_tree(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise BuildError(f"input directory is missing: {source}")
    reject_symlinks(source)
    shutil.copytree(source, destination)


def copy_artifacts(source: Path, pattern: str, destination: Path, label: str) -> int:
    if not source.is_dir():
        raise BuildError(f"{label} directory is missing: {source}")
    destination.mkdir(parents=True, exist_ok=True)
    paths = sorted(source.glob(pattern))
    if not paths:
        raise BuildError(f"no {label} artifacts match {source / pattern}")
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise BuildError(f"invalid {label} artifact: {path}")
        shutil.copy2(path, destination / path.name)
    return len(paths)


def write_checksums(root: Path) -> int:
    paths = sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    lines = [f"{sha256(path)}  {path.relative_to(root).as_posix()}" for path in paths]
    (root / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(paths)


def normalized_tar_info(path: Path, arcname: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(arcname)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    if path.is_dir():
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
        info.size = 0
    elif path.is_file():
        info.type = tarfile.REGTYPE
        executable = bool(path.stat().st_mode & stat.S_IXUSR)
        info.mode = 0o755 if executable else 0o644
        info.size = path.stat().st_size
    else:
        raise BuildError(f"unsupported archive member: {path}")
    return info


def create_tarball(root: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as archive:
                members = [root, *sorted(root.rglob("*"))]
                for path in members:
                    arcname = path.relative_to(root.parent).as_posix()
                    info = normalized_tar_info(path, arcname)
                    if path.is_file():
                        with path.open("rb") as stream:
                            archive.addfile(info, stream)
                    else:
                        archive.addfile(info)


def assemble(args: argparse.Namespace) -> dict[str, Any]:
    repo = args.repo.resolve()
    verifier = args.verifier.resolve()
    if not verifier.is_file():
        raise BuildError(f"verifier binary is missing: {verifier}")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        raise BuildError("--commit must be a full lowercase 40-character Git SHA")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", args.version):
        raise BuildError("--version must be the workspace release version")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        raise BuildError("--repository must use owner/name form")
    if not args.carrier.startswith("ghcr.io/") or ":" not in args.carrier:
        raise BuildError("--carrier must be a tag-addressed ghcr.io reference")

    safe_subject = re.sub(r"[^A-Za-z0-9_.-]+", "-", args.subject).strip("-.")
    if not safe_subject:
        raise BuildError("--subject does not contain a portable name")

    with tempfile.TemporaryDirectory(prefix="trackone-conformance-build-") as temp:
        root = Path(temp) / f"trackone-conformance-{safe_subject}"
        (root / "contracts/toolset").mkdir(parents=True)
        (root / "verifier/bin").mkdir(parents=True)
        copy_tree(repo / "toolset/unified", root / "contracts/toolset/unified")
        copy_tree(repo / "toolset/vectors", root / "vectors")
        crate_count = copy_artifacts(
            args.crates_dir.resolve(),
            f"*-{args.version}.crate",
            root / "software/crates",
            "crate",
        )
        helm_count = copy_artifacts(
            args.helm_dir.resolve(),
            f"trackone-{args.version}.tgz",
            root / "software/helm",
            "Helm",
        )
        if crate_count != 8:
            raise BuildError(f"expected exactly 8 workspace crate packages, found {crate_count}")
        if helm_count != 1:
            raise BuildError(f"expected exactly one Helm chart, found {helm_count}")
        shutil.copy2(verifier, root / "verifier/bin/trackone-evidence")
        os.chmod(root / "verifier/bin/trackone-evidence", 0o755)
        shutil.copy2(
            repo / "toolset/independent-verifier/verify_conformance_archive.py",
            root / "verifier/verify_conformance_archive.py",
        )
        shutil.copy2(
            repo / "toolset/independent-verifier/README.md",
            root / "verifier/README.md",
        )

        manifest = {
            "schema": "trackone-conformance-archive-v2",
            "schema_uri": SCHEMA_URI,
            "version": 2,
            "subject": {
                "kind": args.subject_kind,
                "name": args.subject,
                "git_commit": args.commit,
            },
            "software_version": args.version,
            "repository": args.repository,
            "carrier": {
                "oci_ref": args.carrier,
                "artifact_type": ARTIFACT_TYPE,
            },
            "contents": {
                "schema_catalog": "contracts/toolset/unified/schema-catalog.json",
                "schemas": "contracts/toolset/unified/schemas",
                "cddl": "contracts/toolset/unified/cddl",
                "vectors": "vectors",
                "crates": "software/crates",
                "helm": "software/helm",
                "detached_verifier": "verifier/bin/trackone-evidence",
            },
            "claims": {
                "canonical_cbor_v1_vectors": True,
                "canonical_cbor_v2_preview_vectors": True,
                "v2_full_conformance": False,
                "negative_fixture_floor": True,
                "offline_schema_resolution": True,
            },
        }
        write_json(root / "conformance-manifest.json", manifest)
        checksummed_files = write_checksums(root)
        create_tarball(root, args.output.resolve())

        sidecar = args.output.resolve().with_name(args.output.name + ".sha256")
        sidecar.write_text(
            f"{sha256(args.output.resolve())}  {args.output.name}\n", encoding="utf-8"
        )
        manifest_sidecar = args.output.resolve().with_name(
            args.output.name + ".manifest.json"
        )
        write_json(manifest_sidecar, manifest)

    return {
        "ok": True,
        "archive": str(args.output.resolve()),
        "archive_sha256": sha256(args.output.resolve()),
        "checksummed_files": checksummed_files,
        "crates": crate_count,
        "helm_charts": helm_count,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--subject-kind", choices=("commit", "release"), required=True)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--carrier", required=True)
    parser.add_argument("--crates-dir", type=Path, required=True)
    parser.add_argument("--helm-dir", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = assemble(args)
    except Exception as exc:
        print(f"conformance archive build failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
