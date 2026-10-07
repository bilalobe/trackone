"""Freeze a successful VTL acceptance run and source snapshot into a deterministic archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import subprocess
import tarfile
from pathlib import Path

from replay_corpus import verify_inventory
from source_snapshot import source_files
from wire_cases import validate_matrix

ROOT = Path(__file__).resolve().parents[2]


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"vtl-https-acceptance-\d{8}T\d{6}Z", args.release):
        parser.error("release must be vtl-https-acceptance-<YYYYMMDDTHHMMSSZ>")
    if args.output.exists() or Path(str(args.output) + ".sha256").exists():
        parser.error("immutable archive or checksum already exists")
    verify_inventory(args.result)
    coverage = json.loads((args.result / "reports/wire-coverage.json").read_text())
    try:
        validate_matrix(coverage)
    except ValueError as exc:
        parser.error(str(exc))
    for name in ("class-a", "class-b", "class-c"):
        for verifier in ("independent", "trackone"):
            report = json.loads(
                (args.result / "reports" / f"{name}-{verifier}.json").read_text()
            )
            if report["overall"] != "success":
                parser.error("all positive reports must succeed")
    files = {}
    allowed = {
        "SHA256SUMS",
        "evaluation-time.txt",
        "tool-versions.json",
        "verification-inputs.json",
        "source-sha256.json",
    }
    allowed_dirs = {
        "published",
        "reports",
        "https-evidence",
        "trust-inputs",
        "tsa-exchange",
    }
    for path in sorted(args.result.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(args.result)
        if relative.as_posix() not in allowed and relative.parts[0] not in allowed_dirs:
            parser.error(f"unexpected result file: {relative}")
        data = path.read_bytes()
        if path.suffix == ".key" or b"PRIVATE KEY-----" in data:
            parser.error(f"private key in result: {relative}")
        files[f"evidence/{relative.as_posix()}"] = data
    # Explicit source roots include workspace members and their build-time inputs.
    # No .git, IDE state, local connector configuration, or build products are included.
    sources = source_files(ROOT)
    recorded_sources = json.loads((args.result / "source-sha256.json").read_text())
    if {
        name: hashlib.sha256(data).hexdigest() for name, data in sources.items()
    } != recorded_sources:
        parser.error(
            "source snapshot differs from the successful run; rerun acceptance"
        )
    for name, data in sources.items():
        files[f"source/{name}"] = data
    for name in ("replay_corpus.py", "https_fixture_server.py"):
        files[f"tools/{name}"] = (ROOT / "toolset/acceptance" / name).read_bytes()
    files["tools/verify_https_bundle.py"] = (
        ROOT / "toolset/independent-verifier/verify_https_bundle.py"
    ).read_bytes()
    for path in (ROOT / "docs/diagrams").glob("vtl-wire-*"):
        files[f"docs/diagrams/{path.name}"] = path.read_bytes()
    for name in ("vtl-https-acceptance.md",):
        files[f"docs/{name}"] = (ROOT / "docs" / name).read_bytes()
    files["README.md"] = (ROOT / "toolset/acceptance/CORPUS.md").read_bytes()
    files["toolset/acceptance/README.md"] = (
        ROOT / "toolset/acceptance/README.md"
    ).read_bytes()
    files["toolset/acceptance/CORPUS.md"] = (
        ROOT / "toolset/acceptance/CORPUS.md"
    ).read_bytes()
    provenance = {
        "release": args.release,
        "release_tag": f"corpus-{args.release}",
        "repository": "https://github.com/bilalobe/trackone",
        "base_commit": git("rev-parse", "HEAD"),
        "source_is_clean_commit": False,
        "source_note": "Packaged working-tree bytes are authoritative for this run; base commit alone is insufficient.",
        "source_sha256": {
            name: hashlib.sha256(data).hexdigest()
            for name, data in sorted(files.items())
            if name.startswith("source/")
        },
        "claims": "Controlled interoperability and focused negative coverage, not field validation or complete Appendix E conformance.",
    }
    files["provenance.json"] = (
        json.dumps(provenance, indent=2, sort_keys=True) + "\n"
    ).encode()
    files["SHA256SUMS"] = "".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n"
        for name, data in sorted(files.items())
    ).encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with (
        args.output.open("xb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed,
        tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
        ) as archive,
    ):
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(f"{args.release}/{name}")
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    with Path(str(args.output) + ".sha256").open("x") as checksum:
        checksum.write(f"{digest}  {args.output.name}\n")
    print(f"{digest}  {args.output}")


if __name__ == "__main__":
    main()
