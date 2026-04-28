#!/usr/bin/env python3
"""Extract the native extension from the canonical wheel for source tox jobs."""

from __future__ import annotations

import argparse
import glob
import os
import zipfile
from pathlib import Path


def _pick_wheel(wheel_dir: Path) -> Path:
    wheels = sorted(glob.glob(str(wheel_dir / "trackone-*.whl")))
    if not wheels:
        raise SystemExit(f"No TrackOne wheel found under {wheel_dir}")
    preferred = [w for w in wheels if "manylinux" in os.path.basename(w)] or wheels
    return Path(max(preferred, key=os.path.getmtime))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel-dir", type=Path, default=Path("target/wheels"))
    parser.add_argument("--package-dir", type=Path, default=Path("src/trackone_core"))
    args = parser.parse_args()

    wheel = _pick_wheel(args.wheel_dir)
    package_dir = args.package_dir
    package_dir.mkdir(parents=True, exist_ok=True)

    extracted: list[Path] = []
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.namelist():
            member_path = Path(member)
            if (
                len(member_path.parts) == 2
                and member_path.parts[0] == "trackone_core"
                and member_path.name.startswith("_native")
                and member_path.suffix in {".so", ".pyd"}
            ):
                target = package_dir / member_path.name
                target.write_bytes(archive.read(member))
                extracted.append(target)

    if not extracted:
        raise SystemExit(f"No trackone_core._native extension found in {wheel}")

    for path in extracted:
        print(f"Hydrated native extension from {wheel.name}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
