#!/usr/bin/env python3
"""Install the built wheel into the active environment and verify imports."""

from __future__ import annotations

import argparse
import glob
import os
import subprocess
import sys
from pathlib import Path


def _pick_wheel(repo_root: Path) -> Path:
    pattern = str(repo_root / "target" / "wheels" / "trackone-*.whl")
    wheels = sorted(glob.glob(pattern))
    if not wheels:
        raise SystemExit(
            "No wheel found under target/wheels. Did the artifact download step run?"
        )

    preferred_candidates = [
        w for w in wheels if "manylinux" in os.path.basename(w)
    ] or wheels
    preferred = max(preferred_candidates, key=os.path.getmtime)
    return Path(preferred)


def _install_wheel(wheel: Path) -> None:
    print(f"Installing wheel: {wheel}")
    subprocess.check_call(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--force-reinstall",
            str(wheel),
        ]
    )


def _verify_import(repo_root: Path) -> None:
    source = (repo_root / "src" / "trackone_core").resolve()

    import trackone_core
    import trackone_core._native as native

    package_path = Path(trackone_core.__file__).resolve()
    native_path = Path(native.__file__).resolve()
    if package_path.is_relative_to(source):
        raise SystemExit(
            f"trackone_core imported from checkout instead of wheel: {package_path}"
        )
    if native_path.is_relative_to(source):
        raise SystemExit(
            f"trackone_core._native imported from checkout instead of wheel: {native_path}"
        )

    print("Imported trackone_core from:", package_path)
    print("Imported trackone_core._native from:", native_path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    wheel = _pick_wheel(repo_root)
    _install_wheel(wheel)
    _verify_import(repo_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
