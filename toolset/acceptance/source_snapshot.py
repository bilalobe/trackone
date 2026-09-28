"""Explicit, reviewable source selection for the acceptance producer and checkers."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


def source_files(root: Path) -> dict[str, bytes]:
    names = {"Cargo.toml", "Cargo.lock", "LICENSE", "justfile"}
    for directory in ("apps", "crates", "toolset/acceptance", "toolset/vectors"):
        for path in (root / directory).rglob("*"):
            if (
                path.is_file()
                and not path.is_symlink()
                and not set(path.parts) & {"__pycache__", "target", ".ruff_cache"}
                and path.suffix
                in {
                    ".rs",
                    ".toml",
                    ".sql",
                    ".py",
                    ".md",
                    ".json",
                    ".cbor",
                    ".tsr",
                    ".tsq",
                    ".b64",
                    ".pem",
                    ".txt",
                }
            ):
                names.add(path.relative_to(root).as_posix())
    names.add("toolset/independent-verifier/verify_https_bundle.py")
    result = {name: (root / name).read_bytes() for name in sorted(names)}
    for name, data in result.items():
        if re.search(rb"(?m)^-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----", data):
            raise ValueError(f"private key in source snapshot: {name}")
    return result


def source_hashes(root: Path) -> dict[str, str]:
    return {
        name: hashlib.sha256(data).hexdigest()
        for name, data in source_files(root).items()
    }
