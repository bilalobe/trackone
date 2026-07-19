#!/usr/bin/env python3
"""Fail when Cargo package dependencies cross TrackOne source-layer boundaries."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LAYERS = {"crates", "apps", "bindings"}


def layer_for(path: Path) -> str:
    relative = path.resolve().relative_to(ROOT)
    if not relative.parts or relative.parts[0] not in LAYERS:
        raise ValueError(f"workspace package is outside a source layer: {relative}")
    return relative.parts[0]


def metadata() -> dict[str, object]:
    completed = subprocess.run(
        [
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--locked",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def check() -> tuple[int, int]:
    document = metadata()
    packages = document["packages"]
    by_manifest = {
        Path(package["manifest_path"]).resolve(): package for package in packages
    }
    package_layers = {
        package["name"]: layer_for(Path(package["manifest_path"]).parent)
        for package in packages
    }
    errors: list[str] = []
    internal_edges = 0

    if "trackone-gateway" in package_layers:
        errors.append("the removed mixed-purpose trackone-gateway package returned")

    for package in packages:
        name = package["name"]
        source_layer = package_layers[name]
        if source_layer == "bindings" and package["publish"] != []:
            errors.append(f"{name}: binding packages must set publish = false")

        for target in package["targets"]:
            if "lib" in target["kind"]:
                expected = name.replace("-", "_")
                if target["name"] != expected:
                    errors.append(
                        f"{name}: library target {target['name']!r} must be {expected!r}"
                    )

        for dependency in package["dependencies"]:
            raw_path = dependency.get("path")
            if raw_path is None:
                continue
            manifest = Path(raw_path).resolve() / "Cargo.toml"
            target = by_manifest.get(manifest)
            if target is None:
                errors.append(f"{name}: internal path is not a workspace member: {raw_path}")
                continue
            internal_edges += 1
            target_layer = package_layers[target["name"]]
            if source_layer in {"crates", "apps"} and target_layer != "crates":
                errors.append(
                    f"{name}: {source_layer} packages may not depend on "
                    f"{target_layer} package {target['name']}"
                )
            if source_layer == "bindings" and target_layer != "crates":
                errors.append(
                    f"{name}: bindings may depend only on reusable crates, "
                    f"not {target_layer} package {target['name']}"
                )

    if errors:
        raise SystemExit("workspace boundary violations:\n- " + "\n- ".join(errors))
    return len(packages), internal_edges


def main() -> int:
    package_count, edge_count = check()
    print(
        f"validated {package_count} workspace packages and "
        f"{edge_count} internal dependency edges"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
