#!/usr/bin/env python3
"""Emit Rust-native postcard framed NDJSON fixtures."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.pod_sim import pod_sim  # noqa: E402


def _load_native_crypto() -> Any:
    try:
        import trackone_core.crypto as native_crypto
    except ImportError as exc:  # pragma: no cover - environment issue
        raise RuntimeError(
            "trackone_core native crypto helper is required for Rust framed fixture emission. "
            "Build/install the native extension or run via tox."
        ) from exc
    return native_crypto


def emit_frames(
    *,
    device_id: str,
    count: int,
    out_path: Path,
    device_table_path: Path,
    site_id: str | None = None,
    provisioning_input_path: Path | None = None,
    start_fc: int = 0,
) -> None:
    if count < 0:
        raise ValueError("count must be >= 0")
    if start_fc < 0:
        raise ValueError("start_fc must be >= 0")
    if start_fc + count > 2**32:
        raise ValueError("start_fc + count exceeds framed u32 counter range")

    native_crypto = _load_native_crypto()
    dev_id_u16 = pod_sim.parse_dev_id_u16(device_id)
    device_table = pod_sim.load_device_table(device_table_path)
    device_entry = pod_sim.ensure_device_entry(
        device_table, dev_id_u16, site_id=site_id
    )
    pod_sim.save_device_table(device_table_path, device_table)

    if provisioning_input_path is not None:
        provisioning = pod_sim.load_provisioning_input(provisioning_input_path)
        meta = device_table.get("_meta")
        if not isinstance(meta, dict):
            raise ValueError("device table metadata is missing")
        master_seed_b64 = meta.get("master_seed")
        if not isinstance(master_seed_b64, str):
            raise ValueError("device table metadata.master_seed is missing")

        master_seed = base64.b64decode(master_seed_b64)
        pod_sim.ensure_authoritative_provisioning_record(
            provisioning,
            dev_id_u16=dev_id_u16,
            master_seed=master_seed,
            site_id=site_id,
        )
        if site_id and not isinstance(provisioning.get("site_id"), str):
            provisioning["site_id"] = site_id
        pod_sim.save_provisioning_input(provisioning_input_path, provisioning)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for fc in range(start_fc, start_fc + count):
        frame = native_crypto.emit_rust_postcard_framed_fixture(
            dev_id_u16,
            fc,
            device_entry,
        )
        lines.append(json.dumps(frame, separators=(",", ":")))
    payload = ("\n".join(lines) + "\n") if lines else ""
    out_path.write_text(payload, encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Emit Rust postcard framed NDJSON fixtures"
    )
    parser.add_argument("--device-id", default="pod-001")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--device-table", type=Path, required=True)
    parser.add_argument("--site", default=None)
    parser.add_argument("--provisioning-input", type=Path, default=None)
    parser.add_argument("--start-fc", type=int, default=0)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    emit_frames(
        device_id=args.device_id,
        count=args.count,
        out_path=args.out,
        device_table_path=args.device_table,
        site_id=args.site,
        provisioning_input_path=args.provisioning_input,
        start_fc=args.start_fc,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
