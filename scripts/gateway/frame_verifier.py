#!/usr/bin/env python3
"""
frame_verifier.py

Parse framed NDJSON records from pod_sim v2, enforce a basic replay window,
"decrypt" the stub ciphertext (JSON payload), validate against fact.schema,
and write canonical fact JSON files for batching.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

try:
    import jsonschema

    JSONSCHEMA_AVAILABLE = True
except Exception:
    JSONSCHEMA_AVAILABLE = False


def load_fact_schema() -> dict | None:
    schema_path = (
            Path(__file__).parent.parent.parent
            / "toolset"
            / "unified"
            / "schemas"
            / "fact.schema.json"
    )
    if schema_path.exists():
        try:
            return json.loads(schema_path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[WARN] Failed to load fact schema: {e}", file=sys.stderr)
    return None


def validate_fact(obj: dict, schema: dict | None) -> None:
    if not (schema and JSONSCHEMA_AVAILABLE):
        return
    try:
        jsonschema.validate(instance=obj, schema=schema)
    except jsonschema.ValidationError as e:
        print(f"[WARN] Fact schema validation failed: {e.message}", file=sys.stderr)
    except Exception as e:
        print(f"[WARN] Fact schema validation error: {e}", file=sys.stderr)


def device_label(dev_id_u16: int) -> str:
    return f"pod-{dev_id_u16:03d}"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Verify framed input and emit facts")
    p.add_argument("--in", dest="in_path", type=Path, help="Frames NDJSON file (or omit for stdin)")
    p.add_argument("--out-facts", type=Path, required=True, help="Directory to write canonical facts")
    p.add_argument(
        "--device-table",
        type=Path,
        required=True,
        help="Path to device table JSON (will be created if missing)",
    )
    p.add_argument("--window", type=int, default=64, help="Replay window size in fc units")
    return p.parse_args(argv)


def load_device_table(path: Path) -> Dict[str, Dict[str, Any]]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_device_table(path: Path, tbl: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(tbl, indent=2) + "\n", encoding="utf-8")


def accept_frame(fc: int, highest: int | None, window: int) -> bool:
    # First frame from a device: accept any non-negative fc
    if highest is None:
        return fc >= 0
    # Subsequent frames must be within (0, window] steps ahead of highest
    delta = fc - highest
    return 0 < delta <= window


def process(argv=None) -> int:
    args = parse_args(argv)
    frames_fh = (
        args.in_path.open("r", encoding="utf-8") if args.in_path else sys.stdin
    )
    out_dir = args.out_facts
    out_dir.mkdir(parents=True, exist_ok=True)

    device_table = load_device_table(args.device_table)
    fact_schema = load_fact_schema()

    accepted = 0
    rejected = 0
    total = 0

    try:
        for line in frames_fh:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                frame = json.loads(line)
            except Exception as e:
                print(f"[WARN] Skip invalid JSON frame: {e}", file=sys.stderr)
                rejected += 1
                continue

            # Expect hdr as object
            hdr = frame.get("hdr")
            if not isinstance(hdr, dict):
                print("[WARN] Missing/invalid hdr", file=sys.stderr)
                rejected += 1
                continue
            dev_id = hdr.get("dev_id")
            fc = hdr.get("fc")
            msg_type = hdr.get("msg_type")
            flags = hdr.get("flags")
            if not (
                    isinstance(dev_id, int)
                    and isinstance(fc, int)
                    and isinstance(msg_type, int)
                    and isinstance(flags, int)
            ):
                print("[WARN] Invalid header fields", file=sys.stderr)
                rejected += 1
                continue

            dev_key = str(dev_id)
            entry = device_table.get(dev_key) or {}
            highest = entry.get("highest_fc_seen")
            if isinstance(highest, str) and highest.isdigit():
                highest = int(highest, 10)
            if not isinstance(highest, int):
                highest = None

            if not accept_frame(fc, highest, args.window):
                rejected += 1
                continue

            # Stub decrypt: decode ct and parse JSON payload
            ct_b64 = frame.get("ct")
            nonce_b64 = frame.get("nonce")
            if not (isinstance(ct_b64, str) and isinstance(nonce_b64, str)):
                print("[WARN] Missing ct/nonce", file=sys.stderr)
                rejected += 1
                continue
            try:
                ct_bytes = base64.b64decode(ct_b64)
                payload = json.loads(ct_bytes.decode("utf-8"))
            except Exception as e:
                print(f"[WARN] Decrypt/parse failed: {e}", file=sys.stderr)
                rejected += 1
                continue

            fact = {
                "device_id": device_label(dev_id),
                "timestamp": now_iso(),
                "nonce": nonce_b64,
                "payload": payload,
            }
            validate_fact(fact, fact_schema)

            out_path = out_dir / f"fact_{accepted:06d}.json"
            out_path.write_text(
                json.dumps(fact, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            # Update device table
            device_table[dev_key] = {
                "highest_fc_seen": fc,
                "last_seen": now_iso(),
                "msg_type": msg_type,
                "flags": flags,
            }

            accepted += 1
    finally:
        if frames_fh is not sys.stdin:
            frames_fh.close()

    save_device_table(args.device_table, device_table)

    # Cross-check accepted count from disk to guard against counter drift
    try:
        accepted_files = len(list(out_dir.glob("*.json")))
    except Exception:
        accepted_files = accepted

    print(
        f"[frame_verifier] total={total} accepted={accepted_files} rejected={rejected} window={args.window}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(process())
