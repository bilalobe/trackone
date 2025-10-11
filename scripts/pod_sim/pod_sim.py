#!/usr/bin/env python3
"""
pod_sim.py

Pod simulator that emits NDJSON facts or framed records to stdout or a file.
This is used for early pipeline testing.
"""
from __future__ import annotations

import argparse
import base64
import json
import random
import secrets
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List

# Constants / knobs for maintainability
DEFAULT_DEVICE_ID = "pod-001"
DEFAULT_COUNT = 10
DEFAULT_SLEEP = 0.0
HDR_STRUCT_FORMAT = ">HBIB"  # big-endian: u16, u8, u32, u8
HDR_MSG_TYPE_MEASUREMENT = 1
NONCE_SIZE = 24
TAG_SIZE = 16
JSON_SEPARATORS = (",", ":")
CT_SORT_KEYS = True


def emit_fact(device_id: str, counter: int) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "counter": counter,
        "bioimpedance": round(random.uniform(50.0, 120.0), 3),
        "temp_c": round(random.uniform(20.0, 40.0), 2),
    }
    return {
        "device_id": device_id,
        "timestamp": now,
        "nonce": f"{counter:016x}",
        "payload": payload,
    }


def parse_dev_id_u16(device_id: str) -> int:
    """Parse a u16 device id from a device_id string like 'pod-001'.
    Falls back to 1 if no trailing number is present. Clamped to [0, 65535]."""
    num = 1
    # extract trailing digits
    i = len(device_id) - 1
    while i >= 0 and device_id[i].isdigit():
        i -= 1
    digits = device_id[i + 1:]
    if digits:
        try:
            num = int(digits, 10)
        except ValueError:
            num = 1
    return max(0, min(65535, num))


def build_header(dev_id_u16: int, msg_type: int, fc_u32: int, flags: int) -> bytes:
    """Build 8-byte header: u16, u8, u32, u8 using big-endian canonical order."""
    # Use > for big-endian. H=uint16, B=uint8, I=uint32, B=uint8
    return struct.pack(
        HDR_STRUCT_FORMAT, dev_id_u16, msg_type & 0xFF, fc_u32 & 0xFFFFFFFF, flags & 0xFF
    )


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def emit_framed(device_id: str, counter: int, payload: dict) -> dict:
    # Header fields
    dev_id_u16 = parse_dev_id_u16(device_id)
    msg_type = HDR_MSG_TYPE_MEASUREMENT  # stub: measurement
    fc_u32 = counter
    flags = 0
    hdr = build_header(dev_id_u16, msg_type, fc_u32, flags)

    # Nonce and tag placeholders
    nonce = secrets.token_bytes(NONCE_SIZE)
    tag = secrets.token_bytes(TAG_SIZE)

    # Ciphertext is just JSON(payload) bytes for M#1 stub
    ct_bytes = json.dumps(payload, separators=JSON_SEPARATORS, sort_keys=CT_SORT_KEYS).encode(
        "utf-8"
    )

    # Emit human-readable header object instead of base64-encoded bytes
    hdr_obj = {"dev_id": dev_id_u16, "msg_type": msg_type, "fc": fc_u32, "flags": flags}

    return {
        "hdr": hdr_obj,
        "nonce": b64(nonce),
        "ct": b64(ct_bytes),
        "tag": b64(tag),
    }


def write_plain_fact(path: Path, counter: int, fact: dict) -> None:
    path.mkdir(parents=True, exist_ok=True)
    out_file = path / f"fact_{counter:06d}.json"
    with out_file.open("w", encoding="utf-8") as fh:
        json.dump(fact, fh, ensure_ascii=False, separators=JSON_SEPARATORS, sort_keys=True)
        fh.write("\n")


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Emit NDJSON facts or framed records for testing"
    )
    p.add_argument("--device-id", default=DEFAULT_DEVICE_ID)
    p.add_argument("--count", type=int, default=DEFAULT_COUNT)
    p.add_argument("--sleep", type=float, default=DEFAULT_SLEEP, help="Seconds between records")
    p.add_argument("--out", type=Path, help="Path to write NDJSON (defaults to stdout)")
    p.add_argument(
        "--framed",
        action="store_true",
        help="Emit framed NDJSON with {hdr, nonce, ct, tag} fields instead of plain facts",
    )
    p.add_argument(
        "--facts-out",
        type=Path,
        help="When --framed is set, also write plain facts to this directory for cross-check",
    )
    args = p.parse_args(argv)

    out_fh = args.out.open("w", encoding="utf-8") if args.out else None
    try:
        for i in range(args.count):
            fact = emit_fact(args.device_id, i)
            if args.framed:
                frame = emit_framed(
                    args.device_id, i, fact["payload"]
                )  # use payload as plaintext
                line = json.dumps(frame, separators=JSON_SEPARATORS)
                if args.facts_out:
                    write_plain_fact(args.facts_out, i, fact)
            else:
                line = json.dumps(fact, separators=JSON_SEPARATORS)
            if out_fh:
                out_fh.write(line + "\n")
            else:
                print(line)
            if args.sleep > 0 and i + 1 < args.count:
                time.sleep(args.sleep)
    finally:
        if out_fh:
            out_fh.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
