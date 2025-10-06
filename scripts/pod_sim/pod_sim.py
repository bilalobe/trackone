#!/usr/bin/env python3
"""
pod_sim.py

Minimal pod simulator that emits NDJSON facts to stdout or a file. This is a placeholder used
for early pipeline testing.
"""
from __future__ import annotations

import argparse
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List


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


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Emit NDJSON facts for testing")
    p.add_argument("--device-id", default="pod-001")
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--sleep", type=float, default=0.0, help="Seconds between facts")
    p.add_argument("--out", type=Path, help="Path to write NDJSON (defaults to stdout)")
    args = p.parse_args(argv)

    out_fh = args.out.open("w", encoding="utf-8") if args.out else None
    try:
        for i in range(args.count):
            fact = emit_fact(args.device_id, i)
            line = json.dumps(fact, separators=(',', ':'))
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
