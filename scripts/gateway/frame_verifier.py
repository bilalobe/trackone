#!/usr/bin/env python3
"""
frame_verifier.py

Parse framed telemetry (NDJSON), enforce replay window, stub-decrypt, and emit canonical facts.

For M#1, this implements basic frame parsing and replay protection with stubbed decryption.
Real AEAD (XChaCha20-Poly1305) will be added in M#2.

Frame format (v1, stubbed):
- Header: dev_id(u16), msg_type(u8), fc(u32), flags(u8)
- Nonce: 24 bytes (base64/hex string for now)
- Ciphertext: json.dumps(payload) bytes (plaintext for now)
- Tag: 16 bytes (placeholder)

Transport: NDJSON, one frame per line as JSON with fields {hdr, nonce, ct, tag}.

References:
- ADR-002: Telemetry Framing, Nonce/Replay Policy
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Set, Any

# Constants for maintainability
DEFAULT_REPLAY_WINDOW = 64
MAX_FRAME_COUNTER = 2 ** 32 - 1
HEADER_FIELDS = {"dev_id", "msg_type", "fc", "flags"}

try:
    import jsonschema

    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False


class ReplayWindow:
    """
    Tracks frame counters per device to enforce replay protection.

    Uses a sliding window approach: accept frames within window_size of highest fc seen.
    Rejects duplicates and frames too far behind.
    """

    def __init__(self, window_size: int = DEFAULT_REPLAY_WINDOW):
        self.window_size = window_size
        self.highest_fc: Dict[str, int] = {}
        self.seen: Dict[str, Set[int]] = {}

    def check_and_update(self, dev_id: str, fc: int) -> tuple[bool, str]:
        """
        Check if frame counter is acceptable and update state.

        Returns:
            (accepted: bool, reason: str)
        """
        if dev_id not in self.highest_fc:
            # First frame from this device
            self.highest_fc[dev_id] = fc
            self.seen[dev_id] = {fc}
            return True, "first"

        highest = self.highest_fc[dev_id]
        seen_set = self.seen[dev_id]

        # Check for duplicate
        if fc in seen_set:
            return False, "duplicate"

        # Check if too old (outside window behind)
        if fc < highest and (highest - fc) > self.window_size:
            return False, "out_of_window"

        # Check if too far ahead (outside window forward)
        if fc > highest and (fc - highest) > self.window_size:
            return False, "out_of_window"

        # Accept and update
        if fc > highest:
            self.highest_fc[dev_id] = fc
            # Prune old entries from seen set
            seen_set = {f for f in seen_set if (fc - f) <= self.window_size}
            seen_set.add(fc)
            self.seen[dev_id] = seen_set
        else:
            seen_set.add(fc)

        return True, "ok"


def load_fact_schema() -> dict | None:
    """Load fact.schema.json for optional validation."""
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
    """Validate fact against schema if available."""
    if not (schema and JSONSCHEMA_AVAILABLE):
        return
    try:
        jsonschema.validate(instance=obj, schema=schema)
    except Exception as e:
        print(f"[WARN] Fact validation: {e}", file=sys.stderr)


def load_device_table(path: Path) -> Dict[str, Dict[str, Any]]:
    """Load device table from disk, or return empty dict."""
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_device_table(path: Path, tbl: dict) -> None:
    """Persist device table to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(tbl, indent=2) + "\n", encoding="utf-8")


def parse_frame(line: str) -> tuple[dict | None, str]:
    """
    Parse a single NDJSON frame line.

    Returns:
        (frame_dict | None, error_message)
    """
    try:
        frame = json.loads(line)
    except json.JSONDecodeError:
        return None, "invalid_json"

    # Validate frame structure
    if not isinstance(frame, dict):
        return None, "not_dict"

    if "hdr" not in frame:
        return None, "missing_hdr"

    hdr = frame["hdr"]
    if not isinstance(hdr, dict):
        return None, "invalid_hdr"

    # Check required header fields
    if not HEADER_FIELDS.issubset(hdr.keys()):
        return None, "missing_hdr_fields"

    # Validate field types
    try:
        dev_id = int(hdr["dev_id"])
        msg_type = int(hdr["msg_type"])
        fc = int(hdr["fc"])
        flags = int(hdr["flags"])
    except (ValueError, TypeError):
        return None, "invalid_hdr_types"

    # Validate ranges
    if not (0 <= dev_id <= 65535):
        return None, "dev_id_range"
    if not (0 <= msg_type <= 255):
        return None, "msg_type_range"
    if not (0 <= fc <= MAX_FRAME_COUNTER):
        return None, "fc_range"
    if not (0 <= flags <= 255):
        return None, "flags_range"

    return frame, ""


def stub_decrypt(frame: dict) -> dict | None:
    """
    Stub decryption for M#1.

    For now, assumes ciphertext is base64-encoded JSON payload.
    Real AEAD will be implemented in M#2.

    Returns:
        payload dict or None on failure
    """
    try:
        if "ct" not in frame:
            return None

        ct_b64 = frame["ct"]
        ct_bytes = base64.b64decode(ct_b64)
        payload = json.loads(ct_bytes.decode("utf-8"))
        return payload
    except Exception:
        return None


def frame_to_fact(frame: dict, payload: dict) -> dict:
    """
    Convert verified frame + decrypted payload to canonical fact.

    Returns:
        fact dict matching fact.schema.json
    """
    hdr = frame["hdr"]
    dev_id_str = f"pod-{hdr['dev_id']:03d}"

    return {
        "device_id": dev_id_str,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nonce": frame.get("nonce", ""),
        "payload": payload,
    }


def process(argv=None) -> int:
    """
    Main processing function.

    Reads frames from --in, enforces replay window, stub-decrypts,
    and writes canonical facts to --out-facts directory.

    Returns:
        0 on success, 1 on error
    """
    p = argparse.ArgumentParser(
        description="Parse framed telemetry and emit canonical facts (M#1 stub)"
    )
    p.add_argument(
        "--in",
        dest="input_file",
        type=Path,
        help="Input NDJSON file with framed records (or stdin if omitted)",
    )
    p.add_argument(
        "--out-facts",
        dest="out_facts",
        type=Path,
        required=True,
        help="Output directory for canonical fact JSON files",
    )
    p.add_argument(
        "--device-table",
        dest="device_table",
        type=Path,
        required=True,
        help="Device table JSON (for key lookup in M#2, persisted state)",
    )
    p.add_argument(
        "--window",
        type=int,
        default=DEFAULT_REPLAY_WINDOW,
        help=f"Replay window size (default: {DEFAULT_REPLAY_WINDOW})",
    )

    args = p.parse_args(argv)

    # Open input (file or stdin)
    frames_fh = (
        args.input_file.open("r", encoding="utf-8")
        if args.input_file
        else sys.stdin
    )

    # Create output directory
    args.out_facts.mkdir(parents=True, exist_ok=True)

    # Load device table and schema
    device_table = load_device_table(args.device_table)
    fact_schema = load_fact_schema()

    # Initialize replay window
    replay = ReplayWindow(window_size=args.window)

    # Process frames
    total = 0
    accepted = 0
    rejected = 0

    try:
        for line_num, line in enumerate(frames_fh, start=1):
            line = line.strip()
            if not line:
                continue

            total += 1

            # Parse frame
            frame, err = parse_frame(line)
            if frame is None:
                rejected += 1
                print(f"[WARN] {err}", file=sys.stderr)
                continue

            hdr = frame["hdr"]
            dev_id_str = f"pod-{hdr['dev_id']:03d}"
            fc = hdr["fc"]

            # Check replay window
            ok, reason = replay.check_and_update(dev_id_str, fc)
            if not ok:
                rejected += 1
                print(
                    f"[WARN] Rejected {dev_id_str} fc={fc}: {reason}", file=sys.stderr
                )
                continue

            # Stub decrypt
            payload = stub_decrypt(frame)
            if payload is None:
                rejected += 1
                print(
                    f"[WARN] Decrypt failed for {dev_id_str} fc={fc}", file=sys.stderr
                )
                continue

            # Convert to fact
            fact = frame_to_fact(frame, payload)

            # Validate against schema
            validate_fact(fact, fact_schema)

            # Write fact file
            fact_file = args.out_facts / f"{dev_id_str}-{fc:08d}.json"
            with fact_file.open("w", encoding="utf-8") as out_fh:
                json.dump(fact, out_fh, indent=2, sort_keys=True)

            # Update device table for persistence
            dev_key = str(hdr["dev_id"])
            device_table[dev_key] = {
                "highest_fc_seen": fc,
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "msg_type": hdr["msg_type"],
                "flags": hdr["flags"],
            }

            accepted += 1

    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}", file=sys.stderr)
        return 1
    finally:
        if frames_fh is not sys.stdin:
            frames_fh.close()

    # Save device table
    save_device_table(args.device_table, device_table)

    # Cross-check accepted count from disk to guard against counter drift
    try:
        accepted_files = len(list(args.out_facts.glob("*.json")))
    except Exception:
        accepted_files = accepted

    print(
        f"[frame_verifier] total={total} accepted={accepted_files} rejected={rejected} window={args.window}"
    )
    return 0


def main(argv=None) -> int:
    """CLI entry point."""
    return process(argv)


if __name__ == "__main__":
    raise SystemExit(main())
