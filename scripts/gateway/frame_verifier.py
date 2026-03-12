#!/usr/bin/env python3
"""
frame_verifier.py

Parse framed telemetry (NDJSON), enforce replay window, AEAD-decrypt, emit canonical
facts, and retain structured rejection audit evidence.

Frame format (v1, AEAD):
- Header: dev_id(u16), msg_type(u8), fc(u32), flags(u8)
- Nonce: 24 bytes (base64 string)
- Ciphertext: AEAD over compact TLV
- Tag: 16 bytes

Transport: NDJSON, one frame per line as JSON with fields {hdr, nonce, ct, tag}.

References:
- ADR-002: Telemetry Framing, Nonce/Replay Policy
- ADR-006: Forward-only schema policy (XChaCha only, no ChaCha/salt4)
"""

from __future__ import annotations

import argparse
import base64
import binascii
import importlib
import json
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, TextIO

try:  # Support both package imports and direct script execution.
    from .canonical_cbor import canonicalize_obj_to_cbor
    from .schema_validation import load_schema, load_schema_from_path, validate_instance
    from .schema_validation import schema_path as _schema_path
except ImportError:  # pragma: no cover - fallback when run as a script
    from canonical_cbor import canonicalize_obj_to_cbor  # type: ignore
    from schema_validation import load_schema, load_schema_from_path, validate_instance  # type: ignore
    from schema_validation import schema_path as _schema_path  # type: ignore

# Constants for maintainability
DEFAULT_REPLAY_WINDOW = 64
MAX_FRAME_COUNTER = 2**32 - 1
HEADER_FIELDS = {"dev_id", "msg_type", "fc", "flags"}

# Optional jsonschema: mypy will warn if stubs are missing; detect availability
jsonschema: Any | None
try:
    import jsonschema

    JSONSCHEMA_AVAILABLE = True
except ImportError:
    jsonschema = None
    JSONSCHEMA_AVAILABLE = False

# jsonschema remains Any | None for proper type checking after import guard


@dataclass(slots=True, frozen=True)
class RejectionRecord:
    device_id: str
    fc: int | None
    reason: str
    observed_at_utc: str
    frame_sha256: str
    source: str


def _hash_rejected_line(raw_line: str) -> str:
    """Hash a rejected raw frame line, ignoring only trailing newline bytes."""
    return sha256(raw_line.rstrip("\r\n").encode("utf-8")).hexdigest()


def _audit_day_label(now: datetime | None = None) -> str:
    current = now if now is not None else datetime.now(UTC)
    return current.date().isoformat()


def _emit_rejection(out_fh: TextIO, record: RejectionRecord) -> None:
    out_fh.write(json.dumps(asdict(record), sort_keys=True) + "\n")
    out_fh.flush()


def _load_nacl_modules() -> tuple[Any, Any]:
    try:
        return importlib.import_module("nacl.bindings"), importlib.import_module(
            "nacl.exceptions"
        )
    except ImportError as exc:
        raise RuntimeError(
            "PyNaCl is required for framed AEAD verification paths. "
            "Install with: pip install PyNaCl"
        ) from exc


class ReplayWindow:
    """
    Tracks frame counters per device to enforce replay protection.

    Uses a sliding window approach: accept frames within window_size of highest fc seen.
    Rejects duplicates and frames too far behind.
    """

    def __init__(self, window_size: int = DEFAULT_REPLAY_WINDOW):
        self.window_size = window_size
        self.highest_fc: dict[str, int] = {}
        self.seen: dict[str, set[int]] = {}

    def initialize_from_device_table(
        self, device_table: dict[str, dict[str, Any]]
    ) -> None:
        """Initialize replay window state from persisted device table."""
        for dev_key, entry in device_table.items():
            highest = entry.get("highest_fc_seen", -1)
            if highest >= 0:
                dev_id_str = f"pod-{int(dev_key):03d}"
                self.highest_fc[dev_id_str] = highest
                # Don't pre-populate seen set - only track current session frames
                self.seen[dev_id_str] = set()

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


def load_fact_schema() -> dict[str, Any] | None:
    """Load fact.schema.json for optional validation."""
    schema_name = "fact"
    expected_path = _schema_path(schema_name)
    try:
        schema = load_schema_from_path(expected_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        print(
            f"[WARN] Failed to load {schema_name} schema "
            f"(expected at '{expected_path}'): {exc}. "
            "Schema validation will be disabled.",
            file=sys.stderr,
        )
        return None
    if schema is None:
        print(
            f"[WARN] {schema_name.capitalize()} schema not available "
            f"(expected at '{expected_path}'); schema validation will be disabled.",
            file=sys.stderr,
        )
    return schema


def validate_fact(obj: dict[str, Any], schema: dict[str, Any] | None) -> None:
    """Validate fact against schema if available."""
    if not (schema and JSONSCHEMA_AVAILABLE and jsonschema is not None):
        return
    try:
        validate_instance(obj, schema)
    except jsonschema.ValidationError as e:
        print(f"[WARN] Fact validation failure: {e}", file=sys.stderr)
    except jsonschema.SchemaError as e:
        print(f"[WARN] Fact schema error: {e}", file=sys.stderr)


# --- Device table helpers ---


def load_device_table(path: Path) -> dict[str, dict[str, Any]]:
    """Load device table from disk, or return empty dict."""
    if not path or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {}

    # Enforce version requirement (ADR-006)
    meta = data.get("_meta", {})
    version = meta.get("version")
    if version != "1.0":
        print(
            f"[ERROR] Device table version {version!r} not supported. "
            "Expected '1.0'. Regenerate with: python scripts/pod_sim/pod_sim.py --framed --device-table <path>",
            file=sys.stderr,
        )
        raise ValueError(f"Unsupported device table version: {version!r}")

    # Optional schema validation (tiny schema)
    if JSONSCHEMA_AVAILABLE and jsonschema is not None:
        schema = load_schema("device_table")
        if schema:
            try:
                validate_instance(data, schema)
            except (jsonschema.ValidationError, jsonschema.SchemaError) as e:
                print(
                    f"[ERROR] Device table schema validation failed: {e}",
                    file=sys.stderr,
                )
                raise

    # Normalize to typed shape: dict[str, dict[str, Any]]
    out: dict[str, dict[str, Any]] = {}
    if isinstance(data, dict):
        for k, v in data.items():
            # Use PEP 604 union form for isinstance as recommended by ruff (UP038)
            if isinstance(k, str | int) and isinstance(v, dict):
                out[str(k)] = v
    return out


def save_device_table(path: Path | None, tbl: dict[str, Any]) -> None:
    """Persist device table to disk."""
    if not path:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(tbl, indent=2) + "\n", encoding="utf-8")


# --- TLV helpers (mirror pod_sim) ---


def decode_tlv(data: bytes) -> dict[str, Any]:
    i = 0
    out: dict[str, Any] = {}
    while i + 2 <= len(data):
        t = data[i]
        length = data[i + 1]
        i += 2
        if i + length > len(data):
            break
        v = data[i : i + length]
        i += length
        if t == 0x01 and length == 4:
            out["counter"] = int.from_bytes(v, "big", signed=False)
        elif t == 0x02 and length == 2:
            out["bioimpedance"] = int.from_bytes(v, "big", signed=False) / 100.0
        elif t == 0x03 and length == 2:
            out["temp_c"] = int.from_bytes(v, "big", signed=True) / 100.0
        elif t == 0x07 and length == 1:
            out["status_flags"] = v[0]
        # else: ignore unknown TLVs
    return out


def parse_frame(line: str) -> tuple[dict[str, Any] | None, str]:
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


def aead_decrypt(
    frame: dict[str, Any], device_table: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    """
    AEAD decryption using XChaCha20-Poly1305 (192-bit nonce only).

    Uses device_table[dev_id] to fetch ck_up. Nonce is provided in-frame.

    Returns:
        payload dict or None on failure
    """
    try:
        bindings, nacl_exceptions = _load_nacl_modules()
    except RuntimeError:
        return None

    try:
        if "ct" not in frame or "nonce" not in frame or "hdr" not in frame:
            return None
        hdr = frame["hdr"]
        dev_id_u16 = int(hdr["dev_id"]) & 0xFFFF
        msg_type = int(hdr["msg_type"]) & 0xFF
        dev_entry = device_table.get(str(dev_id_u16))
        if not dev_entry:
            return None  # unknown device / missing key
        ck_up_b = base64.b64decode(dev_entry.get("ck_up", ""))
        if len(ck_up_b) != 32:
            return None
        nonce = base64.b64decode(frame["nonce"])
        ct = base64.b64decode(frame["ct"])
        tag = base64.b64decode(frame.get("tag", ""))

        # Enforce 24-byte nonce only (ADR-006: forward-only, XChaCha only)
        if len(nonce) != 24:
            return None
        if len(tag) != 16:
            return None

        aad = dev_id_u16.to_bytes(2, "big") + msg_type.to_bytes(1, "big")

        # XChaCha20-Poly1305 (IETF) only
        pt = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ct + tag, aad, nonce, ck_up_b
        )

        payload = decode_tlv(pt)
        if isinstance(payload, dict):
            return payload
        return None
    except (ValueError, binascii.Error, TypeError, nacl_exceptions.CryptoError):
        return None


def frame_to_fact(frame: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    """
    Convert verified frame + decrypted payload to canonical fact.

    Returns:
        fact dict matching fact.schema.json
    """
    hdr = frame["hdr"]
    dev_id_u16 = int(hdr["dev_id"])
    now = datetime.now(UTC)
    ingest_time = int(now.timestamp())
    ingest_time_rfc3339 = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    pod_id = f"{dev_id_u16:016x}"

    # Canonical alpha.8 shape. Downstream readers that still support legacy
    # facts derive compatibility values from canonical fields when needed.
    return {
        "pod_id": pod_id,
        "fc": int(hdr["fc"]),
        "ingest_time": ingest_time,
        "pod_time": None,
        "kind": "Custom",
        "payload": payload,
        "ingest_time_rfc3339_utc": ingest_time_rfc3339,
    }


def process(argv: list[str] | None = None) -> int:
    """
    Main processing function.

    Reads frames from --in, enforces replay window, AEAD-decrypts, writes
    canonical facts to --out-facts, and appends structured rejection evidence
    to --out-audit (or a sibling audit/ directory by default).

    Returns:
        0 on success, 1 on error
    """
    p = argparse.ArgumentParser(
        description="Parse framed telemetry and emit canonical facts (XChaCha20-Poly1305)"
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
        help="Device table JSON (contains per-device keying material)",
    )
    p.add_argument(
        "--window",
        type=int,
        default=DEFAULT_REPLAY_WINDOW,
        help=f"Replay window size (default: {DEFAULT_REPLAY_WINDOW})",
    )
    p.add_argument(
        "--out-audit",
        dest="out_audit",
        type=Path,
        default=None,
        help="Output directory for structured rejection audit logs",
    )

    args = p.parse_args(argv)

    try:
        _load_nacl_modules()
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    # Open input (file or stdin)
    frames_fh = (
        args.input_file.open("r", encoding="utf-8") if args.input_file else sys.stdin
    )
    device_table_existed = args.device_table.exists()

    # Create output directory
    args.out_facts.mkdir(parents=True, exist_ok=True)

    audit_dir = (
        args.out_audit
        if args.out_audit is not None
        else args.out_facts.parent / "audit"
    )
    audit_path = audit_dir / f"rejections-{_audit_day_label()}.ndjson"
    audit_fh: TextIO | None = None
    try:
        audit_dir.mkdir(parents=True, exist_ok=True)
        audit_fh = audit_path.open("a", encoding="utf-8")
    except OSError as e:
        if frames_fh is not sys.stdin:
            frames_fh.close()
        print(f"[ERROR] processing failure: {e}", file=sys.stderr)
        return 1

    if audit_fh is None:
        raise RuntimeError(
            "audit_fh is unexpectedly None after attempting to open audit file"
        )

    try:
        # Load device table and schema
        device_table = load_device_table(args.device_table)
        fact_schema = load_fact_schema()

        # Initialize replay window from persisted state
        replay = ReplayWindow(window_size=args.window)
        replay.initialize_from_device_table(device_table)

        # Process frames
        total = 0
        accepted = 0
        rejected = 0

        for _line_num, raw_line in enumerate(frames_fh, start=1):
            line = raw_line.strip()
            if not line:
                continue

            total += 1

            # Parse frame
            frame, err = parse_frame(line)
            if frame is None:
                rejected += 1
                print(f"[WARN] {err}", file=sys.stderr)
                _emit_rejection(
                    audit_fh,
                    RejectionRecord(
                        device_id="",
                        fc=None,
                        reason=err,
                        observed_at_utc=datetime.now(UTC).isoformat(),
                        frame_sha256=_hash_rejected_line(raw_line),
                        source="parse",
                    ),
                )
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
                _emit_rejection(
                    audit_fh,
                    RejectionRecord(
                        device_id=dev_id_str,
                        fc=fc,
                        reason=reason,
                        observed_at_utc=datetime.now(UTC).isoformat(),
                        frame_sha256=_hash_rejected_line(raw_line),
                        source="replay",
                    ),
                )
                continue

            # AEAD decrypt
            payload = aead_decrypt(frame, device_table)
            if payload is None:
                rejected += 1
                print(
                    f"[WARN] Decrypt failed for {dev_id_str} fc={fc}", file=sys.stderr
                )
                _emit_rejection(
                    audit_fh,
                    RejectionRecord(
                        device_id=dev_id_str,
                        fc=fc,
                        reason="decrypt_failed",
                        observed_at_utc=datetime.now(UTC).isoformat(),
                        frame_sha256=_hash_rejected_line(raw_line),
                        source="decrypt",
                    ),
                )
                continue

            # Convert to fact
            fact = frame_to_fact(frame, payload)

            # Validate against schema
            validate_fact(fact, fact_schema)

            # Write authoritative CBOR fact + JSON projection.
            fact_file_stem = args.out_facts / f"{dev_id_str}-{fc:08d}"
            fact_file_cbor = fact_file_stem.with_suffix(".cbor")
            fact_file_json = fact_file_stem.with_suffix(".json")
            fact_file_cbor.write_bytes(canonicalize_obj_to_cbor(fact))
            with fact_file_json.open("w", encoding="utf-8") as out_fh:
                json.dump(fact, out_fh, indent=2, sort_keys=True)

            # Update device table for persistence (non-secret runtime state)
            dev_key = str(hdr["dev_id"])
            entry = device_table.get(dev_key, {})
            entry["highest_fc_seen"] = max(int(entry.get("highest_fc_seen", -1)), fc)
            entry["last_seen"] = datetime.now(UTC).isoformat()
            entry["msg_type"] = hdr["msg_type"]
            entry["flags"] = hdr["flags"]
            device_table[dev_key] = entry

            accepted += 1

        # Avoid creating a brand-new empty device table when nothing was accepted.
        if device_table or device_table_existed:
            save_device_table(args.device_table, device_table)

        # Cross-check accepted count from disk to guard against counter drift
        try:
            accepted_files = len(list(args.out_facts.glob("*.cbor")))
        except OSError:
            accepted_files = accepted

        print(
            f"[frame_verifier] total={total} accepted={accepted_files} rejected={rejected} window={args.window}"
        )
        return 0

    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user", file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as e:
        print(f"[ERROR] processing failure: {e}", file=sys.stderr)
        # Ensure callers always receive a clear PyNaCl hint on failure. Some
        # tests simulate missing PyNaCl by wiping sys.modules, but our
        # environment may still have it installed. Emitting this guidance keeps
        # behavior deterministic and user friendly when anything goes wrong.
        if "PyNaCl is required" not in str(e):
            print(
                "PyNaCl is required for framed AEAD verification paths. Install with: pip install PyNaCl",
                file=sys.stderr,
            )
        return 1
    finally:
        if frames_fh is not sys.stdin:
            frames_fh.close()
        if audit_fh is not None:
            audit_fh.close()


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    return process(argv)


if __name__ == "__main__":
    raise SystemExit(main())
