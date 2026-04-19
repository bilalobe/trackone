#!/usr/bin/env python3
"""
frame_verifier.py

Parse framed telemetry (NDJSON), call native Rust admission, emit canonical
fact CBOR, and retain structured rejection audit evidence.

Frame envelope (v1, AEAD):
- Header: dev_id(u16), msg_type(u8), fc(u32), flags(u8)
- Nonce: 24 bytes (base64 string)
- Ciphertext: AEAD over postcard-encoded trackone-core Fact plaintext
- Tag: 16 bytes

Transport: NDJSON, one frame per line as JSON with fields {hdr, nonce, ct, tag}.

The public commitment authority is the deterministic canonical CBOR artifact,
not the transport/plaintext encoding or JSON projection.

References:
- ADR-002: Telemetry Framing, Nonce/Replay Policy
- ADR-006: Forward-only schema policy (XChaCha only, no ChaCha/salt4)
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, TextIO

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from trackone_core.constants import (  # noqa: E402
    DEFAULT_INGEST_PROFILE,
    INGEST_PROFILES,
)

try:  # Support both package imports and direct script execution.
    from .canonical_cbor import canonicalize_obj_to_cbor_native
    from .input_integrity import require_sha256_sidecar, write_sha256_sidecar
    from .schema_validation import (
        JSONSCHEMA_AVAILABLE,
        SCHEMA_VALIDATION_EXCEPTIONS,
        load_schema,
        load_schema_from_path,
        schema_validation_available,
        validate_instance,
        validate_instance_if_available,
    )
    from .schema_validation import schema_path as _schema_path
except ImportError:  # pragma: no cover - fallback when run as a script
    from canonical_cbor import canonicalize_obj_to_cbor_native  # type: ignore
    from input_integrity import (  # type: ignore
        require_sha256_sidecar,
        write_sha256_sidecar,
    )
    from schema_validation import (  # type: ignore
        JSONSCHEMA_AVAILABLE,
        SCHEMA_VALIDATION_EXCEPTIONS,
        load_schema,
        load_schema_from_path,
        schema_validation_available,
        validate_instance,
        validate_instance_if_available,
    )
    from schema_validation import schema_path as _schema_path  # type: ignore

# Constants for maintainability
DEFAULT_REPLAY_WINDOW = 64
MAX_FRAME_COUNTER = 2**32 - 1
MAX_NDJSON_LINE_BYTES = 4096
HEADER_FIELDS = {"dev_id", "msg_type", "fc", "flags"}
FRAME_FIELDS = {"hdr", "nonce", "ct", "tag"}

jsonschema: Any | None = None
if JSONSCHEMA_AVAILABLE:  # pragma: no branch - import only when installed
    jsonschema = importlib.import_module("jsonschema")


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


def _is_json_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _load_native_crypto() -> Any:
    try:
        return importlib.import_module("trackone_core.crypto")
    except ImportError as exc:
        raise RuntimeError(
            "trackone_core native crypto helper is required for framed AEAD "
            "verification paths. Build/install the native extension or run via tox."
        ) from exc


def _normalize_ingest_profile(value: str | None) -> str:
    profile = value or DEFAULT_INGEST_PROFILE
    if profile not in INGEST_PROFILES:
        raise ValueError(f"Unsupported ingest profile: {profile!r}")
    return profile


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
    elif not schema_validation_available():
        print(
            "[WARN] jsonschema unavailable; fact schema validation will be skipped.",
            file=sys.stderr,
        )
    return schema


def validate_fact(obj: dict[str, Any], schema: dict[str, Any] | None) -> None:
    """Validate fact against schema if available."""
    if not schema:
        return
    try:
        validate_instance_if_available(obj, schema)
    except SCHEMA_VALIDATION_EXCEPTIONS as e:
        raise ValueError(f"Fact validation failure: {e}") from e


# --- Device table helpers ---


def load_device_table(path: Path) -> dict[str, dict[str, Any]]:
    """Load device table from disk, or return empty dict."""
    if not path or not path.exists():
        return {}
    require_sha256_sidecar(path, label="device_table")
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
            "Expected '1.0'. Provision a Rust postcard device table.",
            file=sys.stderr,
        )
        raise ValueError(f"Unsupported device table version: {version!r}")

    # Optional schema validation (tiny schema)
    if schema_validation_available():
        schema = load_schema("device_table")
        if schema:
            try:
                validate_instance(data, schema)
            except SCHEMA_VALIDATION_EXCEPTIONS as e:
                print(
                    f"[ERROR] Device table schema validation failed: {e}",
                    file=sys.stderr,
                )
                raise
    elif load_schema("device_table") is not None:
        print(
            "[WARN] jsonschema unavailable; device_table schema validation will be skipped.",
            file=sys.stderr,
        )

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
    write_sha256_sidecar(path)


def parse_frame(line: str) -> tuple[dict[str, Any] | None, str]:
    """
    Parse a single NDJSON frame line.

    Returns:
        (frame_dict | None, error_message)
    """
    line_bytes = len(line.rstrip("\r\n").encode("utf-8"))
    if line_bytes > MAX_NDJSON_LINE_BYTES:
        return None, "line_too_long"

    try:
        frame = json.loads(line)
    except json.JSONDecodeError:
        return None, "invalid_json"

    # Validate frame structure
    if not isinstance(frame, dict):
        return None, "not_dict"

    frame_keys = set(frame.keys())
    if not FRAME_FIELDS.issubset(frame_keys):
        return None, "missing_frame_fields"
    if frame_keys != FRAME_FIELDS:
        return None, "unexpected_frame_fields"

    hdr = frame["hdr"]
    if not isinstance(hdr, dict):
        return None, "invalid_hdr"

    if (
        not isinstance(frame["nonce"], str)
        or not isinstance(frame["ct"], str)
        or not isinstance(frame["tag"], str)
    ):
        return None, "invalid_frame_types"

    # Check required header fields
    hdr_keys = set(hdr.keys())
    if not HEADER_FIELDS.issubset(hdr_keys):
        return None, "missing_hdr_fields"
    if hdr_keys != HEADER_FIELDS:
        return None, "unexpected_hdr_fields"

    # Validate field types
    if not all(
        _is_json_int(hdr[name]) for name in ("dev_id", "msg_type", "fc", "flags")
    ):
        return None, "invalid_hdr_types"
    dev_id = hdr["dev_id"]
    msg_type = hdr["msg_type"]
    fc = hdr["fc"]
    flags = hdr["flags"]

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


def _validate_and_decrypt_framed(
    frame: dict[str, Any],
    device_table: dict[str, dict[str, Any]],
    *,
    ingest_profile: str = DEFAULT_INGEST_PROFILE,
) -> tuple[dict[str, Any] | None, str]:
    _normalize_ingest_profile(ingest_profile)

    if "ct" not in frame or "nonce" not in frame or "hdr" not in frame:
        return None, "missing_frame_fields"

    hdr = frame["hdr"]
    if not isinstance(hdr, dict):
        return None, "invalid_hdr"

    try:
        dev_id_u16 = int(hdr["dev_id"])
    except (ValueError, TypeError):
        return None, "invalid_hdr_types"
    if not (0 <= dev_id_u16 <= 65535):
        return None, "dev_id_range"

    dev_entry = device_table.get(str(dev_id_u16))
    if not dev_entry:
        return None, "unknown_device"

    try:
        native_crypto = _load_native_crypto()
        payload, reason = native_crypto.validate_and_decrypt_framed(
            frame,
            dev_entry,
            ingest_profile=ingest_profile,
        )
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(
            "trackone_core native crypto helper failed during framed verification"
        ) from exc

    if payload is None:
        return None, reason or "decrypt_failed"
    if not isinstance(payload, dict):
        return None, "decrypt_failed"
    return payload, ""


def aead_decrypt(
    frame: dict[str, Any],
    device_table: dict[str, dict[str, Any]],
    ingest_profile: str = DEFAULT_INGEST_PROFILE,
) -> dict[str, Any] | None:
    """
    Decrypt a framed payload under the selected ingest profile.

    Returns:
        payload dict or None on failure
    """
    try:
        payload, _reason = _validate_and_decrypt_framed(
            frame,
            device_table,
            ingest_profile=ingest_profile,
        )
    except RuntimeError:
        return None
    return payload


def _native_replay_state(
    native_crypto: Any,
    device_table_entry: dict[str, Any],
    *,
    window_size: int,
) -> Any:
    highest_raw = device_table_entry.get("highest_fc_seen", -1)
    highest_fc_seen: int | None = None
    if (
        not isinstance(highest_raw, bool)
        and isinstance(highest_raw, int)
        and highest_raw >= 0
    ):
        highest_fc_seen = highest_raw
    return native_crypto.ReplayWindowState(
        window_size=window_size,
        highest_fc_seen=highest_fc_seen,
    )


def _admit_framed_fact(
    frame: dict[str, Any],
    device_table: dict[str, dict[str, Any]],
    replay_states: dict[str, Any],
    *,
    window_size: int,
    ingest_time: int,
    ingest_time_rfc3339_utc: str,
    ingest_profile: str = DEFAULT_INGEST_PROFILE,
) -> tuple[dict[str, Any] | None, str, str]:
    ingest_profile = _normalize_ingest_profile(ingest_profile)
    if ingest_profile != DEFAULT_INGEST_PROFILE:
        return None, "invalid_ingest_profile", "decrypt"

    hdr = frame.get("hdr")
    if not isinstance(hdr, dict):
        return None, "invalid_hdr", "decrypt"

    try:
        dev_id_u16 = int(hdr["dev_id"])
    except (ValueError, TypeError):
        return None, "invalid_hdr_types", "decrypt"
    if not (0 <= dev_id_u16 <= 65535):
        return None, "dev_id_range", "decrypt"

    dev_entry = device_table.get(str(dev_id_u16))
    if dev_entry is None:
        return None, "unknown_device", "decrypt"

    native_crypto = _load_native_crypto()
    state = replay_states.get(str(dev_id_u16))
    if state is None:
        state = _native_replay_state(native_crypto, dev_entry, window_size=window_size)
        replay_states[str(dev_id_u16)] = state

    try:
        fact, reason, source = native_crypto.admit_framed_fact(
            frame,
            dev_entry,
            state,
            ingest_time=ingest_time,
            ingest_time_rfc3339_utc=ingest_time_rfc3339_utc,
            ingest_profile=ingest_profile,
        )
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(
            "trackone_core native crypto helper failed during authoritative "
            "framed admission"
        ) from exc

    if fact is None:
        return None, reason or "decrypt_failed", source or "decrypt"
    if not isinstance(fact, dict):
        raise RuntimeError(
            "trackone_core native crypto helper returned a non-dict fact"
        )
    return fact, "", ""


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
        help="Output directory for authoritative fact CBOR files and JSON projections",
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
    p.add_argument(
        "--ingest-profile",
        choices=INGEST_PROFILES,
        default=DEFAULT_INGEST_PROFILE,
        help=(
            "Framed plaintext/profile contract. The supported path is "
            "rust-postcard-v1: native Rust postcard Fact admission followed by "
            "deterministic canonical CBOR commitment."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse, replay-check, decrypt, and validate without writing facts, audit logs, or device-table updates",
    )

    args = p.parse_args(argv)

    # Open input (file or stdin)
    frames_fh = (
        args.input_file.open("r", encoding="utf-8") if args.input_file else sys.stdin
    )
    device_table_existed = args.device_table.exists()

    if not args.dry_run:
        args.out_facts.mkdir(parents=True, exist_ok=True)

    audit_fh: TextIO | None = None
    if not args.dry_run:
        audit_dir = (
            args.out_audit
            if args.out_audit is not None
            else args.out_facts.parent / "audit"
        )
        audit_path = audit_dir / f"rejections-{_audit_day_label()}.ndjson"
        try:
            audit_dir.mkdir(parents=True, exist_ok=True)
            audit_fh = audit_path.open("a", encoding="utf-8")
        except OSError as e:
            if frames_fh is not sys.stdin:
                frames_fh.close()
            print(f"[ERROR] processing failure: {e}", file=sys.stderr)
            return 1

    try:
        # Load device table and schema
        device_table = load_device_table(args.device_table)
        fact_schema = load_fact_schema()
        replay_states: dict[str, Any] = {}

        # Process frames
        total = 0
        accepted = 0
        rejected = 0

        for _line_num, raw_line in enumerate(frames_fh, start=1):
            line = raw_line.rstrip("\r\n")
            if not line.strip():
                continue

            total += 1

            # Parse frame
            frame, err = parse_frame(line)
            if frame is None:
                rejected += 1
                print(f"[WARN] {err}", file=sys.stderr)
                if audit_fh is not None:
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
            dev_key = str(hdr["dev_id"])
            fc = hdr["fc"]
            frame_now = datetime.now(UTC)
            ingest_time = int(frame_now.timestamp())
            ingest_time_rfc3339 = (
                frame_now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
            )

            try:
                fact, reason, source = _admit_framed_fact(
                    frame,
                    device_table,
                    replay_states,
                    window_size=args.window,
                    ingest_time=ingest_time,
                    ingest_time_rfc3339_utc=ingest_time_rfc3339,
                    ingest_profile=args.ingest_profile,
                )
            except RuntimeError as exc:
                print(f"[ERROR] {exc}", file=sys.stderr)
                return 1

            if fact is None:
                rejected += 1
                print(
                    f"[WARN] Rejected {dev_id_str} fc={fc}: {reason}",
                    file=sys.stderr,
                )
                if audit_fh is not None:
                    _emit_rejection(
                        audit_fh,
                        RejectionRecord(
                            device_id=dev_id_str,
                            fc=fc,
                            reason=reason,
                            observed_at_utc=datetime.now(UTC).isoformat(),
                            frame_sha256=_hash_rejected_line(raw_line),
                            source=source,
                        ),
                    )
                continue

            # Validate against schema
            validate_fact(fact, fact_schema)

            # Write authoritative CBOR fact + JSON projection.
            if not args.dry_run:
                fact_file_stem = args.out_facts / f"{dev_id_str}-{fc:08d}"
                fact_file_cbor = fact_file_stem.with_suffix(".cbor")
                fact_file_json = fact_file_stem.with_suffix(".json")
                fact_file_cbor.write_bytes(canonicalize_obj_to_cbor_native(fact))
                with fact_file_json.open("w", encoding="utf-8") as out_fh:
                    json.dump(fact, out_fh, indent=2, sort_keys=True)

                # Update device table for persistence (non-secret runtime state)
                entry = device_table.get(dev_key, {})
                state = replay_states.get(dev_key)
                highest_fc_seen = getattr(state, "highest_fc_seen", None)
                entry["highest_fc_seen"] = (
                    int(highest_fc_seen)
                    if isinstance(highest_fc_seen, int)
                    else max(int(entry.get("highest_fc_seen", -1)), fc)
                )
                entry["last_seen"] = frame_now.isoformat()
                entry["msg_type"] = hdr["msg_type"]
                entry["flags"] = hdr["flags"]
                device_table[dev_key] = entry

            accepted += 1

        # Avoid creating a brand-new empty device table when nothing was accepted.
        if not args.dry_run and (device_table or device_table_existed):
            save_device_table(args.device_table, device_table)

        # Cross-check accepted count from disk to guard against counter drift
        if args.dry_run:
            accepted_files = accepted
        else:
            try:
                accepted_files = len(list(args.out_facts.glob("*.cbor")))
            except OSError:
                accepted_files = accepted

        print(
            f"[frame_verifier] total={total} accepted={accepted_files} rejected={rejected} "
            f"window={args.window} ingest_profile={args.ingest_profile}"
        )
        return 0

    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user", file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError, ValueError, TypeError, RuntimeError) as e:
        print(f"[ERROR] processing failure: {e}", file=sys.stderr)
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
