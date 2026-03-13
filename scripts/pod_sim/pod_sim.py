#!/usr/bin/env python3
"""
pod_sim.py

Pod simulator that emits NDJSON facts or framed records for testing.

This simulator supports two modes:

1. **Plain mode** (M#0): Emits canonical fact JSON (`pod_id`, `fc`, `ingest_time`, `kind`, `payload`)
   Usage: python pod_sim.py --device-id pod-001 --count 10

2. **Framed mode** (M#2/Production): Emits NDJSON frames with {hdr, nonce, ct, tag} fields using AEAD (XChaCha20-Poly1305)
   Usage: python pod_sim.py --framed --device-id pod-003 --count 10 --out frames.ndjson --device-table device_table.json

Frame structure (AEAD):
- hdr: dict with {dev_id: u16, msg_type: u8, fc: u32, flags: u8}
- nonce: base64 string (24 bytes = salt8 || fc64 || rand8)
- ct: base64 string (AEAD ciphertext)
- tag: base64 string (16 bytes Poly1305)

Payload inside AEAD is a compact TLV for minimal overhead.

Optional --facts-out writes plain facts alongside framed output for cross-checking.

References:
- ADR-001/002: Cryptographic primitives and nonce/replay policy (XChaCha20-Poly1305 with 192-bit nonce)
- ADR-006: Forward-only schema policy (salt8 only, no salt4/migrations)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import importlib.util
import json
import secrets
import struct
import time
from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from typing import Any

# Local crypto helpers (HKDF)
try:
    # Prefer importing from gateway utils to avoid duplication
    GW_DIR = Path(__file__).parent.parent / "gateway"
    cu_spec = importlib.util.spec_from_file_location(
        "crypto_utils", str(GW_DIR / "crypto_utils.py")
    )
    # Avoid using 'assert' (Bandit B101). Raise ImportError to trigger fallback.
    if not cu_spec or not cu_spec.loader:
        raise ImportError("crypto_utils spec not found")
    crypto_utils = importlib.util.module_from_spec(cu_spec)
    cu_spec.loader.exec_module(crypto_utils)
except Exception:  # Fallback minimal HKDF if import or execution fails
    import hashlib
    import hmac
    import types

    importlib = None  # type: ignore[assignment]

    crypto_utils = types.ModuleType("crypto_utils")

    def hkdf_sha256(
        ikm: bytes, salt: bytes | None, info: bytes | None, length: int
    ) -> bytes:
        if salt is None:
            salt = b""
        if info is None:
            info = b""
        prk = hmac.new(salt, ikm, hashlib.sha256).digest()
        okm = b""
        t = b""
        counter = 1
        while len(okm) < length:
            t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
            okm += t
            counter += 1
        return okm[:length]

else:
    hkdf_sha256 = crypto_utils.hkdf_sha256


# Use a cryptographically secure RNG for simulations to avoid Bandit B311 warnings.
_rnd = secrets.SystemRandom()


def _load_nacl_bindings() -> Any:
    try:
        return import_module("nacl.bindings")
    except ImportError as exc:
        raise RuntimeError(
            "PyNaCl is required for framed AEAD emission paths. "
            "Install with: pip install PyNaCl"
        ) from exc


def emit_fact(device_id: str, counter: int) -> dict[str, Any]:
    dev_id_u16 = parse_dev_id_u16(device_id)
    now_dt = datetime.now(UTC)
    payload: dict[str, Any] = {
        "counter": counter,
        "bioimpedance": round(_rnd.uniform(50.0, 120.0), 2),
        "temp_c": round(_rnd.uniform(20.0, 40.0), 2),
    }
    return {
        "pod_id": f"{dev_id_u16:016x}",
        "fc": counter,
        "ingest_time": int(now_dt.timestamp()),
        "ingest_time_rfc3339_utc": now_dt.replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "pod_time": None,
        "kind": "Custom",
        "payload": payload,
    }


def parse_dev_id_u16(device_id: str) -> int:
    """Parse a u16 device id from a device_id string like 'pod-001'.
    Falls back to 1 if no trailing number is present. Clamped to [0, 65535]."""
    num = 1
    i = len(device_id) - 1
    while i >= 0 and device_id[i].isdigit():
        i -= 1
    digits = device_id[i + 1 :]
    if digits:
        try:
            num = int(digits, 10)
        except ValueError:
            num = 1
    return max(0, min(65535, num))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _hex_digest(*parts: bytes) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.hexdigest()


def _demo_provisioning_metadata(
    master_seed: bytes, dev_id_u16: int, site_id: str | None
) -> dict[str, Any]:
    dev_bytes = f"{dev_id_u16:05d}".encode("ascii")
    firmware_version = "v0.0.0-demo"
    identity_pubkey = _hex_digest(
        b"trackone:demo:identity-pubkey:", master_seed, b":", dev_bytes
    )
    firmware_hash = _hex_digest(
        b"trackone:demo:firmware-hash:", firmware_version.encode("utf-8")
    )
    birth_cert_sig = (
        _hex_digest(
            b"trackone:demo:birth-cert:",
            identity_pubkey.encode("ascii"),
            b":",
            firmware_hash.encode("ascii"),
            b":",
            dev_bytes,
        )
        * 2
    )
    out: dict[str, Any] = {
        "identity_pubkey": identity_pubkey,
        "firmware_version": firmware_version,
        "firmware_hash": firmware_hash,
        "birth_cert_sig": birth_cert_sig,
        "provisioned_at": int(time.time()),
    }
    if site_id:
        out["site_id"] = site_id
    return out


def _demo_deployment_metadata() -> dict[str, Any]:
    return {
        "deployment_sensor_key": "shtc3-ambient",
        "sensor_keys": {
            "temperature_air": "shtc3-ambient",
            "bioimpedance_magnitude": "bioimpedance-pad",
        },
    }


# --- TLV helpers (very small, for demo/test) ---
# t=0x01: counter (u32), t=0x02: bioimpedance*100 (u16), t=0x03: temp_c*100 (i16)


def encode_tlv(payload: dict[str, Any]) -> bytes:
    out = bytearray()
    # counter
    c = int(payload.get("counter", 0)) & 0xFFFFFFFF
    out += bytes([0x01, 4]) + struct.pack(">I", c)
    # bioimpedance scaled by 100 to u16
    bio = int(round(float(payload.get("bioimpedance", 0.0)) * 100))
    bio = max(0, min(65535, bio))
    out += bytes([0x02, 2]) + struct.pack(">H", bio)
    # temp_c scaled by 100 to i16
    tc = int(round(float(payload.get("temp_c", 0.0)) * 100))
    tc = max(-32768, min(32767, tc))
    out += bytes([0x03, 2]) + struct.pack(">h", tc)
    return bytes(out)


# --- Device table helpers ---


def load_device_table(path: Path) -> dict[str, dict[str, Any]]:
    if not path or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            out: dict[str, dict[str, Any]] = {}
            for k, v in data.items():
                # Use PEP 604 union form for isinstance as recommended by ruff (UP038)
                if isinstance(k, str | int) and isinstance(v, dict):
                    out[str(k)] = v
            return out
        return {}
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {}


def save_device_table(path: Path | None, tbl: dict[str, dict[str, Any]]) -> None:
    if not path:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(tbl, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_provisioning_input(path: Path | None) -> dict[str, Any]:
    if not path or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_provisioning_input(path: Path | None, bundle: dict[str, Any]) -> None:
    if not path:
        return
    site_id = bundle.get("site_id")
    if not isinstance(site_id, str) or not site_id:
        raise ValueError(
            "provisioning input requires a top-level site_id; rerun pod_sim with --site"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    bundle["generated_at_utc"] = datetime.now(UTC).isoformat()
    path.write_text(
        json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def ensure_device_entry(
    tbl: dict[str, dict[str, Any]], dev_id_u16: int, site_id: str | None = None
) -> dict[str, Any]:
    # Top-level metadata for key derivation
    meta = tbl.get("_meta")
    if not isinstance(meta, dict):
        meta = {"version": "1.0"}
    if "master_seed" not in meta:
        meta["master_seed"] = b64(secrets.token_bytes(32))
    if "version" not in meta:
        meta["version"] = "1.0"
    tbl["_meta"] = meta

    key = str(dev_id_u16)
    if key not in tbl:
        master_seed = base64.b64decode(meta["master_seed"])
        salt8 = secrets.token_bytes(8)
        # Derive per-device uplink key from master seed and salt8
        info = f"barnacle:up:dev={dev_id_u16:05d}".encode("ascii")
        ck_up = hkdf_sha256(master_seed, salt8, info, 32)
        tbl[key] = {
            "salt8": b64(salt8),
            "ck_up": b64(ck_up),
            "highest_fc_seen": -1,
        }
    return tbl[key]


def ensure_authoritative_provisioning_record(
    bundle: dict[str, Any],
    *,
    dev_id_u16: int,
    master_seed: bytes,
    site_id: str | None = None,
) -> None:
    bundle.setdefault("version", 1)
    if site_id and not isinstance(bundle.get("site_id"), str):
        bundle["site_id"] = site_id
    records = bundle.setdefault("records", [])
    if not isinstance(records, list):
        raise ValueError("authoritative provisioning input records must be a list")

    pod_id = f"{dev_id_u16 & 0xFFFF:016x}"
    existing = None
    for record in records:
        if isinstance(record, dict) and record.get("pod_id") == pod_id:
            existing = record
            break

    if existing is None:
        existing = {
            "pod_id": pod_id,
            "deployment": _demo_deployment_metadata(),
            "provisioning": _demo_provisioning_metadata(
                master_seed, dev_id_u16, site_id
            ),
        }
        records.append(existing)
        records.sort(key=lambda item: str(item.get("pod_id", "")))
        return

    if not isinstance(existing.get("deployment"), dict):
        existing["deployment"] = _demo_deployment_metadata()
    if not isinstance(existing.get("provisioning"), dict):
        existing["provisioning"] = _demo_provisioning_metadata(
            master_seed, dev_id_u16, site_id
        )
    elif site_id and not isinstance(existing["provisioning"].get("site_id"), str):
        existing["provisioning"]["site_id"] = site_id


def build_nonce(salt8: bytes, fc64: int) -> bytes:
    """Build 24-byte nonce: salt8 || fc64 || rand8 (big-endian for fc)."""
    rand8 = secrets.token_bytes(8)
    return salt8 + (fc64 & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big") + rand8


def emit_framed(
    device_id: str,
    counter: int,
    payload: dict[str, Any],
    device_table_path: Path | None,
    provisioning_input_path: Path | None,
    site_id: str | None = None,
) -> dict[str, Any]:
    """
    Emit a framed record with header dict and base64-encoded fields using AEAD (XChaCha20-Poly1305).
    """
    dev_id_u16 = parse_dev_id_u16(device_id)
    msg_type = 1  # measurement
    fc64 = int(counter)
    fc_u32 = fc64 & 0xFFFFFFFF
    flags = 0

    # Device table / keys
    tbl = load_device_table(device_table_path) if device_table_path else {}
    entry = ensure_device_entry(tbl, dev_id_u16, site_id=site_id)
    meta = tbl.get("_meta")
    master_seed = (
        base64.b64decode(meta["master_seed"])
        if isinstance(meta, dict) and isinstance(meta.get("master_seed"), str)
        else secrets.token_bytes(32)
    )

    if provisioning_input_path:
        authoritative_input = load_provisioning_input(provisioning_input_path)
        ensure_authoritative_provisioning_record(
            authoritative_input,
            dev_id_u16=dev_id_u16,
            master_seed=master_seed,
            site_id=site_id,
        )
        save_provisioning_input(provisioning_input_path, authoritative_input)

    # Retrieve salt8, ensuring it's exactly 8 bytes
    salt8_raw = entry.get("salt8")
    if isinstance(salt8_raw, str):
        salt8 = base64.b64decode(salt8_raw)
    elif isinstance(salt8_raw, bytes):
        salt8 = salt8_raw
    else:
        raise ValueError(f"Device {dev_id_u16}: missing required salt8 field")

    # Validate salt8 length
    if len(salt8) != 8:
        raise ValueError(
            f"Device {dev_id_u16}: salt8 must be exactly 8 bytes, got {len(salt8)}"
        )

    ck_up = (
        base64.b64decode(entry["ck_up"])
        if isinstance(entry.get("ck_up"), str)
        else entry["ck_up"]
    )
    if len(ck_up) != 32:
        raise ValueError(
            f"Device {dev_id_u16}: ck_up must be exactly 32 bytes, got {len(ck_up)}"
        )

    # Nonce and AAD
    nonce = build_nonce(salt8, fc64)
    aad = struct.pack(">HB", dev_id_u16, msg_type & 0xFF)

    # TLV payload and AEAD encrypt (XChaCha20-Poly1305)
    tlv = encode_tlv(payload)
    nacl_bindings = _load_nacl_bindings()
    combined = nacl_bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        tlv, aad, nonce, ck_up
    )
    ct, tag = combined[:-16], combined[-16:]

    # Persist highest fc and any updates
    entry["highest_fc_seen"] = max(int(entry.get("highest_fc_seen", -1)), fc64)
    tbl[str(dev_id_u16)] = entry
    save_device_table(device_table_path, tbl)

    return {
        "hdr": {
            "dev_id": dev_id_u16,
            "msg_type": msg_type,
            "fc": fc_u32,
            "flags": flags,
        },
        "nonce": b64(nonce),
        "ct": b64(ct),
        "tag": b64(tag),
    }


def write_plain_fact(path: Path, counter: int, fact: dict[str, Any]) -> None:
    path.mkdir(parents=True, exist_ok=True)
    out_file = path / f"{counter:06d}.json"
    with out_file.open("w", encoding="utf-8") as fh:
        json.dump(fact, fh, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        fh.write("\n")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Emit NDJSON facts or framed records for testing"
    )
    p.add_argument("--device-id", default="pod-001")
    p.add_argument("--site", default=None)
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--sleep", type=float, default=0.0, help="Seconds between records")
    p.add_argument("--out", type=Path, help="Path to write NDJSON (defaults to stdout)")
    p.add_argument(
        "--framed",
        action="store_true",
        help="Emit framed NDJSON with {hdr, nonce, ct, tag} fields using AEAD",
    )
    p.add_argument(
        "--facts-out",
        type=Path,
        help="When --framed is set, also write plain facts to this directory for cross-check",
    )
    p.add_argument(
        "--device-table",
        type=Path,
        help="Path to device table JSON (used to persist per-device salt and key)",
    )
    p.add_argument(
        "--provisioning-input",
        type=Path,
        help="Path to authoritative provisioning input JSON emitted alongside runtime state",
    )
    args = p.parse_args(argv)

    out_fh = args.out.open("w", encoding="utf-8") if args.out else None
    try:
        for i in range(args.count):
            fact = emit_fact(args.device_id, i)
            if args.framed:
                frame = emit_framed(
                    args.device_id,
                    i,
                    fact["payload"],
                    args.device_table,
                    args.provisioning_input,
                    site_id=args.site,
                )
                line = json.dumps(frame, separators=(",", ":"))
                if args.facts_out:
                    write_plain_fact(args.facts_out, i, fact)
            else:
                line = json.dumps(fact, separators=(",", ":"))
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
