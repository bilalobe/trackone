#!/usr/bin/env python3
"""Deterministic CBOR commitment helpers (ADR-039)."""

from __future__ import annotations

import json
import math
import struct
from typing import Any

_RUST_CANONICALIZE_JSON_TO_CBOR = None
try:  # pragma: no cover - optional acceleration
    import trackone_core

    native = getattr(trackone_core, "_native", None)
    if native is not None:
        _ledger = getattr(native, "ledger", None)
        if _ledger is not None:
            _RUST_CANONICALIZE_JSON_TO_CBOR = getattr(
                _ledger, "canonicalize_json_to_cbor_bytes", None
            )
except Exception:  # pragma: no cover - extension optional
    _RUST_CANONICALIZE_JSON_TO_CBOR = None


def _major_u64(buf: bytearray, major: int, n: int) -> None:
    if n < 0:
        raise ValueError("length cannot be negative")
    if n < 24:
        buf.append((major << 5) | n)
    elif n <= 0xFF:
        buf.extend(((major << 5) | 24, n))
    elif n <= 0xFFFF:
        buf.append((major << 5) | 25)
        buf.extend(n.to_bytes(2, "big"))
    elif n <= 0xFFFFFFFF:
        buf.append((major << 5) | 26)
        buf.extend(n.to_bytes(4, "big"))
    else:
        buf.append((major << 5) | 27)
        buf.extend(n.to_bytes(8, "big"))


def _encode_int(buf: bytearray, n: int) -> None:
    if n >= 0:
        _major_u64(buf, 0, n)
    else:
        _major_u64(buf, 1, -1 - n)


def _encode_obj(buf: bytearray, obj: Any) -> None:
    if obj is None:
        buf.append(0xF6)
        return
    if obj is False:
        buf.append(0xF4)
        return
    if obj is True:
        buf.append(0xF5)
        return
    if isinstance(obj, int):
        _encode_int(buf, obj)
        return
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError("non-finite float not allowed")
        buf.append(0xFB)  # float64
        buf.extend(struct.pack(">d", obj))
        return
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        _major_u64(buf, 3, len(raw))
        buf.extend(raw)
        return
    if isinstance(obj, bytes | bytearray):
        raw = bytes(obj)
        _major_u64(buf, 2, len(raw))
        buf.extend(raw)
        return
    if isinstance(obj, list):
        _major_u64(buf, 4, len(obj))
        for item in obj:
            _encode_obj(buf, item)
        return
    if isinstance(obj, dict):
        items: list[tuple[int, bytes, str, Any]] = []
        for key, val in obj.items():
            if not isinstance(key, str):
                raise TypeError("CBOR commitment maps require string keys")
            key_bytes = key.encode("utf-8")
            items.append((len(key_bytes), key_bytes, key, val))
        # RFC 8949 deterministic ordering for text keys:
        # 1) encoded key length, 2) lexicographic encoded key bytes.
        items.sort(key=lambda item: (item[0], item[1]))
        _major_u64(buf, 5, len(items))
        for _key_len, _key_bytes, key, val in items:
            _encode_obj(buf, key)
            _encode_obj(buf, val)
        return
    raise TypeError(f"unsupported value for CBOR commitment: {type(obj)!r}")


def canonicalize_obj_to_cbor(obj: Any) -> bytes:
    """Encode JSON-like object into deterministic CBOR commitment bytes."""
    buf = bytearray()
    _encode_obj(buf, obj)
    return bytes(buf)


def canonicalize_json_bytes_to_cbor(input_bytes: bytes) -> bytes:
    """Parse JSON bytes and return deterministic CBOR commitment bytes."""
    rust_fn = _RUST_CANONICALIZE_JSON_TO_CBOR
    if rust_fn is not None:
        try:
            return bytes(rust_fn(input_bytes))
        except Exception:
            pass
    return canonicalize_obj_to_cbor(json.loads(input_bytes))
