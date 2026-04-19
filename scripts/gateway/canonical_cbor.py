#!/usr/bin/env python3
"""Reference/test-only CBOR commitment helpers plus native bridge utilities."""

from __future__ import annotations

import json
import math
import struct
from collections.abc import Callable
from typing import Any, cast

_native_ledger: Any | None
try:  # pragma: no cover - optional native bridge
    from trackone_core import ledger as _native_ledger
except ImportError:  # pragma: no cover - extension optional
    _native_ledger = None


def _native_ledger_attr(name: str) -> Any | None:
    try:
        return getattr(_native_ledger, name)
    except (AttributeError, ImportError):
        return None


def _require_native_canonicalizer() -> Callable[[bytes], Any]:
    rust_fn = _native_ledger_attr("canonicalize_json_to_cbor_bytes")
    if rust_fn is None:
        raise RuntimeError(
            "trackone_core native ledger helper is required for authoritative "
            "commitment paths. Build/install the native extension or run via tox."
        )
    return cast(Callable[[bytes], Any], rust_fn)


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


def _same_float_value(a: float, b: float) -> bool:
    if a != b:
        return False
    if a == 0.0:
        return math.copysign(1.0, a) == math.copysign(1.0, b)
    return True


def _encode_float_preferred(buf: bytearray, value: float) -> None:
    if not math.isfinite(value):
        raise ValueError("non-finite float not allowed")

    # RFC 8949 deterministic encoding: use the shortest float width
    # that exactly preserves the numeric value.
    try:
        f16 = struct.pack(">e", value)
        if _same_float_value(struct.unpack(">e", f16)[0], value):
            buf.append(0xF9)  # float16
            buf.extend(f16)
            return
    except OverflowError:
        pass

    f32 = struct.pack(">f", value)
    if _same_float_value(struct.unpack(">f", f32)[0], value):
        buf.append(0xFA)  # float32
        buf.extend(f32)
        return

    buf.append(0xFB)  # float64
    buf.extend(struct.pack(">d", value))


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
        _encode_float_preferred(buf, obj)
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
    """Encode JSON-like object using the Python reference CBOR policy."""
    buf = bytearray()
    _encode_obj(buf, obj)
    return bytes(buf)


def canonicalize_json_bytes_to_cbor(input_bytes: bytes) -> bytes:
    """Parse JSON bytes and return deterministic CBOR commitment bytes.

    This helper prefers the native implementation when available, but remains a
    reference/test-oriented compatibility surface.
    """
    rust_fn = _native_ledger_attr("canonicalize_json_to_cbor_bytes")
    if rust_fn is not None:
        try:
            return bytes(rust_fn(input_bytes))
        except Exception:
            pass
    return canonicalize_obj_to_cbor(json.loads(input_bytes))


def canonicalize_json_bytes_to_cbor_native(input_bytes: bytes) -> bytes:
    """Canonicalize JSON bytes through the native ledger boundary only."""
    rust_fn = _require_native_canonicalizer()
    try:
        return bytes(rust_fn(input_bytes))
    except Exception as exc:  # pragma: no cover - native path exercised in tox
        raise RuntimeError(
            "trackone_core native ledger helper failed during authoritative CBOR generation"
        ) from exc


def canonicalize_obj_to_cbor_native(obj: Any) -> bytes:
    """Canonicalize a JSON-like object through the native ledger boundary only."""
    try:
        input_bytes = json.dumps(
            obj,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"failed to serialize object for native CBOR canonicalization: {exc}"
        ) from exc
    return canonicalize_json_bytes_to_cbor_native(input_bytes)
