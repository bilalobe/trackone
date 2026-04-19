from __future__ import annotations

import math

import pytest

from scripts.gateway import canonical_cbor
from scripts.gateway.canonical_cbor import canonicalize_obj_to_cbor


def test_text_map_keys_sorted_by_len_then_bytes():
    obj = {
        "aa": 1,
        "b": 2,
    }
    encoded = canonicalize_obj_to_cbor(obj)
    expected = bytes([0xA2, 0x61, ord("b"), 0x02, 0x62, ord("a"), ord("a"), 0x01])
    assert encoded == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1.0, bytes([0xF9, 0x3C, 0x00])),
        (1.5, bytes([0xF9, 0x3E, 0x00])),
        (100000.0, bytes([0xFA, 0x47, 0xC3, 0x50, 0x00])),
    ],
)
def test_floats_use_preferred_width(value: float, expected: bytes):
    assert canonicalize_obj_to_cbor(value) == expected


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_floats_are_rejected(value: float):
    with pytest.raises(ValueError, match="non-finite float not allowed"):
        canonicalize_obj_to_cbor(value)


def test_canonicalize_json_bytes_falls_back_when_ledger_shim_raises_importerror(
    monkeypatch,
):
    class _ImportErrorShim:
        def __getattr__(self, _name: str):
            raise ImportError("native extension not available")

    monkeypatch.setattr(canonical_cbor, "ledger", _ImportErrorShim())

    encoded = canonical_cbor.canonicalize_json_bytes_to_cbor(b'{"aa":1,"b":2}')

    assert encoded == bytes(
        [0xA2, 0x61, ord("b"), 0x02, 0x62, ord("a"), ord("a"), 0x01]
    )
