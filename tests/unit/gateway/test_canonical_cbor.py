from __future__ import annotations

from scripts.gateway.canonical_cbor import canonicalize_obj_to_cbor


def test_text_map_keys_sorted_by_len_then_bytes():
    obj = {
        "aa": 1,
        "b": 2,
    }
    encoded = canonicalize_obj_to_cbor(obj)
    expected = bytes([0xA2, 0x61, ord("b"), 0x02, 0x62, ord("a"), ord("a"), 0x01])
    assert encoded == expected
