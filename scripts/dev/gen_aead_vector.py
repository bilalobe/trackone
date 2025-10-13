#!/usr/bin/env python3
"""
Generate deterministic AEAD test vectors and write to
`toolset/unified/crypto_test_vectors.json` under the keys
`deterministic_aead_vectors` (ChaCha20-Poly1305, 96-bit nonce) and
`deterministic_xaead_vectors` (XChaCha20-Poly1305, 192-bit nonce).

Vector fields (hex except fc which is int):
- ChaCha: key, salt4, fc, rand4, nonce, aad, plaintext, ciphertext, tag
- XChaCha: key, salt8, fc, rand8, nonce, aad, plaintext, ciphertext, tag
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

import nacl.bindings

ROOT = Path(__file__).resolve().parents[2]
OUT_PATH = ROOT / "toolset" / "unified" / "crypto_test_vectors.json"


def gen_chacha_vector() -> dict:
    # Fixed inputs
    key = bytes(range(32))
    salt4 = bytes([0x0A, 0x0B, 0x0C, 0x0D])
    fc = 42
    rand4 = bytes([0x01, 0x02, 0x03, 0x04])
    nonce = salt4 + fc.to_bytes(4, "big") + rand4

    # AAD for dev_id=0x0123, msg_type=1
    aad = struct.pack(">HB", 0x0123, 1)

    # TLV payload as used by pod_sim.encode_tlv
    counter = fc
    bioimpedance = 100.00  # scaled*100 -> 10000 = 0x2710
    temp_c = 25.50  # scaled*100 -> 2550  = 0x09F6

    pt = (
        bytes([0x01, 0x04])
        + struct.pack(">I", counter)
        + bytes([0x02, 0x02])
        + struct.pack(">H", int(round(bioimpedance * 100)))
        + bytes([0x03, 0x02])
        + struct.pack(">h", int(round(temp_c * 100)))
    )

    # PyNaCl AEAD encryption
    combined = nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
        pt, aad, nonce, key
    )
    ct, tag = combined[:-16], combined[-16:]

    return {
        "description": "Deterministic AEAD vector (ChaCha20-Poly1305, fixed inputs)",
        "key": key.hex(),
        "salt4": salt4.hex(),
        "fc": fc,
        "rand4": rand4.hex(),
        "nonce": nonce.hex(),
        "aad": aad.hex(),
        "plaintext": pt.hex(),
        "ciphertext": ct.hex(),
        "tag": tag.hex(),
    }


def gen_xchacha_vector() -> dict:
    # Fixed inputs (parallel to chacha vector where possible)
    key = bytes(range(32))
    salt8 = bytes.fromhex("0a0b0c0d0e0f1011")
    fc = 42
    rand8 = bytes.fromhex("0102030405060708")
    nonce = salt8 + fc.to_bytes(4, "big") + rand8

    # AAD for dev_id=0x0123, msg_type=1
    aad = struct.pack(">HB", 0x0123, 1)

    # TLV payload identical to chacha vector
    counter = fc
    bioimpedance = 100.00
    temp_c = 25.50
    pt = (
        bytes([0x01, 0x04])
        + struct.pack(">I", counter)
        + bytes([0x02, 0x02])
        + struct.pack(">H", int(round(bioimpedance * 100)))
        + bytes([0x03, 0x02])
        + struct.pack(">h", int(round(temp_c * 100)))
    )

    combined = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        pt, aad, nonce, key
    )
    ct, tag = combined[:-16], combined[-16:]

    return {
        "description": "Deterministic XAEAD vector (XChaCha20-Poly1305, fixed inputs)",
        "key": key.hex(),
        "salt8": salt8.hex(),
        "fc": fc,
        "rand8": rand8.hex(),
        "nonce": nonce.hex(),
        "aad": aad.hex(),
        "plaintext": pt.hex(),
        "ciphertext": ct.hex(),
        "tag": tag.hex(),
    }


def main() -> int:
    chacha_vec = gen_chacha_vector()
    xchacha_vec = gen_xchacha_vector()

    # Merge into existing JSON, preserving other keys
    data = {}
    if OUT_PATH.exists():
        try:
            data = json.loads(OUT_PATH.read_text(encoding="utf-8"))
        except Exception:
            data = {}

    data["deterministic_aead_vectors"] = [chacha_vec]
    data["deterministic_xaead_vectors"] = [xchacha_vec]

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Wrote vectors to {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
