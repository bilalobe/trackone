#!/usr/bin/env python3
"""Unit tests for peer attestation helper."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from scripts.gateway import peer_attestation


def write_peer_file(tmp_path: Path, peers: list[dict[str, str]]) -> Path:
    path = tmp_path / "peers.json"
    path.write_text(json.dumps(peers), encoding="utf-8")
    return path


def gen_peer(peer_id: str) -> dict[str, str]:
    key = SigningKey.generate()
    return {
        "peer_id": peer_id,
        "private_key": key.encode(encoder=HexEncoder).decode(),
        "public_key": key.verify_key.encode(encoder=HexEncoder).decode(),
    }


def test_sign_and_verify_roundtrip(tmp_path):
    day_root = "ab" * 32
    peers = [gen_peer("peerA")]
    peer_config = write_peer_file(tmp_path, peers)
    out_dir = tmp_path / "out"
    result = peer_attestation.write_peer_attestations(
        site_id="an-001",
        day="2025-10-07",
        day_root_hex=day_root,
        peer_config=peer_config,
        out_dir=out_dir,
    )
    assert result.path.exists()
    saved = json.loads(result.path.read_text(encoding="utf-8"))
    sig = saved["signatures"][0]
    assert peer_attestation.verify_peer_signature(
        site_id="an-001",
        day="2025-10-07",
        day_root_hex=day_root,
        signature_hex=sig["signature_hex"],
        pubkey_hex=sig["pubkey_hex"],
    )


def test_insufficient_signatures(tmp_path):
    peer_config = write_peer_file(tmp_path, [])
    out_dir = tmp_path / "out"
    with pytest.raises(peer_attestation.PeerAttestationError):
        peer_attestation.write_peer_attestations(
            site_id="an-001",
            day="2025-10-07",
            day_root_hex="ab" * 32,
            peer_config=peer_config,
            out_dir=out_dir,
            min_signatures=1,
        )


def test_verify_failure_on_bad_signature():
    bad_sig = "00" * 64
    bad_pub = "11" * 32
    assert not peer_attestation.verify_peer_signature(
        site_id="an-001",
        day="2025-10-07",
        day_root_hex="ab" * 32,
        signature_hex=bad_sig,
        pubkey_hex=bad_pub,
    )
