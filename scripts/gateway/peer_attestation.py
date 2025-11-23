#!/usr/bin/env python3
"""Peer attestation helper for TrackOne day roots."""

import argparse
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import nacl.exceptions
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey, VerifyKey

DEFAULT_CONTEXT = b"trackone:day-root:v1"


@dataclass(slots=True)
class PeerSignature:
    peer_id: str
    signature_hex: str
    pubkey_hex: str


@dataclass(slots=True)
class AttestationResult:
    day: str
    site_id: str
    day_root: str
    signatures: list[PeerSignature]
    context: str
    path: Path


class PeerAttestationError(RuntimeError):
    """Raised when peer attestation cannot be completed."""


def load_peer_config(path: Path) -> list[dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):  # pragma: no cover - defensive programming
        raise PeerAttestationError("peer config must be a list of peers")
    peers: list[dict[str, str]] = []
    for item in data:
        if not isinstance(item, dict):  # pragma: no cover
            raise PeerAttestationError("peer entry must be an object")
        required = {"peer_id", "private_key", "public_key"}
        if not required.issubset(item):
            missing = ",".join(sorted(required - set(item)))
            raise PeerAttestationError(f"peer entry missing fields: {missing}")
        peers.append(item)
    return peers


def attestation_message(
    site_id: str, day: str, day_root_hex: str, context: bytes = DEFAULT_CONTEXT
) -> bytes:
    return b"|".join(  # context bound to avoid replays with other protocols
        [context, site_id.encode(), day.encode(), bytes.fromhex(day_root_hex)]
    )


def sign_day_root(
    *,
    site_id: str,
    day: str,
    day_root_hex: str,
    peer_id: str,
    signing_key_hex: str,
    context: bytes = DEFAULT_CONTEXT,
) -> PeerSignature:
    signing_key = SigningKey(signing_key_hex, encoder=HexEncoder)  # type: ignore
    signature = signing_key.sign(
        attestation_message(site_id, day, day_root_hex, context)
    ).signature
    verify_key_hex = signing_key.verify_key.encode(encoder=HexEncoder).decode()
    return PeerSignature(
        peer_id=peer_id, signature_hex=signature.hex(), pubkey_hex=verify_key_hex
    )


def write_peer_attestations(
    *,
    site_id: str,
    day: str,
    day_root_hex: str,
    peer_config: Path,
    out_dir: Path,
    min_signatures: int = 1,
    context: bytes = DEFAULT_CONTEXT,
) -> AttestationResult:
    peers = load_peer_config(peer_config)
    out_dir.mkdir(parents=True, exist_ok=True)
    signatures: list[PeerSignature] = []
    for entry in peers:
        sig = sign_day_root(
            site_id=site_id,
            day=day,
            day_root_hex=day_root_hex,
            peer_id=entry["peer_id"],
            signing_key_hex=entry["private_key"],
            context=context,
        )
        signatures.append(sig)

    if len(signatures) < min_signatures:
        raise PeerAttestationError(
            f"insufficient peer signatures (have={len(signatures)} need={min_signatures})"
        )

    path = out_dir / f"{day}.peers.json"
    payload = {
        "day": day,
        "site_id": site_id,
        "day_root": day_root_hex,
        "context": context.decode(),
        "signatures": [
            {
                "peer_id": sig.peer_id,
                "signature_hex": sig.signature_hex,
                "pubkey_hex": sig.pubkey_hex,
            }
            for sig in signatures
        ],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return AttestationResult(
        day=day,
        site_id=site_id,
        day_root=day_root_hex,
        signatures=signatures,
        context=context.decode(),
        path=path,
    )


def verify_peer_signature(
    *,
    site_id: str,
    day: str,
    day_root_hex: str,
    signature_hex: str,
    pubkey_hex: str,
    context: bytes = DEFAULT_CONTEXT,
) -> bool:
    verify_key = VerifyKey(pubkey_hex, encoder=HexEncoder)  # type: ignore
    try:
        verify_key.verify(
            attestation_message(site_id, day, day_root_hex, context),
            bytes.fromhex(signature_hex),
        )
        return True
    except nacl.exceptions.BadSignatureError:  # pragma: no cover
        return False


def collect_min_peers(
    signatures: Iterable[PeerSignature], min_signatures: int
) -> list[PeerSignature]:
    selected = list(signatures)
    if len(selected) < min_signatures:
        raise PeerAttestationError(
            f"need {min_signatures} signatures, got {len(selected)}"
        )
    return selected[:min_signatures]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Collect peer co-signatures for a day root"
    )
    parser.add_argument("day_json", type=Path, help="Path to day/YYYY-MM-DD.json")
    parser.add_argument(
        "--peers", type=Path, required=True, help="Peer key configuration JSON"
    )
    parser.add_argument(
        "--out", type=Path, required=True, help="Directory for peer signatures"
    )
    parser.add_argument(
        "--min", type=int, default=1, help="Minimum signatures required"
    )
    parser.add_argument(
        "--context",
        default=DEFAULT_CONTEXT.decode(),
        help="Context string bound into the signed message",
    )
    args = parser.parse_args(argv)

    data = json.loads(args.day_json.read_text(encoding="utf-8"))
    site_id = data.get("site_id")
    day = data.get("date")
    day_root = data.get("day_root") or data.get("merkle_root")
    if not (site_id and day and day_root):  # pragma: no cover - validated upstream
        raise PeerAttestationError("day record missing site/date/merkle_root")

    context = args.context.encode()
    result = write_peer_attestations(
        site_id=site_id,
        day=day,
        day_root_hex=day_root,
        peer_config=args.peers,
        out_dir=args.out,
        min_signatures=args.min,
        context=context,
    )
    print(f"Wrote {len(result.signatures)} peer signatures to {result.path}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI passthrough
    raise SystemExit(main())
