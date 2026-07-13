#!/usr/bin/env python3
"""Exercise pinned OTS verifier candidates against a deterministic proof."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SANITY_SCHEMA = "trackone-ots-verifier-sanity-v1"
VERIFY_CACHE_HEADER = b"OTSV" + bytes((1, 0, 0, 0)) + (b"\x00" * 8)


class SanityError(RuntimeError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SanityError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SanityError(f"JSON root is not an object: {path}")
    return value


def run(command: list[str], *, timeout: int = 45) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment.update({"LC_ALL": "C", "TZ": "UTC"})
    try:
        return subprocess.run(
            command,
            capture_output=True,
            check=False,
            env=environment,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SanityError(f"cannot run {command[0]}: {exc}") from exc


def parse_json_stdout(
    completed: subprocess.CompletedProcess[str], label: str
) -> dict[str, Any]:
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SanityError(
            f"{label} did not emit JSON (exit {completed.returncode}): "
            f"{completed.stdout}{completed.stderr}"
        ) from exc
    if not isinstance(payload, dict):
        raise SanityError(f"{label} JSON root is not an object")
    return payload


def compact_target(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if not mantissa or bits & 0x00800000:
        raise SanityError(f"invalid compact proof-of-work target: {bits:#x}")
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def validate_header(header: bytes, fixture: dict[str, Any]) -> dict[str, Any]:
    if len(header) != 80:
        raise SanityError(f"Bitcoin header is {len(header)} bytes, expected 80")
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    block_hash = digest[::-1].hex()
    if block_hash != fixture.get("bitcoin_block_hash"):
        raise SanityError("Bitcoin fixture block hash mismatch")
    merkle_root = header[36:68][::-1].hex()
    if merkle_root != fixture.get("bitcoin_merkle_root"):
        raise SanityError("Bitcoin fixture Merkle root mismatch")
    bits = int.from_bytes(header[72:76], "little")
    if int.from_bytes(digest, "little") > compact_target(bits):
        raise SanityError(
            "Bitcoin fixture header does not satisfy its proof-of-work target"
        )
    return {
        "block_hash": block_hash,
        "bits": f"{bits:08x}",
        "header_sha256": sha256_bytes(header),
        "merkle_root": merkle_root,
    }


def build_sparse_sidecar(height: int, header: bytes) -> bytes:
    if not 0 <= height <= 0xFFFFFFFF:
        raise SanityError("Bitcoin fixture height does not fit uint32")
    if len(header) != 80:
        raise SanityError("Bitcoin fixture header is not 80 bytes")
    return VERIFY_CACHE_HEADER + struct.pack("<I", height) + header


def assert_json_client(
    executable: Path,
    proof_path: Path,
    expected_digest: str,
    expected_height: int,
) -> dict[str, Any]:
    info = run([str(executable), "info", "--json", str(proof_path)])
    if info.returncode != 0:
        raise SanityError(f"JSON info failed: {info.stdout}{info.stderr}")
    info_payload = parse_json_stdout(info, "ots info --json")
    if info_payload.get("file_digest") != expected_digest:
        raise SanityError("JSON client reported the wrong detached file digest")
    attestations = info_payload.get("timestamp", {}).get("attestations", [])
    heights = sorted(
        item.get("height")
        for item in attestations
        if isinstance(item, dict)
        and item.get("type") == "BitcoinBlockHeaderAttestation"
    )
    if expected_height not in heights:
        raise SanityError(f"JSON client omitted Bitcoin height {expected_height}")

    verification = run(
        [str(executable), "--no-bitcoin", "verify", "--json", str(proof_path)]
    )
    if verification.returncode != 2:
        raise SanityError(
            "JSON client did not reserve exit 2 for a structurally complete proof "
            f"requiring Bitcoin verification: {verification.stdout}{verification.stderr}"
        )
    verify_payload = parse_json_stdout(verification, "ots verify --json")
    if verify_payload.get("verified") is not False:
        raise SanityError("JSON client claimed verification while Bitcoin was disabled")
    if verify_payload.get("exit_code") != 2:
        raise SanityError("JSON client payload exit_code disagrees with process exit 2")
    if verify_payload.get("status") not in {"pending", "manual_check_required"}:
        raise SanityError("JSON client returned an unexpected no-Bitcoin status")

    target_path = proof_path.with_suffix("")
    original = target_path.read_bytes()
    target_path.write_bytes(original + b"tampered")
    try:
        rejected = run(
            [str(executable), "--no-bitcoin", "verify", "--json", str(proof_path)]
        )
    finally:
        target_path.write_bytes(original)
    if rejected.returncode == 0 or '"verified": true' in rejected.stdout.lower():
        raise SanityError("JSON client accepted a tampered target")

    return {
        "info_json": True,
        "manual_check_exit_code": 2,
        "reported_bitcoin_heights": heights,
        "tampered_target_rejected": True,
    }


def assert_headers_client(
    executable: Path,
    proof_path: Path,
    sidecar_path: Path,
    expected_height: int,
) -> dict[str, Any]:
    verified = run(
        [
            str(executable),
            "--no-cache",
            "verify",
            "--headers",
            str(sidecar_path),
            str(proof_path),
        ]
    )
    if verified.returncode != 0 or f"Bitcoin block {expected_height}" not in (
        verified.stdout + verified.stderr
    ):
        raise SanityError(
            f"header-sidecar verification failed: {verified.stdout}{verified.stderr}"
        )

    target_path = proof_path.with_suffix("")
    original_target = target_path.read_bytes()
    target_path.write_bytes(original_target + b"tampered")
    try:
        rejected_target = run(
            [
                str(executable),
                "--no-cache",
                "verify",
                "--headers",
                str(sidecar_path),
                str(proof_path),
            ]
        )
    finally:
        target_path.write_bytes(original_target)
    if rejected_target.returncode == 0:
        raise SanityError("header-sidecar client accepted a tampered target")

    original_sidecar = sidecar_path.read_bytes()
    corrupted = bytearray(original_sidecar)
    corrupted[len(VERIFY_CACHE_HEADER) + 4 + 36] ^= 0x01
    sidecar_path.write_bytes(corrupted)
    try:
        rejected_header = run(
            [
                str(executable),
                "--no-cache",
                "verify",
                "--headers",
                str(sidecar_path),
                str(proof_path),
            ]
        )
    finally:
        sidecar_path.write_bytes(original_sidecar)
    if rejected_header.returncode == 0:
        raise SanityError("header-sidecar client accepted a corrupted Bitcoin header")

    return {
        "offline_completed_proof_verified": True,
        "tampered_header_rejected": True,
        "tampered_target_rejected": True,
    }


def check(args: argparse.Namespace) -> dict[str, Any]:
    fixture = read_json(args.fixture_metadata)
    target = args.fixture_target.read_bytes()
    try:
        proof = base64.b64decode(
            args.fixture_proof_b64.read_text(encoding="ascii").strip(), validate=True
        )
    except (OSError, ValueError) as exc:
        raise SanityError(f"cannot decode fixture proof: {exc}") from exc
    if sha256_bytes(target) != fixture.get("target_sha256"):
        raise SanityError("fixture target SHA-256 mismatch")
    if sha256_bytes(proof) != fixture.get("proof_sha256"):
        raise SanityError("fixture proof SHA-256 mismatch")
    try:
        header = bytes.fromhex(fixture["bitcoin_header_hex"])
        height = int(fixture["bitcoin_block_height"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SanityError("fixture Bitcoin header metadata is invalid") from exc
    header_result = validate_header(header, fixture)

    for executable in (args.json_ots, args.headers_ots):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise SanityError(
                f"OTS executable is missing or not executable: {executable}"
            )

    with tempfile.TemporaryDirectory(prefix="trackone-ots-sanity-") as temp:
        root = Path(temp)
        target_path = root / "hello-world.txt"
        proof_path = root / "hello-world.txt.ots"
        sidecar_path = root / "hello-world.txt.ots-btc-headers.bin"
        target_path.write_bytes(target)
        proof_path.write_bytes(proof)
        sidecar = build_sparse_sidecar(height, header)
        sidecar_path.write_bytes(sidecar)

        json_checks = assert_json_client(
            args.json_ots, proof_path, fixture["target_sha256"], height
        )
        header_checks = assert_headers_client(
            args.headers_ots, proof_path, sidecar_path, height
        )

    return {
        "schema": SANITY_SCHEMA,
        "ok": True,
        "fixture": {
            "id": fixture["fixture_id"],
            "proof_sha256": fixture["proof_sha256"],
            "target_sha256": fixture["target_sha256"],
            "bitcoin_height": height,
            **header_result,
        },
        "clients": {
            "json": {
                "repository": "bilalobe/opentimestamps-client",
                "commit": args.json_client_commit,
                "checks": json_checks,
            },
            "headers": {
                "repository": "djdarcy/dazzle-opentimestamps-client",
                "commit": args.headers_client_commit,
                "checks": header_checks,
            },
        },
        "trust_boundary": {
            "header_sidecar_validates_full_bitcoin_consensus": False,
            "header_sidecar_role": "proof-shape-and-configured-header-source-quorum",
        },
    }


def main() -> int:
    fixture_root = Path(__file__).resolve().parent / "fixtures"
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-ots", type=Path, required=True)
    parser.add_argument("--headers-ots", type=Path, required=True)
    parser.add_argument("--json-client-commit", required=True)
    parser.add_argument("--headers-client-commit", required=True)
    parser.add_argument(
        "--fixture-target", type=Path, default=fixture_root / "hello-world.txt"
    )
    parser.add_argument(
        "--fixture-proof-b64",
        type=Path,
        default=fixture_root / "hello-world.txt.ots.b64",
    )
    parser.add_argument(
        "--fixture-metadata",
        type=Path,
        default=fixture_root / "hello-world-header.json",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = check(args)
    except Exception as exc:
        print(f"OTS verifier sanity failed: {exc}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
