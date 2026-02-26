#!/usr/bin/env python3
"""Lightweight RFC 3161 HTTP client for TrackOne demo flows.

This tool implements the simple plan discussed with the user:
1. hash an input blob and build a \\*.tsq request
2. POST the TSQ to a TSA endpoint (Content-Type: application/timestamp-query)
3. save the \\*.tsr response and optionally parse metadata via openssl ts -reply -text

It reuses the parsing helper from tsa_stamp.py to keep metadata format consistent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Literal

from scripts.gateway.tsa_stamp import _parse_tsr_text
from scripts.gateway.tsa_utils import _require_requests

HASH_CHOICES: tuple[Literal["sha1", "sha224", "sha256", "sha384", "sha512"], ...] = (
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
)


def build_tsq(
    *,
    digest_hex: str,
    tsq_path: Path,
    policy_oid: str | None,
) -> None:
    """Invoke openssl ts -query to write a TSQ file for a precomputed digest.

    This variant uses `-digest <hex>` as recommended by this OpenSSL build's
    help output, avoiding `-sha256` short flags which are not supported here.
    """
    cmd = [
        "openssl",
        "ts",
        "-query",
        "-digest",
        digest_hex,
        "-cert",
        "-out",
        str(tsq_path),
    ]
    if policy_oid:
        cmd.extend(["-tspolicy", policy_oid])
    subprocess.run(cmd, check=True)


def request_tsa(
    *,
    tsa_url: str,
    tsq_bytes: bytes,
    timeout_s: float,
    headers: dict[str, str] | None = None,
) -> bytes:
    """Submit a TSQ to the TSA via HTTP POST and return the binary TSR."""
    final_headers = {"Content-Type": "application/timestamp-query"}
    if headers:
        final_headers.update(headers)
    response = _require_requests().post(
        tsa_url, data=tsq_bytes, headers=final_headers, timeout=timeout_s
    )
    response.raise_for_status()
    return response.content  # type: ignore


def write_metadata(
    *,
    meta_path: Path,
    tsr_text: str,
    digest_hex: str,
    hash_alg: str,
    tsa_url: str,
) -> None:
    meta = _parse_tsr_text(tsr_text)
    meta.update(
        {
            "digest_hex": digest_hex,
            "hash_alg": hash_alg,
            "tsa_url": tsa_url,
        }
    )
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Submit a TSQ to an RFC 3161 TSA via HTTP"
    )
    parser.add_argument(
        "input", type=Path, help="Blob to hash (e.g. day/YYYY-MM-DD.cbor)"
    )
    parser.add_argument("tsa_url", help="RFC 3161 TSA endpoint URL")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Directory for TSQ/TSR artifacts (default: alongside input file)",
    )
    parser.add_argument(
        "--hash",
        choices=HASH_CHOICES,
        default="sha256",
        help="Hash algorithm for message imprint",
    )
    parser.add_argument(
        "--policy-oid",
        default=None,
        help="Optional policy OID to assert in the request",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="HTTP timeout in seconds",
    )
    parser.add_argument(
        "--nonce-bits",
        type=int,
        default=64,
        help="Random nonce length in bits (default: 64)",
    )
    parser.add_argument(
        "--skip-parse",
        action="store_true",
        help="Skip openssl parsing (only writes .tsq/.tsr)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    blob = args.input
    if not blob.exists():
        raise FileNotFoundError(blob)

    out_dir = args.out_dir or blob.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    prefix = blob.stem
    tsq_path = out_dir / f"{prefix}.tsq"
    tsr_path = out_dir / f"{prefix}.tsr"
    meta_path = out_dir / f"{prefix}.tsr.json"

    data = blob.read_bytes()
    digest_hex = hashlib.new(args.hash, data).hexdigest()
    build_tsq(
        digest_hex=digest_hex,
        tsq_path=tsq_path,
        policy_oid=args.policy_oid,
    )

    tsq_bytes = tsq_path.read_bytes()
    tsr_bytes = request_tsa(
        tsa_url=args.tsa_url,
        tsq_bytes=tsq_bytes,
        timeout_s=args.timeout,
    )
    tsr_path.write_bytes(tsr_bytes)

    if not args.skip_parse:
        result = subprocess.run(
            ["openssl", "ts", "-reply", "-in", str(tsr_path), "-text"],
            check=True,
            capture_output=True,
            text=True,
        )
        write_metadata(
            meta_path=meta_path,
            tsr_text=result.stdout,
            digest_hex=digest_hex,
            hash_alg=args.hash,
            tsa_url=args.tsa_url,
        )

    print(f"TSQ written: {tsq_path}")
    print(f"TSR written: {tsr_path}")
    if not args.skip_parse:
        print(f"Metadata written: {meta_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
