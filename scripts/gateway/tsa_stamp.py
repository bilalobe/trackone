#!/usr/bin/env python3
"""RFC 3161 timestamp helper for TrackOne day blobs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:  # Support both package imports and direct script execution.
    from .tsa_utils import _require_requests
except ImportError:  # pragma: no cover - fallback when run as a script
    from tsa_utils import _require_requests  # type: ignore

DEFAULT_TSA_TIMEOUT = 30.0
DEFAULT_CONTEXT = "trackone:tsa:v1"


@dataclass(slots=True)
class TsaResult:
    blob: Path
    blob_sha256: str
    tsq: Path
    tsr: Path
    tsr_json: Path
    verified: bool
    tsa_url: str
    policy_oid: str | None
    verify_output: str | None


class TsaStampError(RuntimeError):
    """Raised when TSA stamping fails."""


def _run_openssl(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=True, capture_output=True, text=True)


def _parse_tsr_text(text: str) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith("policy oid"):
            meta["policy_oid"] = stripped.split(":", 1)[-1].strip()
        elif stripped.lower().startswith("hash algorithm"):
            meta["hash_alg"] = stripped.split(":", 1)[-1].strip()
        elif stripped.lower().startswith("message imprint"):
            meta["message_imprint"] = stripped.split(":", 1)[-1].strip()
        elif stripped.lower().startswith("time stamp"):
            meta["gen_time"] = stripped.split(":", 1)[-1].strip()
        elif stripped.lower().startswith("serial number"):
            meta["serial"] = stripped.split(":", 1)[-1].strip()
        elif stripped.lower().startswith("tsa"):
            meta["tsa_name"] = stripped.split(":", 1)[-1].strip()
        elif stripped.lower().startswith("nonce"):
            meta["nonce"] = stripped.split(":", 1)[-1].strip()
    meta.setdefault("context", DEFAULT_CONTEXT)
    return meta


def tsa_stamp_day_blob(
    day_blob: Path,
    tsa_url: str,
    out_dir: Path,
    *,
    tsa_ca_pem: Path | None = None,
    tsa_chain_pem: Path | None = None,
    policy_oid: str | None = None,
    timeout_s: float = DEFAULT_TSA_TIMEOUT,
    verify_response: bool = True,
) -> TsaResult:
    if not day_blob.exists():
        raise TsaStampError(f"day blob not found: {day_blob}")
    out_dir.mkdir(parents=True, exist_ok=True)

    date_tag = day_blob.stem or time.strftime("%Y-%m-%d")
    tsq = out_dir / f"{date_tag}.tsq"
    tsr = out_dir / f"{date_tag}.tsr"
    tsr_json = out_dir / f"{date_tag}.tsr.json"

    nonce = int.from_bytes(os.urandom(16), "big")
    query_cmd = [
        "openssl",
        "ts",
        "-query",
        "-data",
        str(day_blob),
        "-sha256",
        "-cert",
        "-nonce",
        str(nonce),
        "-out",
        str(tsq),
    ]
    if policy_oid:
        query_cmd += ["-policy", policy_oid]

    subprocess.run(query_cmd, check=True)

    with tsq.open("rb") as handle:
        requests = _require_requests()
        resp = requests.post(
            tsa_url,
            data=handle.read(),
            headers={"Content-Type": "application/timestamp-query"},
            timeout=timeout_s,
        )
    resp.raise_for_status()
    tsr.write_bytes(resp.content)

    verify_cmd = [
        "openssl",
        "ts",
        "-verify",
        "-in",
        str(tsr),
        "-data",
        str(day_blob),
    ]
    if tsa_ca_pem:
        verify_cmd += ["-CAfile", str(tsa_ca_pem)]
    if tsa_chain_pem:
        verify_cmd += ["-untrusted", str(tsa_chain_pem)]
    if policy_oid:
        verify_cmd += ["-policy", policy_oid]

    verified = False
    verify_output: str | None = None
    if verify_response:
        try:
            proc = _run_openssl(verify_cmd)
            verify_output = proc.stdout
            verified = True
        except (
            subprocess.CalledProcessError
        ) as exc:  # pragma: no cover - external tool failure
            verify_output = exc.stdout or exc.stderr
            verified = False

    reply_cmd = ["openssl", "ts", "-reply", "-in", str(tsr), "-text"]
    reply_text = _run_openssl(reply_cmd).stdout
    meta = _parse_tsr_text(reply_text)
    meta.update(
        {
            "blob": str(day_blob),
            "tsq": str(tsq),
            "tsr": str(tsr),
            "tsa_url": tsa_url,
            "policy_oid": policy_oid,
            "verified": verified,
        }
    )
    tsr_json.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    blob_hash = hashlib.sha256(day_blob.read_bytes()).hexdigest()
    return TsaResult(
        blob=day_blob,
        blob_sha256=blob_hash,
        tsq=tsq,
        tsr=tsr,
        tsr_json=tsr_json,
        verified=verified,
        tsa_url=tsa_url,
        policy_oid=policy_oid,
        verify_output=verify_output,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Submit a day blob to an RFC 3161 TSA")
    parser.add_argument("day_blob", type=Path, help="Path to day/YYYY-MM-DD.bin")
    parser.add_argument("tsa_url", help="RFC 3161 TSA URL")
    parser.add_argument("out_dir", type=Path, help="Output directory for tsq/tsr files")
    parser.add_argument(
        "--tsa-ca", type=Path, default=None, help="Path to TSA CA bundle"
    )
    parser.add_argument(
        "--tsa-chain",
        type=Path,
        default=None,
        help="Optional intermediate chain for TSA",
    )
    parser.add_argument(
        "--policy-oid", default=None, help="Policy OID to assert in the request"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TSA_TIMEOUT,
        help="HTTP timeout in seconds",
    )
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="Skip openssl ts -verify (useful for dev environments without CA bundle)",
    )
    args = parser.parse_args(argv)

    result = tsa_stamp_day_blob(
        day_blob=args.day_blob,
        tsa_url=args.tsa_url,
        out_dir=args.out_dir,
        tsa_ca_pem=args.tsa_ca,
        tsa_chain_pem=args.tsa_chain,
        policy_oid=args.policy_oid,
        timeout_s=args.timeout,
        verify_response=not args.skip_verify,
    )
    print(json.dumps(result.__dict__, default=str, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI passthrough
    raise SystemExit(main())
