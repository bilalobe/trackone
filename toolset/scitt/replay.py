#!/usr/bin/env python3
"""Verify a captured SCITT exchange offline at its explicit evaluation time."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from publication import ROOT, SERVICE_REVISION, parse_json, require, verify_publication

DEFAULT_CAPTURE = ROOT / "toolset/vectors/scitt-publication/exchange"


def replay(directory: Path) -> dict:
    capture = parse_json((directory / "capture.json").read_bytes())
    require(
        capture["service_revision"] == SERVICE_REVISION, "unexpected service revision"
    )
    signed = (directory / "signed.cose").read_bytes()
    transparent = (directory / "transparent.cose").read_bytes()
    exchanges = parse_json((directory / "exchange.json").read_bytes())
    require(
        any(
            e["method"] == "POST"
            and "/entries" in e["url"]
            and e["status"] in (202, 303)
            and (directory / e["request_body"]).read_bytes() == signed
            for e in exchanges
        ),
        "transcript lacks signed-statement submission",
    )
    require(
        any(
            e["method"] == "GET"
            and "/statement" in e["url"]
            and e["status"] == 200
            and (directory / e["response_body"]).read_bytes() == transparent
            for e in exchanges
        ),
        "transcript lacks transparent-statement retrieval",
    )
    result = verify_publication(
        signed,
        transparent,
        (directory / "segment.cbor").read_bytes(),
        policy=parse_json((directory / "authorization.json").read_bytes()),
        ca_file=directory / "organization-ca.pem",
        crls_file=directory / "organization-crls.pem",
        service_keys_file=directory / "service-keys.cbor",
        verification_time=capture["verification_time"],
    )
    require(
        result == parse_json((directory / "publication-report.json").read_bytes()),
        "publication report mismatch",
    )
    return {
        "ok": True,
        "evaluation": "historical-capture-time",
        "verification_time": capture["verification_time"],
        **result,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, default=DEFAULT_CAPTURE)
    args = parser.parse_args()
    try:
        result = replay(args.capture)
    except Exception as exc:  # noqa: BLE001 - expose a structured replay failure
        print(json.dumps({"ok": False, "reason": str(exc)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
