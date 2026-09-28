"""Replay an extracted acceptance corpus with fresh local HTTPS and archived TSA policy."""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import re
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from https_fixture_server import Handler


def verify_inventory(root: Path) -> None:
    expected = set()
    for line in (root / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        path = Path(name)
        if (
            not re.fullmatch(r"[0-9a-f]{64}", digest)
            or path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != name
            or name in expected
        ):
            raise ValueError("unsafe or duplicate inventory entry")
        candidate = root / path
        if candidate.is_symlink() or not candidate.resolve().is_relative_to(
            root.resolve()
        ):
            raise ValueError(f"unsafe corpus path: {name}")
        if hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
            raise ValueError(f"inventory digest mismatch: {name}")
        expected.add(name)
    actual = {
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and p != root / "SHA256SUMS"
    }
    if actual != expected:
        raise ValueError(f"inventory file set mismatch: {sorted(actual ^ expected)}")


def replay(root: Path, output: Path) -> None:
    verify_inventory(root)
    if output.exists() or output.resolve().is_relative_to(root.resolve()):
        raise ValueError("output must be a new directory outside the immutable corpus")
    evidence = root / "evidence"
    inputs = json.loads((evidence / "verification-inputs.json").read_text())
    checker = root / "tools/verify_https_bundle.py"
    output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="vtl-corpus-https-") as temporary:
        work = Path(temporary)
        cert, key = work / "web.pem", work / "web.key"
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-sha256",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-addext",
                "basicConstraints=critical,CA:true",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            capture_output=True,
        )
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.mode = "static"
        server.root = evidence / "published"
        server.log_dir = work
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for case in inputs["cases"]:
                name = case["bundle"]
                if name not in {"class-a", "class-b", "class-c"}:
                    raise ValueError("unknown corpus bundle")
                command = [
                    sys.executable,
                    "-B",
                    str(checker),
                    "--bundle-url",
                    f"https://localhost:{server.server_port}/{name}/",
                    "--https-ca-file",
                    str(cert),
                    "--scope",
                    case["scope"],
                    "--expected-segment-sha256",
                    inputs["expected_segment_sha256"],
                    "--tsa-ca-file",
                    str(evidence / "trust-inputs/tsa-root.pem"),
                    "--tsa-crls-file",
                    str(evidence / "trust-inputs/tsa-crls.pem"),
                    "--tsa-policy",
                    inputs["tsa_policy"],
                    "--tsa-signer-cert-sha256",
                    inputs["tsa_signer_cert_sha256"],
                    "--evaluation-time",
                    inputs["evaluation_time"],
                    "--max-future-skew-seconds",
                    str(inputs["max_future_skew_seconds"]),
                    "--output",
                    str(output / f"{name}.json"),
                ]
                for batch in case["batches"]:
                    command.extend(["--batch", str(batch)])
                subprocess.run(command, check=True, capture_output=True, timeout=90)
                actual = json.loads((output / f"{name}.json").read_text())
                recorded = json.loads(
                    (evidence / "reports" / f"{name}-independent.json").read_text()
                )
                for field in (
                    "artifact_sha256",
                    "manifest_sha256",
                    "claimed_disclosure_class",
                    "verification_scope",
                    "chain_status",
                    "channels",
                    "overall",
                    "network",
                ):
                    if actual[field] != recorded[field]:
                        raise ValueError(f"{name}: replay differs for {field}")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
    verify_inventory(root)
    print(
        f"Corpus inventory and all three historical evidence replays passed: {output}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--inventory-only", action="store_true")
    args = parser.parse_args()
    root = args.corpus.resolve()
    if args.inventory_only:
        verify_inventory(root)
        print("Corpus inventory passed")
    else:
        if args.output is None:
            parser.error("--output is required for replay")
        replay(root, args.output.resolve())


if __name__ == "__main__":
    main()
