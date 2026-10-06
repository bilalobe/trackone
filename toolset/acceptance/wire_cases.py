"""Focused, controlled wire faults; never used by the production publisher."""

from __future__ import annotations

import copy
import hashlib
import http.server
import json
import re
import ssl
import subprocess
import threading
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

from https_fixture_server import media_type

GAPS = [
    "HTTP/2 negotiation and framing",
    "TLS hostname mismatch, expired web certificate, and protocol downgrade",
    "All portable-path grammar branches and resource-limit boundaries",
    "Transient recovery and partial-body discard on successful retry",
    "Live pending/unavailable issuance and nonce correlation failures",
    "Exhaustive RFC 3161 CMS, certificate, revocation, and DER rejection rules",
    "Producer-side malformed TSA responses (matrix exercises the verifiers)",
]


class FaultHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self) -> None:
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            # Expected when a client rejects deliberately malformed framing.
            pass

    def log_message(self, *_: object) -> None:
        pass

    def do_GET(self) -> None:
        state = self.server.state
        state["requests"].append(self.path)
        if self.headers.get("Accept-Encoding") != "identity":
            state["bad_encoding_request"] = True
        parsed = urlsplit(self.path)
        if not parsed.path.startswith("/bundle/") or parsed.query:
            self.send_error(403)
            return
        path = unquote(parsed.path[len("/bundle/") :])
        body = state["objects"].get(path)
        fault = state["fault"] if path == "segment.verify.json" else ""
        status = {
            "redirect": 302,
            "partial": 206,
            "missing": 404,
            "unavailable": 503,
        }.get(fault, 200 if body is not None else 404)
        body = body or b""
        if fault == "http10":
            self.protocol_version = "HTTP/1.0"
        self.send_response(status)
        self.send_header("Content-Type", media_type(Path(path)))
        self.send_header("Connection", "close")
        if fault == "redirect":
            self.send_header("Location", "/outside/segment.verify.json")
        if fault == "encoding":
            self.send_header("Content-Encoding", "gzip")
        self.send_header(
            "Content-Length", str(len(body) + (7 if fault == "truncated" else 0))
        )
        if fault == "duplicate_length":
            self.send_header("Content-Length", str(len(body) + 1))
        if fault == "transfer_and_length":
            self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        if fault == "transfer_and_length":
            body = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True


def run_matrix(
    publish: Path,
    pki: dict,
    rust_command: list[str],
    independent_command: list[str],
    output: Path,
    predecessor_response: bytes,
) -> None:
    """Commands contain policy flags, but no bundle URL, scope, or output."""
    original = {
        p.relative_to(publish / "class-a").as_posix(): p.read_bytes()
        for p in (publish / "class-a").rglob("*")
        if p.is_file()
    }
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FaultHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(pki["https_cert"], pki["https_key"])
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"https://localhost:{server.server_port}/bundle/"
    # Each diagnostic must identify the intended failure, not merely a nonzero exit.
    cases = [
        ("untrusted_https", "https-binding-transport", "certificate|issuer|SSL"),
        ("redirect", "https-binding-url-construction", "302|HTTP 200"),
        ("partial", "https-binding-retrieval", "206|HTTP 200"),
        ("missing", "https-binding-retrieval", "404|HTTP 200"),
        ("unavailable", "https-binding-retrieval", "503|HTTP 200"),
        (
            "truncated",
            "https-binding-retrieval",
            "truncat|partial|missing|transferred|unexpected eof|transfer closed with [0-9]+ bytes remaining",
        ),
        ("duplicate_length", "https-binding-retrieval", "length|Content-Length"),
        ("transfer_and_length", "https-binding-retrieval", "length|framing"),
        ("encoding", "https-binding-retrieval", "Content-Encoding"),
        ("http10", "https-binding-transport", "HTTP version"),
        ("unsafe_path", "https-binding-url-construction", "path|portable"),
        ("wrong_digest", "https-binding-retrieval", "commitment_mismatch|provisioned"),
        (
            "altered_record",
            "https-binding-retrieval",
            "commitment_mismatch|digest mismatch",
        ),
        ("scope_downgrade", "https-binding-retrieval", "scope|Class A|recomputation"),
        ("tsa_imprint", "rfc3161-profile", "imprint"),
        ("tsa_policy", "rfc3161-profile", "policy"),
        ("tsa_pin", "rfc3161-profile", "pin"),
        ("special_paths", "https-binding-url-construction", ""),
        ("anchor_scope", "https-binding-retrieval", ""),
        ("batch_scope", "https-binding-retrieval", ""),
    ]
    results = []
    try:
        for name, requirement, diagnostic in cases:
            objects = copy.copy(original)
            manifest = json.loads(objects["segment.verify.json"])
            flags = ["--scope", "public_recompute"]
            replacements = {}
            if name == "unsafe_path":
                manifest["artifacts"]["segment_cbor"]["path"] = "../outside.cbor"
            elif name == "altered_record":
                ref = manifest["artifacts"]["record_batches"][0]["records"][0]
                objects[ref["path"]] += b"\x00"
            elif name == "scope_downgrade":
                manifest["disclosure_class"] = "C"
                del manifest["artifacts"]["record_batches"]
            elif name == "tsa_imprint":
                ref = manifest["artifacts"]["tsa_tsr"]
                objects[ref["path"]] = predecessor_response
                ref["sha256"] = hashlib.sha256(predecessor_response).hexdigest()
            elif name == "tsa_policy":
                replacements["--tsa-policy"] = "1.3.6.1.4.1.57264.999"
            elif name == "tsa_pin":
                replacements["--tsa-signer-cert-sha256"] = "0" * 64
            elif name == "wrong_digest":
                replacements["--expected-segment-sha256"] = "0" * 64
            elif name == "untrusted_https":
                replacements["--https-ca-file"] = str(pki["tsa_root"])
            elif name == "special_paths":
                ref = manifest["artifacts"]["segment_cbor"]
                replacement = "special/é%2f?#.cbor"
                objects[replacement] = objects.pop(ref["path"])
                ref["path"] = replacement
            elif name == "anchor_scope":
                flags = ["--scope", "anchor_only"]
            elif name == "batch_scope":
                flags = ["--scope", "disclosed_batch_recompute", "--batch", "0"]
            objects["segment.verify.json"] = json.dumps(manifest).encode()
            for implementation, base in (
                ("trackone", rust_command),
                ("independent", independent_command),
            ):
                command = list(base)
                for flag, value in replacements.items():
                    command[command.index(flag) + 1] = value
                server.state = {
                    "objects": objects,
                    "fault": name,
                    "requests": [],
                    "bad_encoding_request": False,
                }
                completed = subprocess.run(
                    command + ["--bundle-url", url, *flags],
                    capture_output=True,
                    text=True,
                    timeout=90,
                    check=False,
                )
                diagnostic_text = completed.stdout + completed.stderr
                try:
                    verdict = json.loads(completed.stdout)
                except json.JSONDecodeError:
                    verdict = {}
                success = (
                    completed.returncode == 0 and verdict.get("overall") == "success"
                )
                expected_success = not diagnostic
                requests = list(server.state["requests"])
                confined = all(
                    p.startswith("/bundle/") and "?" not in p for p in requests
                )
                record_requests = [p for p in requests if "/records/" in p]
                scope_ok = (name != "anchor_scope" or not record_requests) and (
                    name != "batch_scope"
                    or len(record_requests) == 2
                    and all("batch-00000000000000000000/" in p for p in record_requests)
                )
                encoded_ok = name != "special_paths" or (
                    "/bundle/" + quote("special/é%2f?#.cbor", safe="/-._~") in requests
                )
                passed = (
                    success == expected_success
                    and confined
                    and scope_ok
                    and encoded_ok
                    and not server.state["bad_encoding_request"]
                    and (
                        expected_success
                        or completed.returncode != 0
                        and re.search(diagnostic, diagnostic_text, re.IGNORECASE)
                        is not None
                    )
                )
                results.append(
                    {
                        "case": name,
                        "implementation": implementation,
                        "requirement_anchor": requirement,
                        "expected": "success" if expected_success else "rejection",
                        "passed": bool(passed),
                        "returncode": completed.returncode,
                        "requests": requests,
                        "stdout": completed.stdout,
                        "stderr": completed.stderr,
                    }
                )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    report = {
        "complete_appendix_e_coverage": False,
        "remaining_gaps": GAPS,
        "passed": all(r["passed"] for r in results),
        "cases": results,
    }
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if not report["passed"]:
        failures = [
            f"{r['case']}/{r['implementation']}" for r in results if not r["passed"]
        ]
        raise RuntimeError(f"wire matrix failed: {', '.join(failures)}; see {output}")
