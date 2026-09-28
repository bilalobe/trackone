#!/usr/bin/env python3
"""TLS 1.3-only static evidence host or test RFC 3161 responder."""

from __future__ import annotations

import argparse
import http.server
import ssl
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "TrackOneAcceptance/1"
    # Evidence retrieval requires a completely framed HTTP/1.1 (or /2)
    # response; every reply below carries an explicit Content-Length.
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if self.server.mode != "static":  # type: ignore[attr-defined]
            self.send_error(405)
            return
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment:
            self.send_error(400)
            return
        relative = unquote(parsed.path).lstrip("/")
        # Export staging directories are dot-prefixed siblings of published
        # snapshots.  They are deliberately outside the server's namespace,
        # even when this fixture serves their common parent directory.
        parts = Path(relative).parts
        if parts and parts[0].startswith("."):
            self.send_error(404)
            return
        candidate = (self.server.root / relative).resolve()  # type: ignore[attr-defined]
        try:
            candidate.relative_to(self.server.root.resolve())  # type: ignore[attr-defined]
        except ValueError:
            self.send_error(403)
            return
        if not candidate.is_file():
            self.send_error(404)
            return
        body = candidate.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", media_type(candidate))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.server.mode != "tsa" or self.path != "/tsa":  # type: ignore[attr-defined]
            self.send_error(405)
            return
        if self.headers.get_content_type() != "application/timestamp-query":
            self.send_error(415)
            return
        length = int(self.headers.get("Content-Length", "-1"))
        if length < 0 or length > 1024 * 1024:
            self.send_error(413)
            return
        query = self.rfile.read(length)
        log_dir: Path = self.server.log_dir  # type: ignore[attr-defined]
        number = len(list(log_dir.glob("request-*.tsq")))
        request = log_dir / f"request-{number:04}.tsq"
        response = log_dir / f"response-{number:04}.tsr"
        request.write_bytes(query)
        completed = subprocess.run(
            [
                "openssl",
                "ts",
                "-reply",
                "-config",
                str(self.server.config),  # type: ignore[attr-defined]
                "-section",
                "tsa",
                "-queryfile",
                str(request),
                "-out",
                str(response),
            ],
            capture_output=True,
            timeout=15,
            check=False,
        )
        if completed.returncode != 0:
            (log_dir / f"error-{number:04}.txt").write_bytes(completed.stderr)
            self.send_error(500)
            return
        body = response.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        with (self.server.log_dir / "http.log").open("a", encoding="utf-8") as stream:  # type: ignore[attr-defined]
            stream.write((format % args) + "\n")


def media_type(path: Path) -> str:
    if path.name == "segment.verify.json":
        return "application/json"
    if path.suffix == ".cbor":
        return "application/cbor"
    if path.suffix == ".tsr":
        return "application/timestamp-reply"
    if path.suffix == ".tsq":
        return "application/timestamp-query"
    return "application/octet-stream"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["static", "tsa"], required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--log-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "static" and not args.root:
        parser.error("--root is required in static mode")
    if args.mode == "tsa" and not args.config:
        parser.error("--config is required in tsa mode")
    args.log_dir.mkdir(parents=True, exist_ok=True)
    server = http.server.ThreadingHTTPServer((args.bind, args.port), Handler)
    server.mode = args.mode  # type: ignore[attr-defined]
    server.root = args.root  # type: ignore[attr-defined]
    server.config = args.config  # type: ignore[attr-defined]
    server.log_dir = args.log_dir  # type: ignore[attr-defined]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
