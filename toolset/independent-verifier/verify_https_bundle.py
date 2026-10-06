#!/usr/bin/env python3
"""Independent acceptance checker for the VTL HTTPS reference binding.

Uses only the Python standard library and OpenSSL. It does not import TrackOne
packages, invoke ``trackone-evidence``, or consume another verifier's verdict.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.client
import json
import math
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

PROFILE_ID = "c08ade4e-1785-4eb6-9648-b7003d76288d"
SHA256_OID = "2.16.840.1.101.3.4.2.1"
SIGNED_DATA_OID = "1.2.840.113549.1.7.2"
TST_INFO_OID = "1.2.840.113549.1.9.16.1.4"
SIGNING_CERT_V2_OID = "1.2.840.113549.1.9.16.2.47"
LEGACY_SIGNING_CERT_OID = "1.2.840.113549.1.9.16.2.12"
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_OBJECT = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_REQUESTS = 10_000
FETCH_DEADLINE_SECONDS = 60.0
MAX_UINT64 = (1 << 64) - 1
MAX_BATCH_RECORD_LIMIT = 1 << 63
MAX_CBOR_NESTING_DEPTH = 32
MAX_CBOR_ITEMS = 1_000_000
TRANSIENT_STATUS = {408, 429, 500, 502, 503, 504}


class CheckError(RuntimeError):
    pass


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CheckError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def parse_json(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CheckError(f"invalid producer manifest JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise CheckError("producer manifest must be a JSON object")
    return value


def portable_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise CheckError("artifact path must be a non-empty string")
    if (
        value.startswith(("/", "\\"))
        or "\\" in value
        or ":" in value
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise CheckError(f"non-portable artifact path {value!r}")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise CheckError(f"non-portable artifact path {value!r}")
    return value


class DeadlineHTTPSConnection(http.client.HTTPSConnection):
    """Apply one elapsed-time budget to DNS, TCP, and TLS setup."""

    def __init__(self, *args: Any, deadline: float, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.deadline = deadline

    def remaining_timeout(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise CheckError("HTTPS fetch deadline exceeded")
        return min(self.timeout, remaining)

    def connect(self) -> None:
        resolved = threading.Event()
        addresses: list[Any] = []
        errors: list[OSError] = []

        def resolve() -> None:
            try:
                addresses.extend(
                    socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM)
                )
            except OSError as exc:
                errors.append(exc)
            finally:
                resolved.set()

        # libc DNS resolution has no portable cancellation API. A daemon worker
        # lets the caller enforce its deadline; a late result cannot open sockets.
        resolver = threading.Thread(target=resolve, daemon=True)
        resolver.start()
        if not resolved.wait(max(0.0, self.deadline - time.monotonic())):
            raise CheckError("HTTPS fetch deadline exceeded")
        self.remaining_timeout()
        if errors:
            raise errors[0]
        last_error: OSError | None = None
        for family, socktype, protocol, _canonical, address in addresses:
            timeout = self.remaining_timeout()
            self.sock = socket.socket(family, socktype, protocol)
            try:
                self.sock.settimeout(timeout)
                self.sock.connect(address)
                break
            except OSError as exc:
                last_error = exc
                self.sock.close()
                self.sock = None
        else:
            if last_error is not None:
                raise last_error
            raise OSError("DNS resolution returned no addresses")
        self.sock.settimeout(self.remaining_timeout())
        self.sock = self._context.wrap_socket(
            self.sock, server_hostname=self.host, do_handshake_on_connect=False
        )
        self.sock.settimeout(self.remaining_timeout())
        self.sock.do_handshake()
        self.sock.settimeout(self.remaining_timeout())


@dataclass
class HttpRetriever:
    root: str
    ca_file: Path
    timeout: float = 15.0
    retries: int = 2
    requests: int = 0
    total_bytes: int = 0

    def __post_init__(self) -> None:
        parsed = urlsplit(self.root)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not parsed.path.endswith("/")
        ):
            raise CheckError(
                "bundle URL must be an absolute HTTPS directory URL without "
                "userinfo, query, or fragment"
            )
        if not self.ca_file.is_file():
            raise CheckError("HTTPS CA file is not a regular file")
        self.parsed = parsed
        self.context = ssl.create_default_context(cafile=str(self.ca_file))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3

    def get(self, relative: str, accept: str) -> bytes:
        relative = portable_path(relative)
        # Component-wise quoting makes literal %, ?, and # filename octets.
        suffix = "/".join(quote(part, safe="-._~") for part in relative.split("/"))
        request_path = self.parsed.path + suffix
        if not request_path.startswith(self.parsed.path):
            raise CheckError("constructed request escaped the bundle root")
        self.requests += 1
        if self.requests > MAX_REQUESTS:
            raise CheckError("HTTPS request limit exceeded")
        deadline = time.monotonic() + FETCH_DEADLINE_SECONDS
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CheckError("HTTPS fetch deadline exceeded")
            connection = DeadlineHTTPSConnection(
                self.parsed.hostname,
                self.parsed.port or 443,
                timeout=min(self.timeout, remaining),
                context=self.context,
                deadline=deadline,
            )
            expired = threading.Event()

            def expire(
                deadline_event: threading.Event = expired,
                active_connection: DeadlineHTTPSConnection = connection,
            ) -> None:
                deadline_event.set()
                active_socket = active_connection.sock
                if active_socket is not None:
                    try:
                        active_socket.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

            timer = threading.Timer(remaining, expire)
            timer.daemon = True
            timer.start()
            try:
                connection.request(
                    "GET",
                    request_path,
                    headers={
                        "Accept": accept,
                        "Accept-Encoding": "identity",
                        "Connection": "close",
                    },
                )
                if expired.is_set():
                    raise CheckError("HTTPS fetch deadline exceeded")
                response = connection.getresponse()
                if expired.is_set():
                    raise CheckError("HTTPS fetch deadline exceeded")
                if response.version != 11:
                    raise CheckError("unsupported HTTP version; HTTP/1.1 is required")
                if response.status in TRANSIENT_STATUS and attempt < self.retries:
                    response.read(MAX_OBJECT + 1)
                    time.sleep(0.05 * (attempt + 1))
                    continue
                if response.status != 200:
                    raise CheckError(
                        f"evidence retrieval requires HTTP 200, got {response.status}"
                    )
                encoding = response.getheader("Content-Encoding")
                if encoding is not None and encoding.lower().strip() != "identity":
                    raise CheckError(f"unexpected Content-Encoding {encoding!r}")
                declared = response.getheader("Content-Length")
                if (
                    declared is not None
                    and response.getheader("Transfer-Encoding") is not None
                ):
                    raise CheckError(
                        "ambiguous HTTP framing: Transfer-Encoding with Content-Length"
                    )
                body = bytearray()
                while True:
                    chunk = response.read(min(1024 * 1024, MAX_OBJECT + 1 - len(body)))
                    if expired.is_set():
                        raise CheckError("HTTPS fetch deadline exceeded")
                    if not chunk:
                        break
                    body.extend(chunk)
                    if len(body) > MAX_OBJECT:
                        raise CheckError(
                            "HTTPS object exceeds the configured byte limit"
                        )
                if declared is not None:
                    try:
                        declared_length = int(declared)
                    except ValueError as exc:
                        raise CheckError("invalid HTTP Content-Length") from exc
                    if declared_length != len(body):
                        raise CheckError("truncated or overlong HTTP evidence body")
                self.total_bytes += len(body)
                if self.total_bytes > MAX_TOTAL:
                    raise CheckError("aggregate HTTPS byte limit exceeded")
                return bytes(body)
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                if expired.is_set() or time.monotonic() >= deadline:
                    raise CheckError("HTTPS fetch deadline exceeded") from exc
                last_error = exc
                if attempt == self.retries:
                    break
                time.sleep(0.05 * (attempt + 1))
            finally:
                timer.cancel()
                connection.close()
        raise CheckError(f"HTTPS retrieval exhausted its retry budget: {last_error}")


class CborDecoder:
    def __init__(
        self,
        data: bytes,
        max_depth: int = MAX_CBOR_NESTING_DEPTH,
        max_items: int = MAX_CBOR_ITEMS,
    ):
        self.data = data
        self.offset = 0
        self.max_depth = max_depth
        self.max_items = max_items
        self.items = 0

    def decode(self) -> Any:
        value = self.item()
        if self.offset != len(self.data):
            raise CheckError("trailing CBOR bytes")
        return value

    def take(self, length: int) -> bytes:
        end = self.offset + length
        if end > len(self.data):
            raise CheckError("truncated CBOR")
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        if additional not in widths:
            raise CheckError("indefinite or reserved CBOR argument")
        width = widths[additional]
        value = int.from_bytes(self.take(width), "big")
        if value < {1: 24, 2: 256, 4: 65536, 8: 4294967296}[width]:
            raise CheckError("non-shortest CBOR argument")
        return value

    def item(self, depth: int = 0, *, materialize: bool = True) -> Any:
        if depth > self.max_depth:
            raise CheckError("CBOR nesting depth exceeds the supported limit")
        self.items += 1
        if self.items > self.max_items:
            raise CheckError("CBOR item count exceeds the supported limit")
        initial = self.take(1)[0]
        major, additional = initial >> 5, initial & 31
        if major == 0:
            return self.argument(additional)
        if major == 1:
            return -1 - self.argument(additional)
        if major == 2:
            length = self.argument(additional)
            if not materialize:
                self.advance(length)
                return None
            return self.take(length)
        if major == 3:
            try:
                return self.take(self.argument(additional)).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CheckError("invalid UTF-8 CBOR text") from exc
        if major == 4:
            count = self.argument(additional)
            if count > len(self.data) - self.offset:
                raise CheckError("CBOR array length exceeds remaining input")
            if count > self.max_items - self.items:
                raise CheckError("CBOR item count exceeds the supported limit")
            if materialize:
                return [self.item(depth + 1) for _ in range(count)]
            for _ in range(count):
                self.item(depth + 1, materialize=False)
            return None
        if major == 5:
            count = self.argument(additional)
            if count > (len(self.data) - self.offset) // 2:
                raise CheckError("CBOR map length exceeds remaining input")
            if count > (self.max_items - self.items) // 2:
                raise CheckError("CBOR item count exceeds the supported limit")
            return self.mapping(count, depth, materialize=materialize)
        if major == 6:
            raise CheckError("CBOR tags are not permitted")
        if major == 7 and additional in {20, 21, 22}:
            return {20: False, 21: True, 22: None}[additional]
        if major == 7 and additional in {25, 26, 27}:
            fmt, width = {25: (">e", 2), 26: (">f", 4), 27: (">d", 8)}[additional]
            encoded = self.take(width)
            value = struct.unpack(fmt, encoded)[0]
            if not math.isfinite(value):
                raise CheckError("non-finite CBOR float")
            for shorter in (">e", ">f")[: {25: 0, 26: 1, 27: 2}[additional]]:
                try:
                    candidate = struct.pack(shorter, value)
                except OverflowError:
                    continue
                if struct.pack(
                    ">d", struct.unpack(shorter, candidate)[0]
                ) == struct.pack(">d", value):
                    raise CheckError(
                        "CBOR float is not encoded at its shortest exact width"
                    )
            return value
        raise CheckError("unsupported CBOR value")

    def advance(self, length: int) -> None:
        if self.offset + length > len(self.data):
            raise CheckError("truncated CBOR")
        self.offset += length

    def mapping(
        self, count: int, depth: int, *, materialize: bool = True
    ) -> dict[str, Any] | None:
        result: dict[str, Any] | None = {} if materialize else None
        previous: tuple[int, bytes] | None = None
        for _ in range(count):
            start = self.offset
            key = self.item(depth + 1)
            encoded = self.data[start : self.offset]
            ordering = (len(encoded), encoded)
            if not isinstance(key, str) or (
                previous is not None and ordering <= previous
            ):
                raise CheckError(
                    "non-text, duplicate, or non-deterministic CBOR map key"
                )
            if result is not None and key in result:
                raise CheckError("duplicate CBOR map key")
            previous = ordering
            value = self.item(depth + 1, materialize=materialize)
            if result is not None:
                result[key] = value
        return result


@dataclass
class DerNode:
    tag: int
    value: bytes
    children: list[DerNode]


def der_nodes(data: bytes) -> list[DerNode]:
    nodes: list[DerNode] = []
    offset = 0
    while offset < len(data):
        tag = data[offset]
        offset += 1
        if tag & 0x1F == 0x1F:
            raise CheckError("high-tag-number DER is outside this checker")
        if offset >= len(data):
            raise CheckError("truncated DER length")
        length = data[offset]
        offset += 1
        if length & 0x80:
            width = length & 0x7F
            if width == 0 or width > 4 or offset + width > len(data):
                raise CheckError("invalid DER length")
            length = int.from_bytes(data[offset : offset + width], "big")
            if length < 128:
                raise CheckError("non-minimal DER length")
            offset += width
        end = offset + length
        if end > len(data):
            raise CheckError("truncated DER value")
        value = data[offset:end]
        children = der_nodes(value) if tag & 0x20 else []
        nodes.append(DerNode(tag, value, children))
        offset = end
    return nodes


def one(nodes: list[DerNode], tag: int, label: str) -> DerNode:
    matches = [node for node in nodes if node.tag == tag]
    if len(matches) != 1:
        raise CheckError(f"{label} must occur exactly once")
    return matches[0]


def der_integer(node: DerNode) -> int:
    if node.tag != 0x02 or not node.value or node.value[0] & 0x80:
        raise CheckError("invalid non-negative DER INTEGER")
    if len(node.value) > 1 and node.value[0] == 0 and not node.value[1] & 0x80:
        raise CheckError("non-minimal DER INTEGER")
    return int.from_bytes(node.value, "big")


def der_oid(node: DerNode) -> str:
    if node.tag != 0x06 or not node.value:
        raise CheckError("invalid DER OID")
    first = node.value[0]
    first_component = min(first // 40, 2)
    parts = [first_component, first - first_component * 40]
    value = 0
    for byte in node.value[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    if value:
        raise CheckError("truncated DER OID")
    return ".".join(str(part) for part in parts)


def message_imprint(node: DerNode) -> tuple[str, bytes]:
    if node.tag != 0x30 or len(node.children) != 2:
        raise CheckError("invalid RFC 3161 messageImprint")
    algorithm = node.children[0]
    digest = node.children[1]
    if algorithm.tag != 0x30 or not algorithm.children or digest.tag != 0x04:
        raise CheckError("invalid messageImprint fields")
    return der_oid(algorithm.children[0]), digest.value


def parse_generalized_time(node: DerNode) -> dt.datetime:
    if node.tag != 0x18:
        raise CheckError("TSTInfo genTime is not GeneralizedTime")
    raw = node.value.decode("ascii")
    match = re.fullmatch(r"(\d{14})(?:\.(\d*[1-9]))?Z", raw)
    if not match:
        raise CheckError("TSTInfo genTime is not canonical UTC GeneralizedTime")
    base = dt.datetime.strptime(match.group(1), "%Y%m%d%H%M%S").replace(tzinfo=dt.UTC)
    fraction = match.group(2) or ""
    return base.replace(microsecond=int((fraction + "000000")[:6]))


def parse_tst_response(response: bytes) -> tuple[dict[str, Any], DerNode]:
    root = one(der_nodes(response), 0x30, "TimeStampResp")
    if len(root.children) != 2:
        raise CheckError("successful TimeStampResp must contain status and token")
    status_info = root.children[0]
    if status_info.tag != 0x30 or not status_info.children:
        raise CheckError("malformed PKIStatusInfo")
    status = der_integer(status_info.children[0])
    if status != 0:
        raise CheckError(f"TimeStampResp status is {status}, not granted (0)")
    content_info = root.children[1]
    if content_info.tag != 0x30 or len(content_info.children) != 2:
        raise CheckError("malformed CMS ContentInfo")
    if der_oid(content_info.children[0]) != SIGNED_DATA_OID:
        raise CheckError("timestamp token contentType is not id-signedData")
    signed_data = one(content_info.children[1].children, 0x30, "SignedData")
    if len(signed_data.children) < 4:
        raise CheckError("malformed CMS SignedData")
    signer_infos = signed_data.children[-1]
    if signer_infos.tag != 0x31 or len(signer_infos.children) != 1:
        raise CheckError("timestamp token must contain exactly one CMS SignerInfo")
    encap = signed_data.children[2]
    if (
        encap.tag != 0x30
        or not encap.children
        or der_oid(encap.children[0]) != TST_INFO_OID
    ):
        raise CheckError("CMS encapsulated content is not id-ct-TSTInfo")
    content = one(encap.children, 0xA0, "encapsulated TSTInfo")
    octets = one(content.children, 0x04, "encapsulated TSTInfo octets").value
    tst = one(der_nodes(octets), 0x30, "TSTInfo")
    fields = tst.children
    if len(fields) < 5 or der_integer(fields[0]) != 1:
        raise CheckError("malformed TSTInfo")
    algorithm, imprint = message_imprint(fields[2])
    nonce = next((der_integer(node) for node in fields[5:] if node.tag == 0x02), None)
    return {
        "policy": der_oid(fields[1]),
        "imprint_algorithm": algorithm,
        "imprint": imprint,
        "gen_time": parse_generalized_time(fields[4]),
        "nonce": nonce,
    }, signed_data


def parse_request(request: bytes) -> dict[str, Any]:
    root = one(der_nodes(request), 0x30, "TimeStampReq")
    fields = root.children
    if len(fields) < 2 or der_integer(fields[0]) != 1:
        raise CheckError("malformed TimeStampReq")
    algorithm, imprint = message_imprint(fields[1])
    nonce = next((der_integer(node) for node in fields[2:] if node.tag == 0x02), None)
    cert_req = next(
        (node.value != b"\x00" for node in fields[2:] if node.tag == 0x01), False
    )
    return {
        "imprint_algorithm": algorithm,
        "imprint": imprint,
        "nonce": nonce,
        "cert_req": cert_req,
    }


def walk(node: DerNode) -> list[DerNode]:
    result = [node]
    for child in node.children:
        result.extend(walk(child))
    return result


def run(command: list[str], label: str) -> bytes:
    completed = subprocess.run(
        command,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr[:16_384].decode("utf-8", "replace").strip()
        raise CheckError(f"{label} failed: {diagnostic}")
    return completed.stdout


def parse_evaluation_time(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CheckError("evaluation time must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise CheckError("evaluation time must include a UTC offset")
    return parsed.astimezone(dt.UTC)


def verify_timestamp(
    response: bytes,
    request: bytes | None,
    artifact: bytes,
    args: argparse.Namespace,
) -> dict[str, Any]:
    info, signed_data = parse_tst_response(response)
    digest = hashlib.sha256(artifact).digest()
    if info["imprint_algorithm"] != SHA256_OID or info["imprint"] != digest:
        raise CheckError("timestamp response has an incorrect SHA-256 artifact imprint")
    if info["policy"] != args.tsa_policy:
        raise CheckError("timestamp response policy OID is not accepted")
    if request is not None:
        query = parse_request(request)
        if (
            query["imprint_algorithm"] != SHA256_OID
            or query["imprint"] != digest
            or not query["cert_req"]
        ):
            raise CheckError("timestamp request profile or imprint is invalid")
        if query["nonce"] != info["nonce"]:
            raise CheckError("timestamp request and response nonce values differ")
    elif info["nonce"] is not None:
        raise CheckError("nonce-bearing response requires the exact timestamp request")
    evaluation = parse_evaluation_time(args.evaluation_time)
    if info["gen_time"] > evaluation + dt.timedelta(
        seconds=args.max_future_skew_seconds
    ):
        raise CheckError("TSTInfo genTime exceeds the configured future-skew bound")

    all_nodes = walk(signed_data)
    oids = [der_oid(node) for node in all_nodes if node.tag == 0x06]
    if oids.count(SIGNING_CERT_V2_OID) != 1 or LEGACY_SIGNING_CERT_OID in oids:
        raise CheckError(
            "CMS signed attributes violate SigningCertificateV2 restrictions"
        )
    attribute = next(
        node
        for node in all_nodes
        if node.tag == 0x30
        and node.children
        and node.children[0].tag == 0x06
        and der_oid(node.children[0]) == SIGNING_CERT_V2_OID
    )
    if (
        len(attribute.children) != 2
        or attribute.children[1].tag != 0x31
        or len(attribute.children[1].children) != 1
    ):
        raise CheckError(
            "SigningCertificateV2 must contain exactly one attribute value"
        )

    with tempfile.TemporaryDirectory(prefix="vtl-independent-tsa-") as temporary:
        root = Path(temporary)
        tsr = root / "response.tsr"
        segment = root / "segment.cbor"
        token = root / "token.der"
        signer = root / "signer.pem"
        trust = root / "trust-and-crls.pem"
        tsr.write_bytes(response)
        segment.write_bytes(artifact)
        trust.write_bytes(
            args.tsa_ca_file.read_bytes() + b"\n" + args.tsa_crls_file.read_bytes()
        )
        token.write_bytes(
            run(
                [args.openssl, "ts", "-reply", "-in", str(tsr), "-token_out"],
                "token extraction",
            )
        )
        run(
            [
                args.openssl,
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-in",
                str(token),
                "-binary",
                "-noverify",
                "-signer",
                str(signer),
                "-out",
                str(root / "content.bin"),
            ],
            "CMS signature verification",
        )
        signer_der = run(
            [args.openssl, "x509", "-in", str(signer), "-outform", "DER"],
            "signer DER extraction",
        )
        signer_digest = hashlib.sha256(signer_der).hexdigest()
        if signer_digest != args.tsa_signer_cert_sha256:
            raise CheckError(
                "selected TSA signer certificate does not match the configured pin"
            )
        text = run(
            [args.openssl, "x509", "-in", str(signer), "-text", "-noout"],
            "signer certificate inspection",
        ).decode("utf-8", "replace")
        eku = re.search(r"X509v3 Extended Key Usage: critical\s*\n\s*([^\n]+)", text)
        if not eku or eku.group(1).strip() not in {
            "Time Stamping",
            "1.3.6.1.5.5.7.3.8",
        }:
            raise CheckError(
                "TSA signer EKU is not one critical timeStamping-only extension"
            )
        verify_command = [
            args.openssl,
            "ts",
            "-verify",
            "-in",
            str(tsr),
            "-data",
            str(segment),
            "-CAfile",
            str(trust),
            "-purpose",
            "timestampsign",
            "-attime",
            str(int(info["gen_time"].timestamp())),
            "-crl_check_all",
            "-x509_strict",
        ]
        if args.tsa_intermediates_file:
            verify_command.extend(["-untrusted", str(args.tsa_intermediates_file)])
        run(verify_command, "RFC 3161 signature/path/revocation verification")
    return {
        "status": "verified",
        "policy": info["policy"],
        "gen_time": info["gen_time"].isoformat().replace("+00:00", "Z"),
        "signer_certificate_sha256": signer_digest,
        "nonce_checked": request is not None or info["nonce"] is not None,
    }


def tree(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(
        b"\x01" + tree(leaves[:split]) + tree(leaves[split:])
    ).digest()


def uint64_string(value: Any, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise CheckError(f"{label} is not a shortest uint64 decimal string")
    number = int(value)
    if number > (1 << 64) - 1:
        raise CheckError(f"{label} exceeds uint64")
    return number


def artifact_ref(value: Any) -> tuple[str, str]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise CheckError("invalid artifact reference shape")
    path = portable_path(value["path"])
    digest = value["sha256"]
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        raise CheckError("artifact reference digest is not lowercase SHA-256")
    return path, digest


def fetch_ref(http: HttpRetriever, value: Any, accept: str) -> bytes:
    path, expected = artifact_ref(value)
    data = http.get(path, accept)
    if hashlib.sha256(data).hexdigest() != expected:
        raise CheckError(f"artifact reference digest mismatch for {path}")
    return data


def uint64(value: Any, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or not (int(positive) <= value <= MAX_UINT64):
        raise CheckError(f"{label} is not a valid uint64")
    return value


def sha256_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise CheckError(f"{label} is not a 32-octet SHA-256 value")
    return value


def validate_record(data: bytes) -> None:
    # The outer record array is excluded from the payload depth limit.
    decoder = CborDecoder(data, MAX_CBOR_NESTING_DEPTH + 1)
    initial = decoder.take(1)[0]
    if initial >> 5 != 4 or decoder.argument(initial & 31) != 7:
        raise CheckError("record opening is not a version-one canonical record")
    decoder.items = 1  # Count the outer array without materializing it.
    version = decoder.item(1)
    if type(version) is not int or version != 1:
        raise CheckError("record opening is not a version-one canonical record")
    device_id = decoder.item(1)
    if not isinstance(device_id, bytes) or len(device_id) != 8:
        raise CheckError("canonical record device identifier is not eight octets")
    uint64(decoder.item(1), "canonical record fc")
    uint64(decoder.item(1), "canonical record ingest_time")
    device_time = decoder.item(1)
    if device_time is not None:
        uint64(device_time, "canonical record device_time")
    uint64(decoder.item(1), "canonical record kind")
    decoder.item(1, materialize=False)
    if decoder.offset != len(data):
        raise CheckError("trailing CBOR bytes")


def validate_segment(segment: Any) -> tuple[int, int, list[bytes]]:
    fields = {
        "version",
        "commitment_profile_id",
        "ledger_id",
        "segment_number",
        "closure_policy",
        "close_reason",
        "prev_segment_sha256",
        "record_count",
        "batch_roots",
        "segment_root",
    }
    if not isinstance(segment, dict) or set(segment) != fields:
        raise CheckError("segment artifact field set is invalid")
    if type(segment["version"]) is not int or segment["version"] != 1:
        raise CheckError("segment artifact version is invalid")
    if segment["commitment_profile_id"] != PROFILE_ID:
        raise CheckError("segment artifact commitment profile is invalid")
    if not isinstance(segment["ledger_id"], str) or not HEX32.fullmatch(
        segment["ledger_id"]
    ):
        raise CheckError("segment artifact ledger identifier is invalid")
    uint64(segment["segment_number"], "segment_number")
    sha256_bytes(segment["prev_segment_sha256"], "prev_segment_sha256")
    close_reason = segment["close_reason"]
    if not isinstance(close_reason, str) or close_reason not in {
        "interval",
        "reconfigure",
        "record_limit",
        "size_limit",
        "shutdown",
        "recovery",
        "manual",
    }:
        raise CheckError("segment close_reason is invalid")
    policy = segment["closure_policy"]
    if not isinstance(policy, dict) or set(policy) != {
        "version",
        "interval_ms",
        "batch_record_limit",
        "record_limit",
        "size_limit_bytes",
        "empty_mode",
    }:
        raise CheckError("segment closure_policy field set is invalid")
    if type(policy["version"]) is not int or policy["version"] != 1:
        raise CheckError("segment closure_policy version is invalid")
    uint64(policy["interval_ms"], "closure_policy.interval_ms", positive=True)
    batch_limit = uint64(
        policy["batch_record_limit"], "closure_policy.batch_record_limit", positive=True
    )
    if batch_limit > MAX_BATCH_RECORD_LIMIT or batch_limit & (batch_limit - 1):
        raise CheckError("segment batch limit is not a valid power of two")
    for name in ("record_limit", "size_limit_bytes"):
        if policy[name] is not None:
            uint64(policy[name], f"closure_policy.{name}", positive=True)
    if not isinstance(policy["empty_mode"], str) or policy["empty_mode"] not in {
        "emit",
        "suppress",
    }:
        raise CheckError("segment closure_policy.empty_mode is invalid")
    count = uint64(segment["record_count"], "record_count")
    roots = segment["batch_roots"]
    if not isinstance(roots, list):
        raise CheckError("segment batch_roots is not an array")
    for root in roots:
        sha256_bytes(root, "batch root")
    sha256_bytes(segment["segment_root"], "segment_root")
    expected_roots = 0 if count == 0 else 1 + (count - 1) // batch_limit
    if len(roots) != expected_roots:
        raise CheckError("segment batch-root cardinality is invalid")
    if (
        count == 0
        and policy["empty_mode"] != "emit"
        and close_reason not in {"shutdown", "recovery"}
    ):
        raise CheckError("empty segment closure policy is invalid")
    if tree(roots) != segment["segment_root"]:
        raise CheckError("batch-root composition does not reproduce segment_root")
    if segment["segment_number"] == 0 and segment["prev_segment_sha256"] != bytes(32):
        raise CheckError("epoch predecessor marker is nonzero")
    return count, batch_limit, roots


def verify_exchange(args: argparse.Namespace) -> dict[str, Any]:
    http = HttpRetriever(args.bundle_url, args.https_ca_file)
    manifest_bytes = http.get("segment.verify.json", "application/json")
    manifest = parse_json(manifest_bytes)
    required = {
        "version",
        "ledger_id",
        "segment_number",
        "commitment_profile_id",
        "disclosure_class",
        "artifacts",
        "anchoring",
    }
    if not required.issubset(manifest) or not set(manifest).issubset(
        required | {"extensions"}
    ):
        raise CheckError("producer manifest top-level shape is invalid")
    if manifest["version"] != 1 or not HEX32.fullmatch(str(manifest["ledger_id"])):
        raise CheckError("producer manifest version or ledger identifier is invalid")
    manifest_number = uint64_string(manifest["segment_number"], "segment_number")
    disclosure = manifest["disclosure_class"]
    if disclosure not in {"A", "B", "C"}:
        raise CheckError("unsupported disclosure class")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, dict) or "segment_cbor" not in artifacts:
        raise CheckError("producer manifest lacks segment_cbor")
    artifact = fetch_ref(http, artifacts["segment_cbor"], "application/cbor")
    artifact_digest = hashlib.sha256(artifact).hexdigest()
    if artifact_digest != args.expected_segment_sha256:
        raise CheckError(
            "segment digest differs from the independently provisioned digest"
        )
    segment = CborDecoder(artifact).decode()
    count, batch_limit, roots = validate_segment(segment)
    if (
        segment.get("commitment_profile_id") != PROFILE_ID
        or manifest["commitment_profile_id"] != PROFILE_ID
        or segment.get("ledger_id") != manifest["ledger_id"]
        or segment.get("segment_number") != manifest_number
    ):
        raise CheckError("segment/manifest identity or profile mismatch")
    if manifest_number == 0:
        if segment.get("prev_segment_sha256") != bytes(32):
            raise CheckError("epoch predecessor marker is nonzero")
        chain = "epoch"
    else:
        if "predecessor_segment_cbor" not in artifacts:
            raise CheckError("successor snapshot omits its immediate predecessor")
        predecessor_bytes = fetch_ref(
            http, artifacts["predecessor_segment_cbor"], "application/cbor"
        )
        predecessor = CborDecoder(predecessor_bytes).decode()
        validate_segment(predecessor)
        if (
            predecessor.get("ledger_id") != segment["ledger_id"]
            or predecessor.get("segment_number") != manifest_number - 1
            or predecessor.get("commitment_profile_id") != PROFILE_ID
            or hashlib.sha256(predecessor_bytes).digest()
            != segment.get("prev_segment_sha256")
        ):
            raise CheckError("predecessor continuity check failed")
        chain = "validated"

    openings = artifacts.get("record_batches", [])
    if not isinstance(openings, list):
        raise CheckError("record_batches is not an array")
    indexed: dict[int, Any] = {}
    for opening in openings:
        if not isinstance(opening, dict) or set(opening) != {"batch_number", "records"}:
            raise CheckError("record batch opening shape is invalid")
        number = uint64_string(opening["batch_number"], "batch_number")
        if (
            number in indexed
            or number >= len(roots)
            or not isinstance(opening["records"], list)
            or not opening["records"]
        ):
            raise CheckError("record batch opening number or cardinality is invalid")
        expected_count = (
            batch_limit if number + 1 < len(roots) else count - number * batch_limit
        )
        if len(opening["records"]) != expected_count:
            raise CheckError("record batch opening is incomplete")
        indexed[number] = opening
    if disclosure == "A" and (
        (count == 0 and openings)
        or (count > 0 and set(indexed) != set(range(len(roots))))
    ):
        raise CheckError("Class A does not open every complete batch")
    if disclosure == "B" and (len(roots) <= 1 or not 0 < len(indexed) < len(roots)):
        raise CheckError("Class B is not a non-empty proper batch subset")
    if disclosure == "C" and openings:
        raise CheckError("Class C must omit record openings")
    selected = set(args.batch)
    if args.scope == "public_recompute":
        if disclosure != "A":
            raise CheckError("public recomputation requires Class A")
        consumed = set(indexed)
    elif args.scope == "disclosed_batch_recompute":
        consumed = selected or set(indexed)
        if (
            len(roots) <= 1
            or not consumed
            or not consumed.issubset(indexed)
            or len(consumed) >= len(roots)
        ):
            raise CheckError(
                "selected batch scope is not a non-empty proper disclosed subset"
            )
        if disclosure == "B" and selected and selected != set(indexed):
            raise CheckError(
                "Class B invocation must consume its exact disclosed subset"
            )
    else:
        consumed = set()
    opened_leaves: dict[int, list[bytes]] = {}
    fetched_records = 0
    for number in sorted(consumed):
        leaves = []
        for reference in indexed[number]["records"]:
            record = fetch_ref(http, reference, "application/cbor")
            validate_record(record)
            leaves.append(hashlib.sha256(b"\x00" + record).digest())
            fetched_records += 1
        leaves.sort()
        if tree(leaves) != roots[number]:
            raise CheckError(f"batch {number} opening does not reproduce its root")
        opened_leaves[number] = leaves
    for left in sorted(opened_leaves):
        if (
            left + 1 in opened_leaves
            and opened_leaves[left][-1] > opened_leaves[left + 1][0]
        ):
            raise CheckError("adjacent disclosed batches violate global leaf ordering")
    if args.scope == "public_recompute":
        leaves = [
            leaf for number in sorted(opened_leaves) for leaf in opened_leaves[number]
        ]
        if len(leaves) != count or tree(leaves) != segment["segment_root"]:
            raise CheckError(
                "full record recomputation does not reproduce segment_root"
            )

    tsa_state = manifest.get("anchoring", {}).get("tsa", {}).get("status")
    if tsa_state == "present":
        if "tsa_tsr" not in artifacts:
            raise CheckError("present TSA state omits tsa_tsr")
        required_tsa_args(args)
        response = fetch_ref(http, artifacts["tsa_tsr"], "application/timestamp-reply")
        request = (
            fetch_ref(http, artifacts["tsa_req"], "application/timestamp-query")
            if "tsa_req" in artifacts
            else None
        )
        timestamp = verify_timestamp(response, request, artifact, args)
        overall = "success"
    elif tsa_state == "pending" and "tsa_tsr" not in artifacts:
        timestamp = {"status": "pending_claim", "reason": "producer_pending_claim"}
        overall = "incomplete"
    elif tsa_state == "unavailable" and "tsa_tsr" not in artifacts:
        timestamp = {"status": "missing", "reason": "timestamp issuance is unavailable"}
        overall = "failure"
    else:
        raise CheckError("producer TSA state and artifact shape are inconsistent")
    return {
        "ok": overall != "failure",
        "checker": "trackone-independent-https-acceptance-v1",
        "artifact_sha256": artifact_digest,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "claimed_disclosure_class": disclosure,
        "verification_scope": args.scope,
        "chain_status": chain,
        "channels": {"tsa": timestamp},
        "overall": overall,
        "network": {
            "requests": http.requests,
            "bytes": http.total_bytes,
            "records_fetched": fetched_records,
        },
        "checks_exercised": [
            "https_tls_1_3_server_authentication",
            "http_1_1_complete_200_identity_transfer",
            "component_wise_utf8_url_encoding",
            "manifest_shape_and_reference_digests",
            "independently_provisioned_segment_digest",
            "deterministic_cbor_and_commitment_profile",
            "batch_root_composition",
            "scope_selected_record_recomputation",
            "predecessor_continuity",
            "rfc3161_restricted_profile_when_present",
        ],
    }


def required_tsa_args(args: argparse.Namespace) -> None:
    missing = [
        name
        for name in (
            "tsa_ca_file",
            "tsa_crls_file",
            "tsa_policy",
            "tsa_signer_cert_sha256",
            "evaluation_time",
        )
        if getattr(args, name) is None
    ]
    if missing:
        raise CheckError(
            f"present timestamp evidence requires explicit inputs: {', '.join(missing)}"
        )
    if not HEX64.fullmatch(args.tsa_signer_cert_sha256):
        raise CheckError("TSA signer certificate pin is not lowercase SHA-256")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--bundle-url", required=True)
    result.add_argument("--expected-segment-sha256", required=True)
    result.add_argument("--https-ca-file", required=True, type=Path)
    result.add_argument(
        "--scope",
        required=True,
        choices=["public_recompute", "disclosed_batch_recompute", "anchor_only"],
    )
    result.add_argument("--batch", action="append", type=int, default=[])
    result.add_argument("--tsa-ca-file", type=Path)
    result.add_argument("--tsa-intermediates-file", type=Path)
    result.add_argument("--tsa-crls-file", type=Path)
    result.add_argument("--tsa-policy")
    result.add_argument("--tsa-signer-cert-sha256")
    result.add_argument("--evaluation-time")
    result.add_argument("--max-future-skew-seconds", type=int, default=0)
    result.add_argument("--openssl", default="openssl")
    result.add_argument("--output", type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if not HEX64.fullmatch(args.expected_segment_sha256):
            raise CheckError("expected segment digest is not lowercase SHA-256")
        if len(args.batch) != len(set(args.batch)) or any(
            number < 0 for number in args.batch
        ):
            raise CheckError("batch selections must be unique non-negative integers")
        if args.max_future_skew_seconds < 0:
            raise CheckError("future skew must be non-negative")
        report = verify_exchange(args)
        status = 0 if report["overall"] in {"success", "incomplete"} else 1
    except Exception as exc:  # noqa: BLE001 - every rejection must produce JSON
        report = {
            "ok": False,
            "checker": "trackone-independent-https-acceptance-v1",
            "overall": "rejected",
            "error": str(exc),
        }
        status = 1
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    (sys.stdout if status == 0 else sys.stderr).write(payload)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
