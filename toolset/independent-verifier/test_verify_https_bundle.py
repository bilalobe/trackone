"""Draft -13 record and segment rejection cases for the independent checker."""

from __future__ import annotations

import copy
import hashlib
import json
import socket
import threading
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

from verify_https_bundle import (
    CborDecoder,
    CheckError,
    DeadlineHTTPSConnection,
    HttpRetriever,
    validate_record,
    validate_segment,
)

VECTOR = (
    Path(__file__).resolve().parents[2] / "toolset/vectors/vtl-known-answer/vector.json"
)


class HttpsBundleSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vector = json.loads(VECTOR.read_text(encoding="utf-8"))

    def test_known_answer_records_and_segment(self) -> None:
        for encoded in self.vector["records_cbor_hex"]:
            validate_record(bytes.fromhex(encoded))
        for case in self.vector["distinct_encoding_cases"]:
            validate_record(bytes.fromhex(case["record_cbor_hex"]))
        segment = CborDecoder(bytes.fromhex(self.vector["segment_cbor_hex"])).decode()
        self.assertEqual(validate_segment(segment)[:2], (3, 2))
        empty = CborDecoder(
            bytes.fromhex(self.vector["empty_shutdown_suppress"]["segment_cbor_hex"])
        ).decode()
        self.assertEqual(validate_segment(empty)[:2], (0, 2))

    def test_record_field_types_and_canonical_float(self) -> None:
        valid = bytes.fromhex(self.vector["records_cbor_hex"][0])
        for index, replacement in ((1, 0xF5), (11, 0xF5), (13, 0xF5), (14, 0xF5)):
            with self.subTest(index=index), self.assertRaises(CheckError):
                validate_record(
                    valid[:index] + bytes([replacement]) + valid[index + 1 :]
                )
        with self.assertRaisesRegex(CheckError, "shortest exact width"):
            validate_record(valid[:-1] + bytes.fromhex("fa3f800000"))

    def test_large_record_payload_is_scanned_without_a_list(self) -> None:
        # 200,000 one-byte items would create a correspondingly large Python list
        # in the old decoder. The record validator only needs to scan them.
        prefix = bytes.fromhex(self.vector["records_cbor_hex"][0])[:-1]
        validate_record(prefix + b"\x9a\x00\x03\x0d\x40" + b"\x00" * 200_000)

    def test_skipped_payload_still_enforces_canonical_cbor_and_item_budget(self) -> None:
        prefix = bytes.fromhex(self.vector["records_cbor_hex"][0])[:-1]
        for payload in (b"\xa2\x61a\x00\x61a\x01", b"\x61\xff", b"\xfa\x3f\x80\x00\x00"):
            with self.subTest(payload=payload), self.assertRaises(CheckError):
                validate_record(prefix + payload)
        with self.assertRaisesRegex(CheckError, "item count"):
            validate_record(prefix + b"\x9a\x00\x0f\x42\x40" + b"\x00" * 1_000_000)

    def test_https_fetch_deadline_interrupts_a_blocked_body_read(self) -> None:
        class StalledResponse:
            version = 11
            status = 200

            def __init__(self, connection):
                self.connection = connection

            def getheader(self, _name):
                return None

            def read(self, _count):
                return self.connection.sock.recv(1)

        class StalledConnection:
            def __init__(self, *_args, **_kwargs):
                self.sock, self.peer = socket.socketpair()

            def request(self, *_args, **_kwargs):
                pass

            def getresponse(self):
                return StalledResponse(self)

            def close(self):
                self.sock.close()
                self.peer.close()

        retriever = HttpRetriever.__new__(HttpRetriever)
        retriever.parsed = urlsplit("https://example.test/bundle/")
        retriever.requests = 0
        retriever.total_bytes = 0
        retriever.retries = 0
        retriever.timeout = 15.0
        retriever.context = None
        with (
            mock.patch("verify_https_bundle.FETCH_DEADLINE_SECONDS", 0.05),
            mock.patch("verify_https_bundle.DeadlineHTTPSConnection", StalledConnection),
            self.assertRaisesRegex(CheckError, "fetch deadline exceeded"),
        ):
            retriever.get("segment.cbor", "application/cbor")

    def test_https_fetch_deadline_bounds_stalled_dns(self) -> None:
        started = threading.Event()
        release = threading.Event()
        finished = threading.Event()

        def stalled_dns(*_args):
            started.set()
            release.wait(2.0)
            finished.set()
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

        retriever = HttpRetriever.__new__(HttpRetriever)
        retriever.parsed = urlsplit("https://example.test/bundle/")
        retriever.requests = 0
        retriever.total_bytes = 0
        retriever.retries = 2
        retriever.timeout = 15.0
        retriever.context = mock.Mock()
        with (
            mock.patch("verify_https_bundle.FETCH_DEADLINE_SECONDS", 0.05),
            mock.patch("verify_https_bundle.socket.getaddrinfo", side_effect=stalled_dns),
            mock.patch("verify_https_bundle.socket.socket") as create_socket,
        ):
            try:
                before = time.monotonic()
                with self.assertRaisesRegex(CheckError, "fetch deadline exceeded"):
                    retriever.get("segment.cbor", "application/cbor")
                self.assertLess(time.monotonic() - before, 0.25)
                self.assertTrue(started.is_set())
                self.assertFalse(finished.is_set())
                create_socket.assert_not_called()
            finally:
                release.set()
                self.assertTrue(finished.wait(1.0))
            create_socket.assert_not_called()

    def test_connection_addresses_share_the_remaining_deadline(self) -> None:
        now = [0.0]
        sockets = [mock.Mock(), mock.Mock()]

        def fail_connect(_address):
            now[0] += 0.03
            raise socket.timeout("connection timed out")

        for candidate in sockets:
            candidate.connect.side_effect = fail_connect
        addresses = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
        ] * 3
        connection = DeadlineHTTPSConnection("example.test", deadline=0.05, timeout=15.0)
        with (
            mock.patch("verify_https_bundle.time.monotonic", side_effect=lambda: now[0]),
            mock.patch("verify_https_bundle.socket.getaddrinfo", return_value=addresses),
            mock.patch("verify_https_bundle.socket.socket", side_effect=sockets) as create_socket,
            self.assertRaisesRegex(CheckError, "fetch deadline exceeded"),
        ):
            connection.connect()
        self.assertEqual(create_socket.call_count, 2)
        sockets[0].settimeout.assert_called_once_with(0.05)
        self.assertAlmostEqual(sockets[1].settimeout.call_args.args[0], 0.02)
        for candidate in sockets:
            candidate.close.assert_called_once()

    def test_tls_handshake_uses_remaining_connection_deadline(self) -> None:
        now = [0.0]
        tcp_socket = mock.Mock()
        tls_socket = mock.Mock()
        connection = DeadlineHTTPSConnection("example.test", deadline=0.05, timeout=15.0)
        connection._context = mock.Mock()
        connection._context.wrap_socket.return_value = tls_socket

        def connected(_address):
            now[0] = 0.03

        def handshake():
            now[0] = 0.06

        tcp_socket.connect.side_effect = connected
        tls_socket.do_handshake.side_effect = handshake
        with (
            mock.patch("verify_https_bundle.time.monotonic", side_effect=lambda: now[0]),
            mock.patch("verify_https_bundle.socket.getaddrinfo", return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
            ]),
            mock.patch("verify_https_bundle.socket.socket", return_value=tcp_socket),
            self.assertRaisesRegex(CheckError, "fetch deadline exceeded"),
        ):
            try:
                connection.connect()
            finally:
                connection.close()
        self.assertAlmostEqual(tls_socket.settimeout.call_args.args[0], 0.02)
        connection._context.wrap_socket.assert_called_once_with(
            tcp_socket, server_hostname="example.test", do_handshake_on_connect=False
        )
        tls_socket.close.assert_called_once()

    def test_draft_13_baseline_record_envelope(self) -> None:
        cases = json.loads(
            (
                Path(__file__).resolve().parents[2]
                / "toolset/vectors/vtl-interoperability/cases.json"
            ).read_text(encoding="utf-8")
        )
        case = cases["canonical_record_acceptance_cases"][0]
        construction = case["construction"]
        record = (
            bytes.fromhex(construction["record_prefix_hex"])
            + bytes.fromhex(construction["repeated_array_head_hex"])
            * construction["repeat_count"]
            + b"\x59"
            + construction["innermost_bstr_length"].to_bytes(2, "big")
            + bytes.fromhex(construction["fill_octet_hex"])
            * construction["innermost_bstr_length"]
        )
        self.assertEqual(len(record), case["expected_encoded_length"])
        self.assertEqual(
            hashlib.sha256(b"\x00" + record).hexdigest(), case["expected_leaf_hash"]
        )
        validate_record(record)

    def test_segment_field_set_policy_and_empty_invariant(self) -> None:
        valid = CborDecoder(bytes.fromhex(self.vector["segment_cbor_hex"])).decode()
        bad_values = [
            ("interval_ms", 0),
            ("batch_record_limit", 1 << 64),
            ("record_limit", 0),
            ("size_limit_bytes", False),
            ("empty_mode", "unknown"),
            ("version", True),
        ]
        for field, value in bad_values:
            with self.subTest(field=field), self.assertRaises(CheckError):
                candidate = copy.deepcopy(valid)
                candidate["closure_policy"][field] = value
                validate_segment(candidate)
        for change in (
            lambda segment: segment.update(extra=1),
            lambda segment: segment["closure_policy"].update(extra=1),
            lambda segment: segment.update(close_reason="unknown"),
            lambda segment: segment.update(prev_segment_sha256=b"short"),
        ):
            with self.subTest(change=change), self.assertRaises(CheckError):
                candidate = copy.deepcopy(valid)
                change(candidate)
                validate_segment(candidate)
        empty = CborDecoder(
            bytes.fromhex(self.vector["empty_shutdown_suppress"]["segment_cbor_hex"])
        ).decode()
        empty["close_reason"] = "interval"
        with self.assertRaises(CheckError):
            validate_segment(empty)


if __name__ == "__main__":
    unittest.main()
