"""Transport and materialization checks with no gateway runtime imports."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

from verify_https_bundle import CheckError, HttpRetriever, download_bundle

FIXTURES = Path(__file__).resolve().parents[1] / "vectors/vtl-http-binding"


class DisclosureClientTests(unittest.TestCase):
    def test_exact_bound_download_and_no_overwrite(self):
        for cls in "abc":
            with self.subTest(cls=cls), tempfile.TemporaryDirectory() as tmp:
                source = FIXTURES / ("class-" + cls)
                manifest = (source / "segment.verify.json").read_bytes()
                http = mock.Mock()
                http.get.side_effect = lambda path, _accept, source=source: (
                    source / path
                ).read_bytes()
                output = Path(tmp) / "bundle"
                download_bundle(http, manifest, json.loads(manifest), output)
                for path in source.rglob("*"):
                    if path.is_file():
                        self.assertEqual(
                            path.read_bytes(),
                            (output / path.relative_to(source)).read_bytes(),
                        )
                with self.assertRaises(FileExistsError):
                    download_bundle(http, manifest, json.loads(manifest), output)

    def test_substitution_and_path_escape_fail_before_writes(self):
        manifest_bytes = (FIXTURES / "class-a/segment.verify.json").read_bytes()
        for path in (None, "../outside", "/absolute", "segment.verify.json"):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as tmp:
                manifest = json.loads(manifest_bytes)
                if path:
                    manifest["artifacts"]["segment_cbor"]["path"] = path
                http = mock.Mock()
                http.get.return_value = b"substituted"
                output = Path(tmp) / "bundle"
                with self.assertRaises(CheckError):
                    download_bundle(http, manifest_bytes, manifest, output)
                self.assertFalse(output.exists())

    def test_redirect_does_not_forward_credential(self):
        retriever = HttpRetriever.__new__(HttpRetriever)
        retriever.parsed = urlsplit("https://example.test/bundle/")
        retriever.requests = retriever.total_bytes = retriever.retries = 0
        retriever.timeout = 15
        retriever.context = None
        retriever.bearer_token = "test-disclosure-credential-0000000000"
        response = mock.Mock(version=11, status=302)
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with (
            mock.patch(
                "verify_https_bundle.DeadlineHTTPSConnection", return_value=connection
            ) as factory,
            self.assertRaisesRegex(CheckError, "got 302"),
        ):
            retriever.get("segment.cbor", "application/cbor")
        factory.assert_called_once()
        connection.request.assert_called_once()
        self.assertEqual(
            connection.request.call_args.kwargs["headers"]["Authorization"],
            "Bearer " + retriever.bearer_token,
        )

    def test_fixture_response_digests(self):
        for exchange in json.loads((FIXTURES / "exchanges.json").read_text()):
            response = exchange["response"]
            if "body_file" in response:
                body = (FIXTURES / response["body_file"]).read_bytes()
                self.assertEqual(
                    response["headers"]["ETag"],
                    '"' + hashlib.sha256(body).hexdigest() + '"',
                )
