"""Unit tests for JSON OTS proof scanner (scripts/lint/scan_embedded_proofs.py)"""
import sys
import tempfile
import textwrap
from pathlib import Path

# Ensure scripts/lint is importable before importing the scanner
try:
    scanner = __import__("scan_embedded_proofs")
except ModuleNotFoundError:
    ROOT = Path(__file__).resolve().parents[3]
    lint_path = str(ROOT / "scripts" / "lint")
    if lint_path not in sys.path:
        sys.path.insert(0, lint_path)
    scanner = __import__("scan_embedded_proofs")


def _write_json(tmp: Path, name: str, content: str) -> Path:
    """Write a JSON file with the given content"""
    p = tmp / name
    p.write_text(textwrap.dedent(content).strip(), encoding="utf8")
    return p


def test_detect_suspicious_key_with_large_string():
    """Detect suspicious key names with large string values"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write_json(
            tmp,
            "test.json",
            """
            {
                "data": "normal",
                "ots_proof": "x" * 300
            }
            """.replace(
                '"x" * 300', '"' + "x" * 300 + '"'
            ),
        )
        issues = scanner.scan_file(f, min_blob_len=256, report_key_names=False)
        assert len(issues) > 0
        assert any("suspicious key 'ots_proof'" in issue for issue in issues)


def test_detect_suspicious_key_with_byte_array():
    """Detect suspicious key names with large byte-array-like lists"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        content = """
        {
            "data": "normal",
            "proof_data": [0, 1, 2, 3, 4, 5]
        }
        """
        # Create a large byte array
        byte_array = list(range(256)) + list(range(50))
        content = content.replace("[0, 1, 2, 3, 4, 5]", str(byte_array))
        f = _write_json(tmp, "test.json", content)
        issues = scanner.scan_file(f, min_blob_len=256, report_key_names=False)
        assert len(issues) > 0
        assert any("byte-array-like list" in issue for issue in issues)


def test_detect_ots_magic_header_base64():
    """Detect OTS magic header in base64 encoding"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # Include the base64 OTS magic pattern
        large_string = "x" * 200 + "AE9wZW5UaW1lc3RhbXBz" + "y" * 100
        f = _write_json(
            tmp,
            "test.json",
            f'{{"data": "{large_string}"}}',
        )
        issues = scanner.scan_file(f, min_blob_len=256, report_key_names=False)
        assert len(issues) > 0
        assert any("OTS magic header" in issue for issue in issues)


def test_detect_ots_magic_header_hex():
    """Detect OTS magic header in hex encoding"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # Include the hex OTS magic pattern
        large_string = "x" * 200 + "004f70656e54696d657374616d7073" + "y" * 100
        f = _write_json(
            tmp,
            "test.json",
            f'{{"data": "{large_string}"}}',
        )
        issues = scanner.scan_file(f, min_blob_len=256, report_key_names=False)
        assert len(issues) > 0
        assert any("OTS magic header" in issue for issue in issues)


def test_report_key_names_without_blob():
    """Report suspicious key names even without blob-like values when flag is set"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write_json(
            tmp,
            "test.json",
            """
            {
                "ots_proof": "short"
            }
            """,
        )
        issues = scanner.scan_file(f, min_blob_len=256, report_key_names=True)
        assert len(issues) > 0
        assert any("suspicious key 'ots_proof'" in issue for issue in issues)


def test_no_report_key_names_without_blob_when_disabled():
    """Don't report suspicious key names without blob-like values when flag is off"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write_json(
            tmp,
            "test.json",
            """
            {
                "ots_proof": "short"
            }
            """,
        )
        issues = scanner.scan_file(f, min_blob_len=256, report_key_names=False)
        assert len(issues) == 0


def test_nested_suspicious_keys():
    """Detect suspicious keys in nested objects"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write_json(
            tmp,
            "test.json",
            """
            {
                "outer": {
                    "inner": {
                        "proof_value": "x" * 300
                    }
                }
            }
            """.replace(
                '"x" * 300', '"' + "x" * 300 + '"'
            ),
        )
        issues = scanner.scan_file(f, min_blob_len=256, report_key_names=False)
        assert len(issues) > 0
        assert any("outer.inner.proof_value" in issue for issue in issues)


def test_clean_json_no_issues():
    """Clean JSON without suspicious content should not trigger"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write_json(
            tmp,
            "test.json",
            """
            {
                "name": "test",
                "value": 42,
                "data": "normal string"
            }
            """,
        )
        issues = scanner.scan_file(f, min_blob_len=256, report_key_names=False)
        assert len(issues) == 0


def test_min_blob_len_threshold():
    """Test that min_blob_len threshold is respected"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # String of length 100
        string_val = "x" * 100
        f = _write_json(
            tmp,
            "test.json",
            f'{{"ots_data": "{string_val}"}}',
        )
        # Should not trigger with min_blob_len=256
        issues = scanner.scan_file(f, min_blob_len=256, report_key_names=False)
        assert len(issues) == 0

        # Should trigger with min_blob_len=50
        issues = scanner.scan_file(f, min_blob_len=50, report_key_names=False)
        assert len(issues) > 0


def test_invalid_json_handling():
    """Test that invalid JSON is handled gracefully"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = tmp / "invalid.json"
        f.write_text("{ invalid json }", encoding="utf8")
        issues = scanner.scan_file(f, min_blob_len=256, report_key_names=False)
        assert len(issues) == 1
        assert "failed to parse JSON" in issues[0]


def test_case_insensitive_key_matching():
    """Test that suspicious key detection is case-insensitive"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        large_val = "x" * 300
        f = _write_json(
            tmp,
            "test.json",
            """
            {
                "OTS_PROOF": "LARGE_VALUE_1",
                "Proof_Data": "LARGE_VALUE_2"
            }
            """.replace("LARGE_VALUE_1", large_val).replace("LARGE_VALUE_2", large_val),
        )
        issues = scanner.scan_file(f, min_blob_len=256, report_key_names=False)
        assert len(issues) >= 2
        assert any("OTS_PROOF" in issue for issue in issues)
        assert any("Proof_Data" in issue for issue in issues)


def test_iter_json_files_excludes_dirs():
    """Test that iter_json_files respects excluded directories"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # Create structure with proofs directory
        proofs_dir = tmp / "proofs"
        proofs_dir.mkdir()
        data_dir = tmp / "data"
        data_dir.mkdir()

        (proofs_dir / "test1.json").write_text("{}", encoding="utf8")
        (data_dir / "test2.json").write_text("{}", encoding="utf8")

        files = list(scanner.iter_json_files(tmp, excluded_dirs={"proofs"}))
        paths = [f.name for f in files]

        assert "test2.json" in paths
        assert "test1.json" not in paths


def test_main_skips_non_json_files():
    """Test that main() skips non-JSON files with warning"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        txt_file = tmp / "test.txt"
        txt_file.write_text("not json", encoding="utf8")

        # Run main with the text file
        import io
        import contextlib

        stderr_capture = io.StringIO()
        with contextlib.redirect_stderr(stderr_capture):
            sys.argv = ["scan_embedded_proofs.py", str(txt_file)]
            result = scanner.main()

        stderr_output = stderr_capture.getvalue()
        assert "not a JSON file" in stderr_output
        assert result == 0  # Should succeed (no issues)


def test_main_with_json_file():
    """Test that main() processes JSON files correctly"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        json_file = _write_json(
            tmp,
            "test.json",
            """
            {
                "data": "value"
            }
            """,
        )

        sys.argv = ["scan_embedded_proofs.py", str(json_file)]
        result = scanner.main()
        assert result == 0  # Clean file should return 0


def test_main_detects_issues():
    """Test that main() detects and reports issues"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        large_val = "x" * 300
        json_file = _write_json(
            tmp,
            "test.json",
            """
            {
                "ots_proof": "LARGE_VALUE"
            }
            """.replace("LARGE_VALUE", large_val),
        )

        sys.argv = ["scan_embedded_proofs.py", str(json_file)]
        result = scanner.main()
        assert result == 1  # Issues found should return 1


def test_suspicious_key_pattern_underscore():
    """Test that keys with underscores like my_ots_data are detected"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        large_val = "x" * 300
        f = _write_json(
            tmp,
            "test.json",
            """
            {
                "my_ots_data": "LARGE_VALUE"
            }
            """.replace("LARGE_VALUE", large_val),
        )
        issues = scanner.scan_file(f, min_blob_len=256, report_key_names=False)
        assert len(issues) > 0
        assert any("my_ots_data" in issue for issue in issues)
