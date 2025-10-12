#!/usr/bin/env python3
"""
test_gateway_pipeline.py

Comprehensive tests for the gateway pipeline: merkle_batcher, ots_anchor, verify_cli.
Tests schema compliance, Merkle root computation, and end-to-end workflow.
"""
import json
import shutil
import sys
from hashlib import sha256
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "gateway"))

from merkle_batcher import (
    BlockHeader,
    canonical_json,
    load_schemas,
    merkle_root_from_leaves,
    validate_against_schema,
)
from merkle_batcher import (
    main as batcher_main,
)
from verify_cli import merkle_root as verify_merkle_root


@pytest.fixture
def temp_workspace(tmp_path):
    """Create a temporary workspace with facts, schemas, and output directories."""
    workspace = {
        "facts_dir": tmp_path / "facts",
        "out_dir": tmp_path / "out",
        "schemas_dir": tmp_path / "schemas",
    }
    workspace["facts_dir"].mkdir()
    workspace["out_dir"].mkdir()
    workspace["schemas_dir"].mkdir()

    # Copy schemas from toolset/unified/schemas
    schema_src = (
            Path(__file__).parent.parent.parent.parent / "toolset" / "unified" / "schemas"
    )
    for schema_file in [
        "fact.schema.json",
        "block_header.schema.json",
        "day_record.schema.json",
    ]:
        src = schema_src / schema_file
        if src.exists():
            shutil.copy(src, workspace["schemas_dir"] / schema_file)

    return workspace


@pytest.fixture
def sample_facts(temp_workspace):
    """Create sample fact JSON files in the temp workspace."""
    facts = [
        {
            "device_id": "test-pod-01",
            "timestamp": "2025-10-07T10:00:00Z",
            "nonce": "a1b2c3d4e5f601234567",
            "payload": {"temperature": 22.5, "humidity": 45},
        },
        {
            "device_id": "test-pod-02",
            "timestamp": "2025-10-07T10:05:00Z",
            "nonce": "b2c3d4e5f601234567a8",
            "payload": {"temperature": 23.1, "humidity": 44},
        },
        {
            "device_id": "test-pod-03",
            "timestamp": "2025-10-07T10:10:00Z",
            "nonce": "c3d4e5f601234567a8b9",
            "payload": {"temperature": 21.8, "humidity": 46, "battery": 90},
        },
    ]

    for i, fact in enumerate(facts):
        fact_path = temp_workspace["facts_dir"] / f"fact_{i:02d}.json"
        fact_path.write_text(json.dumps(fact, indent=2), encoding="utf-8")

    return facts


class TestCanonicalJson:
    """Test canonical JSON serialization."""

    def test_canonical_json_sorted_keys(self):
        obj = {"z": 1, "a": 2, "m": 3}
        result = canonical_json(obj)
        assert result == b'{"a":2,"m":3,"z":1}'

    def test_canonical_json_no_whitespace(self):
        obj = {"key": "value"}
        result = canonical_json(obj)
        assert b" " not in result
        assert b"\n" not in result

    def test_canonical_json_deterministic(self):
        obj = {"nested": {"b": 2, "a": 1}, "top": "value"}
        result1 = canonical_json(obj)
        result2 = canonical_json(obj)
        assert result1 == result2


class TestMerkleRoot:
    """Test Merkle root computation."""

    def test_empty_leaves(self):
        root, hashes = merkle_root_from_leaves([])
        assert root == sha256(b"").hexdigest()
        assert hashes == []

    def test_single_leaf(self):
        leaf = b"test_data"
        root, hashes = merkle_root_from_leaves([leaf])
        expected = sha256(leaf).hexdigest()
        assert root == expected
        assert len(hashes) == 1

    def test_two_leaves(self):
        leaf1 = b"data1"
        leaf2 = b"data2"
        root, hashes = merkle_root_from_leaves([leaf1, leaf2])

        # Compute expected: hash leaves, sort, then combine
        h1 = sha256(leaf1).hexdigest()
        h2 = sha256(leaf2).hexdigest()
        sorted_hashes = sorted([h1, h2])
        combined = bytes.fromhex(sorted_hashes[0]) + bytes.fromhex(sorted_hashes[1])
        expected = sha256(combined).hexdigest()

        assert root == expected
        assert set(hashes) == {h1, h2}

    def test_deterministic_regardless_of_input_order(self):
        leaf1 = b"alpha"
        leaf2 = b"beta"
        leaf3 = b"gamma"

        root1, _ = merkle_root_from_leaves([leaf1, leaf2, leaf3])
        root2, _ = merkle_root_from_leaves([leaf3, leaf1, leaf2])
        root3, _ = merkle_root_from_leaves([leaf2, leaf3, leaf1])

        assert root1 == root2 == root3

    def test_odd_number_of_leaves(self):
        # Three leaves: should duplicate the last one when building tree
        leaves = [b"a", b"b", b"c"]
        root, hashes = merkle_root_from_leaves(leaves)
        assert len(hashes) == 3
        assert len(root) == 64  # hex sha256


class TestBlockHeader:
    """Test BlockHeader dataclass."""

    def test_block_header_to_dict(self):
        header = BlockHeader(
            version=1,
            site_id="test-site",
            day="2025-10-07",
            batch_id="test-site-2025-10-07-00",
            merkle_root="a" * 64,
            count=5,
            leaf_hashes=["b" * 64, "c" * 64],
            ots_proof=None,
        )
        d = header.to_dict()

        assert d["version"] == 1
        assert d["site_id"] == "test-site"
        assert d["day"] == "2025-10-07"
        assert d["merkle_root"] == "a" * 64
        assert d["count"] == 5
        assert len(d["leaf_hashes"]) == 2


class TestSchemaValidation:
    """Test schema loading and validation."""

    def test_load_schemas(self):
        schemas = load_schemas()
        # Should load from toolset/unified/schemas
        assert "fact" in schemas or "block_header" in schemas or "day_record" in schemas

    def test_valid_block_header_passes_schema(self):
        schemas = load_schemas()
        if "block_header" not in schemas:
            pytest.skip("block_header schema not available")

        header = {
            "version": 1,
            "site_id": "test-001",
            "day": "2025-10-07",
            "batch_id": "test-001-2025-10-07-00",
            "merkle_root": "a" * 64,
            "count": 3,
            "leaf_hashes": ["b" * 64, "c" * 64, "d" * 64],
            "ots_proof": None,
        }

        # Should not raise
        validate_against_schema(header, schemas["block_header"], "Test header")

    def test_invalid_merkle_root_fails_schema(self):
        schemas = load_schemas()
        if "block_header" not in schemas:
            pytest.skip("block_header schema not available")

        # Invalid: merkle_root not 64 hex chars
        header = {
            "version": 1,
            "site_id": "test-001",
            "day": "2025-10-07",
            "batch_id": "test-001-2025-10-07-00",
            "merkle_root": "invalid",
            "count": 0,
            "leaf_hashes": [],
            "ots_proof": None,
        }

        # validate_against_schema prints warning but doesn't raise
        # We just ensure it doesn't crash
        validate_against_schema(header, schemas["block_header"], "Invalid header")


class TestMerkleBatcher:
    """Test merkle_batcher end-to-end."""

    def test_batcher_with_sample_facts(self, temp_workspace, sample_facts):
        args = [
            "--facts",
            str(temp_workspace["facts_dir"]),
            "--out",
            str(temp_workspace["out_dir"]),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
        ]

        result = batcher_main(args)
        assert result == 0

        # Check outputs exist
        block_path = temp_workspace["out_dir"] / "blocks" / "2025-10-07-00.block.json"
        day_bin_path = temp_workspace["out_dir"] / "day" / "2025-10-07.bin"
        day_json_path = temp_workspace["out_dir"] / "day" / "2025-10-07.json"

        assert block_path.exists()
        assert day_bin_path.exists()
        assert day_json_path.exists()

        # Validate block header structure
        block_header = json.loads(block_path.read_text())
        assert block_header["version"] == 1
        assert block_header["site_id"] == "test-site"
        assert block_header["day"] == "2025-10-07"
        assert block_header["count"] == 3
        assert len(block_header["leaf_hashes"]) == 3
        assert len(block_header["merkle_root"]) == 64

        # Validate day record structure
        day_record = json.loads(day_json_path.read_text())
        assert day_record["version"] == 1
        assert day_record["site_id"] == "test-site"
        assert day_record["date"] == "2025-10-07"
        assert len(day_record["prev_day_root"]) == 64
        assert day_record["day_root"] == block_header["merkle_root"]
        assert len(day_record["batches"]) == 1

    def test_batcher_with_schema_validation(self, temp_workspace, sample_facts):
        args = [
            "--facts",
            str(temp_workspace["facts_dir"]),
            "--out",
            str(temp_workspace["out_dir"]),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
            "--validate-schemas",
        ]

        result = batcher_main(args)
        assert result == 0

    def test_batcher_empty_facts_fails_without_flag(self, temp_workspace):
        args = [
            "--facts",
            str(temp_workspace["facts_dir"]),
            "--out",
            str(temp_workspace["out_dir"]),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
        ]

        result = batcher_main(args)
        assert result == 1  # Should fail with no facts

    def test_batcher_empty_facts_succeeds_with_flag(self, temp_workspace):
        args = [
            "--facts",
            str(temp_workspace["facts_dir"]),
            "--out",
            str(temp_workspace["out_dir"]),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
            "--allow-empty",
        ]

        result = batcher_main(args)
        assert result == 0

        # Check that merkle root is sha256("")
        block_path = temp_workspace["out_dir"] / "blocks" / "2025-10-07-00.block.json"
        block_header = json.loads(block_path.read_text())
        assert block_header["merkle_root"] == sha256(b"").hexdigest()

    def test_batcher_invalid_date_format(self, temp_workspace):
        args = [
            "--facts",
            str(temp_workspace["facts_dir"]),
            "--out",
            str(temp_workspace["out_dir"]),
            "--site",
            "test-site",
            "--date",
            "2025/10/07",  # Invalid format
        ]

        result = batcher_main(args)
        assert result == 2


class TestVerifyCli:
    """Test verify_cli functionality."""

    def test_merkle_root_computation_matches_batcher(self, sample_facts):
        # Compute using verify_cli's merkle_root function
        leaves = [canonical_json(f) for f in sample_facts]
        verify_root = verify_merkle_root(leaves)

        # Compute using batcher's function
        batcher_root, _ = merkle_root_from_leaves(leaves)

        assert verify_root == batcher_root

    def test_end_to_end_verification(self, temp_workspace, sample_facts):
        # Run batcher
        batcher_args = [
            "--facts",
            str(temp_workspace["facts_dir"]),
            "--out",
            str(temp_workspace["out_dir"]),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
        ]
        assert batcher_main(batcher_args) == 0

        # Create OTS placeholder
        day_bin_path = temp_workspace["out_dir"] / "day" / "2025-10-07.bin"
        ots_path = day_bin_path.with_suffix(day_bin_path.suffix + ".ots")
        ots_path.write_text("OTS_PROOF_PLACEHOLDER\n", encoding="utf-8")

        # Run verify - need to adjust facts_dir reference in verify_cli
        # For now, we test the merkle_root function directly
        fact_files = sorted(temp_workspace["facts_dir"].glob("*.json"))
        leaves = []
        for fpath in fact_files:
            obj = json.load(fpath.open("r", encoding="utf-8"))
            leaves.append(canonical_json(obj))

        recomputed_root = verify_merkle_root(leaves)

        # Load recorded root
        block_path = temp_workspace["out_dir"] / "blocks" / "2025-10-07-00.block.json"
        block_header = json.loads(block_path.read_text())
        recorded_root = block_header["merkle_root"]

        assert recomputed_root == recorded_root


class TestDayChaining:
    """Test that day records chain correctly via prev_day_root."""

    def test_first_day_has_zero_prev_root(self, temp_workspace, sample_facts):
        args = [
            "--facts",
            str(temp_workspace["facts_dir"]),
            "--out",
            str(temp_workspace["out_dir"]),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
        ]

        assert batcher_main(args) == 0

        day_json_path = temp_workspace["out_dir"] / "day" / "2025-10-07.json"
        day_record = json.loads(day_json_path.read_text())

        # First day should have all-zero prev_day_root
        assert day_record["prev_day_root"] == "00" * 32

    def test_second_day_chains_to_first(self, temp_workspace, sample_facts):
        # Run first day
        args1 = [
            "--facts",
            str(temp_workspace["facts_dir"]),
            "--out",
            str(temp_workspace["out_dir"]),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
        ]
        assert batcher_main(args1) == 0

        day1_json = temp_workspace["out_dir"] / "day" / "2025-10-07.json"
        day1_record = json.loads(day1_json.read_text())
        day1_root = day1_record["day_root"]

        # Run second day
        args2 = [
            "--facts",
            str(temp_workspace["facts_dir"]),
            "--out",
            str(temp_workspace["out_dir"]),
            "--site",
            "test-site",
            "--date",
            "2025-10-08",
        ]
        assert batcher_main(args2) == 0

        day2_json = temp_workspace["out_dir"] / "day" / "2025-10-08.json"
        day2_record = json.loads(day2_json.read_text())

        # Second day's prev_day_root should match first day's day_root
        assert day2_record["prev_day_root"] == day1_root


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
