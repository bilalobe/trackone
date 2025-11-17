from __future__ import annotations

import base64
import json

import pytest


def test_load_device_table_version_mismatch(
    tmp_path, frame_verifier, write_device_table
):
    """If device table _meta.version != '1.0', load_device_table should raise ValueError."""
    dt_path = tmp_path / "device_table.json"
    write_device_table(dt_path, {"_meta": {"version": "2.0"}}, indent=None)

    with pytest.raises(ValueError):
        frame_verifier.load_device_table(dt_path)


def test_save_and_load_device_table_roundtrip(tmp_path, frame_verifier):
    """save_device_table should persist table and load_device_table should read it back.

    Construct a schema-valid device table: _meta.master_seed must be base64 string and
    each device entry needs 'salt8' and 'ck_up' base64 fields. This ensures
    jsonschema validation inside load_device_table succeeds in the test environment.
    """
    dt_path = tmp_path / "device_table.json"

    # Build valid base64-encoded fields
    master_seed = base64.b64encode(b"m" * 32).decode("ascii")
    salt8 = base64.b64encode(b"s" * 8).decode("ascii")
    ck_up = base64.b64encode(b"k" * 32).decode("ascii")

    tbl = {
        "_meta": {"version": "1.0", "master_seed": master_seed},
        "3": {"salt8": salt8, "ck_up": ck_up, "highest_fc_seen": 10},
    }
    frame_verifier.save_device_table(dt_path, tbl)

    loaded = frame_verifier.load_device_table(dt_path)
    assert "3" in loaded
    assert loaded["3"]["highest_fc_seen"] == 10


def test_parse_frame_error_cases(frame_verifier):
    # invalid JSON
    frame, err = frame_verifier.parse_frame("not-json")
    assert frame is None and err == "invalid_json"

    # not a dict
    frame, err = frame_verifier.parse_frame('"a string"')
    assert frame is None and err == "not_dict"

    # missing hdr
    frame, err = frame_verifier.parse_frame(json.dumps({"foo": "bar"}))
    assert frame is None and err == "missing_hdr"

    # hdr not dict
    frame, err = frame_verifier.parse_frame(json.dumps({"hdr": "nope"}))
    assert frame is None and err == "invalid_hdr"

    # missing header fields
    frame, err = frame_verifier.parse_frame(json.dumps({"hdr": {"dev_id": 1}}))
    assert frame is None and err == "missing_hdr_fields"

    # invalid header types
    bad = {"hdr": {"dev_id": "x", "msg_type": 1, "fc": 1, "flags": 0}}
    frame, err = frame_verifier.parse_frame(json.dumps(bad))
    assert frame is None and err == "invalid_hdr_types"


def test_aead_decrypt_success_and_failures(tmp_path, frame_verifier, pod_sim):
    # Prepare a device table path for pod_sim to populate
    dt_path = tmp_path / "device_table.json"
    dt_path.write_text("{}", encoding="utf-8")

    # Emit a framed record using pod_sim.emit_framed which also persists device table
    frame = pod_sim.emit_framed(
        "pod-007", 3, {"counter": 3, "bioimpedance": 75.5, "temp_c": 25.3}, dt_path
    )

    # Load device_table into memory using pod_sim helper
    device_table = pod_sim.load_device_table(dt_path)

    # Successful decrypt should return a dict with 'counter' parsed
    payload = frame_verifier.aead_decrypt(frame, device_table)
    assert isinstance(payload, dict)
    assert "counter" in payload

    # Unknown device -> decrypt should fail
    bad_table = {}
    assert frame_verifier.aead_decrypt(frame, bad_table) is None

    # Bad nonce length -> set nonce to short value
    bad = dict(frame)
    bad["nonce"] = base64.b64encode(b"short").decode("ascii")
    assert frame_verifier.aead_decrypt(bad, device_table) is None

    # Bad tag length -> set tag to short value
    bad2 = dict(frame)
    bad2["tag"] = base64.b64encode(b"shorttag").decode("ascii")
    assert frame_verifier.aead_decrypt(bad2, device_table) is None


def test_prev_day_root_or_zero(tmp_path, merkle_batcher):
    out_dir = tmp_path / "out"
    day_dir = out_dir / "day"
    # No day dir -> should return 64 hex zeros
    val = merkle_batcher.prev_day_root_or_zero(out_dir, "an-001", "2025-10-07")
    assert val == "00" * 32

    # Create previous day json with day_root
    day_dir.mkdir(parents=True, exist_ok=True)
    prev = day_dir / "2025-10-06.json"
    prev.write_text(json.dumps({"day_root": "aa" * 32}), encoding="utf-8")

    val2 = merkle_batcher.prev_day_root_or_zero(out_dir, "an-001", "2025-10-07")
    assert val2 == "aa" * 32

    # Corrupt JSON file should gracefully return zeros
    # Create a corrupt file that is the most-recent candidate (< 2025-10-08 but >= latest)
    bad = day_dir / "2025-10-07.json"
    bad.write_text("not-json", encoding="utf-8")
    val3 = merkle_batcher.prev_day_root_or_zero(out_dir, "an-001", "2025-10-08")
    assert val3 == "00" * 32
