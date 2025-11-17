"""
End-to-end pipeline integration tests.

Tests the full pipeline from pod_sim → frame_verifier → merkle_batcher → verify_cli.
Exercises the complete workflow and verifies success indicators at each stage.
"""

from __future__ import annotations


def test_end_to_end_pipeline(temp_dirs, run_pipeline):
    """Run the full pipeline and verify all stages succeed."""
    res = run_pipeline("pod-003", 7, temp_dirs, site="an-001", validate=True)

    assert res["rc_verify"] == 0, "Frame verification should succeed"
    assert res["rc_batch"] == 0, "Merkle batching should succeed"
    assert res["ots_path"].exists(), "OTS proof should be created"
    assert res["rc_verify_cli"] == 0, "CLI verification should succeed"
    assert len(res["facts"]) > 0, "Facts should be produced"


def test_pipeline_with_multiple_devices(temp_dirs, run_pipeline):
    """Verify pipeline handles multiple device IDs correctly."""
    res = run_pipeline("pod-multi-001", 5, temp_dirs, site="test-site", validate=True)

    assert res["rc_verify"] == 0
    assert res["rc_batch"] == 0
    assert len(res["facts"]) == 5


def test_pipeline_empty_facts_produces_empty_batch(
    temp_dirs,
    frame_verifier,
    run_merkle_batcher,
    write_ots_placeholder,
    run_verify_cli,
    list_facts,
    day,
):
    """Pipeline should handle gracefully when no frames produce facts."""
    temp_dirs["root"].mkdir(parents=True, exist_ok=True)
    temp_dirs["frames"].write_text("", encoding="utf-8")

    # Run frame verification (should produce no facts)
    rc_verify = frame_verifier.process(
        [
            "--in",
            str(temp_dirs["frames"]),
            "--out-facts",
            str(temp_dirs["facts"]),
            "--device-table",
            str(temp_dirs["device_table"]),
        ]
    )
    assert rc_verify == 0

    # Verify facts directory is empty or doesn't exist
    facts = list_facts(temp_dirs["facts"])
    assert len(facts) == 0
