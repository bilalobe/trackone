"""Integration tests around day_root vs .bin and .ots mutations.

Goal: demonstrate and enforce the invariant that:
- The Merkle day_root depends only on the content of the day artifact (e.g. day/2025-10-07.bin).
- Mutating the .bin invalidates verification once OTS metadata is enforced.
- Mutating the .ots proof file (e.g. upgrading it) affects only proof verification, not Merkle recomputation.
"""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.mark.usefixtures("sample_facts")
def test_day_root_ignores_day_bin_mutation_for_now(
    built_day_artifacts: dict[str, Path],
    verify_cli,
    mutate_day_bin,
) -> None:
    """Current verify_cli compares roots from facts; OTS meta is optional.

    If no ots_meta sidecar is present for the test day, mutating day.bin alone
    does not affect verify_cli's Merkle comparison. Once real ots_meta for the
    test day is wired in, this test can be tightened to expect failure.
    """
    day_bin = built_day_artifacts["day_bin"]
    root = built_day_artifacts["root"]
    facts_dir = built_day_artifacts["facts_dir"]

    verify_args = ["--root", str(root), "--facts", str(facts_dir)]
    assert verify_cli.main(verify_args) == 0

    # If the test workspace contains an ots_meta sidecar, verify_cli will validate
    # the artifact SHA against the meta and should fail after mutation. Otherwise
    # the mutation is not observed by verify_cli.
    proofs_dir = built_day_artifacts["root"].parent / "proofs"
    meta_path = proofs_dir / f"{built_day_artifacts['date'].name}.ots.meta.json"

    mutate_day_bin(day_bin)

    rc = verify_cli.main(verify_args)
    if meta_path.exists():
        # Expect artifact hash mismatch when meta enforces the artifact hash
        assert rc == 6
    else:
        # No meta present: current behavior is to ignore day.bin contents
        assert rc == 0


def test_ots_mutation_affects_only_proof_verification(
    built_day_artifacts: dict[str, Path],
    verify_cli,
    mutate_ots_file,
) -> None:
    """Mutating the .ots proof file should cause OTS verification to fail.

    The Merkle recomputation step is unaffected; we assert that the failure
    arises from the OTS layer (exit code 4).
    """
    root = built_day_artifacts["root"]
    facts_dir = built_day_artifacts["facts_dir"]
    ots_path = built_day_artifacts["ots_path"]

    verify_args = ["--root", str(root), "--facts", str(facts_dir)]
    assert verify_cli.main(verify_args) == 0

    original, _ = mutate_ots_file(ots_path)
    try:
        rc = verify_cli.main(verify_args)
        # Expect 'OTS proof verification failed' (exit code 4)
        assert rc == 4
    finally:
        ots_path.write_bytes(original)
