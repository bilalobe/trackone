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
    """Verify that mutating day.bin fails validation when OTS metadata is present.

    The built_day_artifacts fixture always creates an OTS meta sidecar that
    includes the artifact SHA256. After mutating day.bin, verify_cli parses
    and validates the day.bin content, then checks the artifact hash against
    the meta, resulting in exit code 9 (artifact hash mismatch).
    """
    day_bin = built_day_artifacts["day_bin"]
    root = built_day_artifacts["root"]
    facts_dir = built_day_artifacts["facts_dir"]

    verify_args = ["--root", str(root), "--facts", str(facts_dir)]
    assert verify_cli.main(verify_args) == 0

    # Mutate the day.bin artifact
    mutate_day_bin(day_bin)

    # With OTS metadata present, verify_cli validates the artifact SHA
    # and should fail with exit code 9 (artifact hash mismatch)
    rc = verify_cli.main(verify_args)
    assert rc == 9


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
