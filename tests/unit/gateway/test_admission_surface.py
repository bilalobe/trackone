from __future__ import annotations

import subprocess


def test_rejection_audit_shape_lives_in_rust_contract() -> None:
    subprocess.run(
        [
            "cargo",
            "test",
            "--package",
            "trackone-evidence",
            "rust_rejection_audit_contract_matches_stable_shape",
        ],
        check=True,
    )
