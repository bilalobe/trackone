from __future__ import annotations

import subprocess


def test_verification_gate_policy_lives_in_rust_contract() -> None:
    subprocess.run(
        [
            "cargo",
            "test",
            "--package",
            "trackone-evidence",
            "rust_verifier_rejects_tampered_fact_root",
        ],
        check=True,
    )
