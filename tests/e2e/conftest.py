"""
End-to-end test fixtures (module-scoped).

These fixtures are specific to e2e tests that run the full pipeline.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# ============================================================================
# Module-scoped gateway fixtures for e2e tests
# ============================================================================


@pytest.fixture(scope="module")
def frame_verifier(gateway_modules):
    """Load frame_verifier module (module-scoped for e2e tests)."""
    module = gateway_modules.get("frame_verifier")
    if module is None:
        pytest.skip("frame_verifier module not available")
    return module


@pytest.fixture(scope="module")
def merkle_batcher(gateway_modules):
    """Load merkle_batcher module (module-scoped for e2e tests)."""
    module = gateway_modules.get("merkle_batcher")
    if module is None:
        pytest.skip("merkle_batcher module not available")
    return module


@pytest.fixture(scope="module")
def verify_cli(gateway_modules):
    """Load verify_cli module (module-scoped for e2e tests)."""
    module = gateway_modules.get("verify_cli")
    if module is None:
        pytest.skip("verify_cli module not available")
    return module


# ============================================================================
# E2E-specific helper fixtures
# ============================================================================


@pytest.fixture
def write_frames():
    """Return a callable that runs pod_sim to produce framed NDJSON (e2e-specific)."""

    def _write(device_id: str, count: int, out_path: Path, *maybe) -> None:
        import subprocess
        import sys

        # Resolve flexible args
        device_table = None
        facts_out = None
        if len(maybe) == 1:
            device_table = maybe[0]
        elif len(maybe) >= 2:
            if maybe[0] is None:
                device_table = maybe[1]
            else:
                device_table = maybe[0]
                facts_out = maybe[1]

        # Normalize str -> Path
        if isinstance(device_table, str):
            device_table = Path(device_table)
        if isinstance(facts_out, str):
            facts_out = Path(facts_out)

        out_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            sys.executable,
            "scripts/pod_sim/pod_sim.py",
            "--device-id",
            device_id,
            "--count",
            str(count),
            "--framed",
            "--out",
            str(out_path),
        ]

        if device_table:
            cmd += ["--device-table", str(device_table)]
        if facts_out and (
            device_table is None
            or Path(facts_out).resolve() != Path(device_table).resolve()
        ):
            cmd += ["--facts-out", str(facts_out)]

        subprocess.run(cmd, check=True)

    return _write


@pytest.fixture
def write_ots_placeholder():
    """Return a callable that writes an OTS placeholder (e2e-specific)."""

    def _write(out_dir: Path, day: str) -> Path:
        day_bin = out_dir / "day" / f"{day}.bin"
        day_bin.parent.mkdir(parents=True, exist_ok=True)
        ots_path = day_bin.with_suffix(day_bin.suffix + ".ots")
        ots_path.write_text("OTS_PROOF_PLACEHOLDER\n", encoding="utf-8")
        return ots_path

    return _write


@pytest.fixture
def run_merkle_batcher(merkle_batcher):
    """Return a callable to run merkle_batcher (e2e-specific)."""

    def _run(
        facts_dir: Path, out_dir: Path, site: str, day: str, validate: bool = True
    ) -> int:
        args = [
            "--facts",
            str(facts_dir),
            "--out",
            str(out_dir),
            "--site",
            site,
            "--date",
            day,
        ]
        if validate:
            args.append("--validate-schemas")
        return merkle_batcher.main(args)

    return _run


@pytest.fixture
def run_verify_cli(verify_cli):
    """Return a callable to run verify_cli (e2e-specific)."""

    def _run(root: Path, facts_dir: Path) -> int:
        args = ["--root", str(root), "--facts", str(facts_dir)]
        return verify_cli.main(args)

    return _run


@pytest.fixture
def list_facts():
    """Return a callable that lists sorted fact JSON files (e2e-specific)."""

    def _list(facts_dir: Path):
        if not facts_dir.exists():
            return []
        return sorted(facts_dir.glob("*.json"))

    return _list


@pytest.fixture
def run_pipeline(
    write_frames,
    frame_verifier,
    run_merkle_batcher,
    write_ots_placeholder,
    run_verify_cli,
    list_facts,
    day,
):
    """Return a callable that runs the full e2e pipeline (e2e-specific)."""

    def _run(
        device_id: str,
        count: int,
        temp_dirs: dict,
        site: str = "an-001",
        validate: bool = True,
    ) -> dict:
        # Ensure root exists
        temp_dirs["root"].mkdir(parents=True, exist_ok=True)

        # 0) Produce framed NDJSON (pod_sim)
        write_frames(
            device_id, count, temp_dirs["frames"], None, temp_dirs["device_table"]
        )

        # 1) Verify frames -> facts
        fv_args = [
            "--in",
            str(temp_dirs["frames"]),
            "--out-facts",
            str(temp_dirs["facts"]),
            "--device-table",
            str(temp_dirs["device_table"]),
        ]
        rc_verify = frame_verifier.process(fv_args)

        # 2) Batch facts
        rc_batch = run_merkle_batcher(
            temp_dirs["facts"], temp_dirs["out_dir"], site, day, validate=validate
        )

        # 3) Write OTS placeholder
        ots_path = write_ots_placeholder(temp_dirs["out_dir"], day)

        # 4) Verify CLI
        rc_verify_cli = run_verify_cli(temp_dirs["out_dir"], temp_dirs["facts"])

        # 5) Collect facts
        facts = list_facts(temp_dirs["facts"])

        return {
            "rc_verify": rc_verify,
            "rc_batch": rc_batch,
            "rc_verify_cli": rc_verify_cli,
            "ots_path": ots_path,
            "facts": facts,
        }

    return _run


@pytest.fixture
def write_frame_json():
    """Return a callable that writes a JSON object as a single line to a frames file (e2e-specific)."""

    def _write(frames_path: Path, obj: dict):
        frames_path.parent.mkdir(parents=True, exist_ok=True)
        frames_path.write_text(__import__("json").dumps(obj) + "\n", encoding="utf-8")

    return _write


@pytest.fixture
def append_frame_json():
    """Return a callable that appends a JSON object as a single line to a frames file (e2e-specific)."""

    def _append(frames_path: Path, obj: dict):
        frames_path.parent.mkdir(parents=True, exist_ok=True)
        with frames_path.open("a", encoding="utf-8") as fh:
            fh.write(__import__("json").dumps(obj) + "\n")

    return _append
