#!/usr/bin/env python3
"""
Pipeline execution fixtures.

Provides high-level fixtures for running pipeline components (merkle_batcher,
verify_cli, OTS stamping, pod_sim) and full end-to-end workflows.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def write_frames():
    """Run pod_sim to produce framed NDJSON output.

    Returns a callable that invokes pod_sim.py with the specified parameters.
    Supports both simple and complex usage patterns for unit and e2e tests.
    """

    def _write(device_id: str, count: int, out_path: Path, *maybe) -> None:
        # Resolve flexible args for backward compatibility
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

        out_path = Path(out_path)
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
def write_ots_placeholder(ots_anchor):
    """Write an OTS placeholder/stub and metadata sidecar.

    Returns a callable that takes (out_dir, day) and creates:
    - day/<day>.cbor.ots (stationary stub or placeholder)
    - proofs/<day>.ots.meta.json (metadata sidecar)

    Returns (ots_path, meta_path) tuple.
    """

    def _write(out_dir: Path, day: str) -> tuple[Path, Path]:
        out_dir = Path(out_dir)
        day_cbor = out_dir / "day" / f"{day}.cbor"
        day_cbor.parent.mkdir(parents=True, exist_ok=True)

        # Ensure day artifact exists (merkle_batcher should have written it in tests)
        if not day_cbor.exists():
            day_cbor.write_bytes(b"test day artifact")

        ots_path = day_cbor.with_suffix(day_cbor.suffix + ".ots")
        proofs_dir = out_dir.parent / "proofs"

        # In tests we want deterministic, offline behavior.
        # Always route through ots_anchor.ots_stamp, which already honors
        # OTS_STATIONARY_STUB and writes the meta sidecar.
        ots_anchor.ots_stamp(day_cbor, ots_path, proofs_dir=proofs_dir)

        meta_path = proofs_dir / f"{day}.ots.meta.json"
        return ots_path, meta_path

    return _write


@pytest.fixture
def run_merkle_batcher(merkle_batcher):
    """Run merkle_batcher with the specified parameters.

    Returns a callable that takes (facts_dir, out_dir, site, day, validate=True)
    and returns the exit code.
    """

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
    """Run verify_cli with the specified parameters.

    Returns a callable that takes (root, facts_dir) and returns the exit code.
    """

    def _run(root: Path, facts_dir: Path) -> int:
        args = ["--root", str(root), "--facts", str(facts_dir)]
        return verify_cli.main(args)

    return _run


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
    """Run the full end-to-end pipeline.

    Returns a callable that executes:
    1. Pod simulator (write frames)
    2. Frame verifier (verify frames -> facts)
    3. Merkle batcher (batch facts -> day.cbor)
    4. OTS anchor (stamp day.cbor)
    5. Verify CLI (verify everything)

    Returns a dict with exit codes and paths.
    """

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

        # 3) Write OTS placeholder (and meta)
        ots_path, meta_path = write_ots_placeholder(temp_dirs["out_dir"], day)

        # 4) Verify CLI
        rc_verify_cli = run_verify_cli(temp_dirs["out_dir"], temp_dirs["facts"])

        # 5) Collect facts
        facts = list_facts(temp_dirs["facts"])

        return {
            "rc_verify": rc_verify,
            "rc_batch": rc_batch,
            "rc_verify_cli": rc_verify_cli,
            "ots_path": ots_path,
            "ots_meta": meta_path,
            "facts": facts,
        }

    return _run
