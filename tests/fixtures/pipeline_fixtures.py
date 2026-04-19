#!/usr/bin/env python3
"""
Pipeline execution fixtures.

Provides high-level fixtures for running pipeline components (merkle_batcher,
verify_cli, OTS stamping, Rust framed fixture emission) and full end-to-end
workflows.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.gateway.rust_framed_fixture_emitter import emit_frames


@pytest.fixture
def write_frames():
    """Produce Rust-native postcard framed NDJSON output for tests."""

    def _write(
        device_id: str,
        count: int,
        out_path: Path,
        provisioning_input: Path | None = None,
        device_table: Path | None = None,
        *,
        start_fc: int = 0,
        site: str | None = None,
    ) -> None:
        # Backward-compatibility for older call sites that pass device_table as
        # the fourth positional argument.
        if device_table is None and provisioning_input is not None:
            device_table = provisioning_input
            provisioning_input = None
        if device_table is None:
            raise ValueError(
                "device_table path is required for framed fixture emission"
            )
        emit_frames(
            device_id=device_id,
            count=count,
            out_path=Path(out_path),
            device_table_path=Path(device_table),
            site_id=site,
            provisioning_input_path=Path(provisioning_input)
            if provisioning_input is not None
            else None,
            start_fc=start_fc,
        )

    return _write


@pytest.fixture
def write_ots_placeholder(ots_anchor):
    """Write an OTS placeholder/stub and metadata sidecar.

    Returns a callable that takes (out_dir, day) and creates:
    - day/<day>.cbor.ots (stationary stub or placeholder)
    - day/<day>.ots.meta.json (metadata sidecar)

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

        # In tests we want deterministic, offline behavior.
        # Always route through ots_anchor.ots_stamp, which already honors
        # OTS_STATIONARY_STUB and writes the meta sidecar.
        ots_anchor.ots_stamp(day_cbor, ots_path)

        meta_path = day_cbor.parent / f"{day}.ots.meta.json"
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
    1. Rust framed fixture emission (write frames)
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

        # 0) Produce framed NDJSON
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
            "--ingest-profile",
            "rust-postcard-v1",
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
