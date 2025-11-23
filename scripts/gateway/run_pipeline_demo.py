#!/usr/bin/env python3
"""Deterministic TrackOne pipeline runner writing artifacts to out/site_demo."""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

try:  # Support both package imports and direct script execution.
    from .tsa_stamp import DEFAULT_TSA_TIMEOUT, TsaStampError, tsa_stamp_day_blob
except ImportError:  # pragma: no cover - fallback when run as a script
    from tsa_stamp import (  # type: ignore
        DEFAULT_TSA_TIMEOUT,
        TsaStampError,
        tsa_stamp_day_blob,
    )

try:  # Support both package imports and direct script execution.
    from .peer_attestation import (
        PeerAttestationError,
        write_peer_attestations,
    )
except ImportError:  # pragma: no cover - fallback when run as a script
    from peer_attestation import (  # type: ignore
        PeerAttestationError,
        write_peer_attestations,
    )

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT_DIR = "out/site_demo"
DEFAULT_DATE = "2025-10-07"
DEFAULT_DEVICE_ID = "pod-003"
DEFAULT_SITE = "an-001"
DEFAULT_FRAME_COUNT = 7
DEFAULT_FRAME_WINDOW = 64


def _maybe_requests_exception() -> type[BaseException] | None:
    try:
        import requests

        return requests.RequestException
    except ModuleNotFoundError:
        return None


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def resolve_repo_path(path: Path | None) -> Path | None:
    if path is None:
        return None
    if path.is_absolute():
        return path
    return (REPO_ROOT / path).resolve()


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def run_cmd(label: str, cmd: Iterable[str], *, cwd: Path) -> None:
    printable = " ".join(shlex.quote(str(part)) for part in cmd)
    print(f"[pipeline] {label}\n[pipeline] → {printable}")
    subprocess.run(list(cmd), check=True, cwd=cwd)


def clean_outputs(out_dir: Path, frames_file: Path, *, keep_existing: bool) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    if keep_existing:
        return
    for path in (
        frames_file,
        out_dir / "frames.ndjson",
    ):
        if Path(path).is_file():
            Path(path).unlink()
    for subdir in ("facts", "blocks", "day"):
        target = out_dir / subdir
        if target.exists():
            shutil.rmtree(target)


def ensure_dirs(*paths: Path) -> None:
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)


def artifact_manifest(
    date: str,
    site: str,
    device_id: str,
    frame_count: int,
    frames_file: Path,
    facts_dir: Path,
    day_bin: Path,
    out_dir: Path,
    *,
    tsa_artifacts: dict[str, Path] | None = None,
    peer_attest: Path | None = None,
) -> Path:
    artifacts = {
        "day_bin": rel(day_bin),
        "day_json": rel(day_bin.with_suffix(".json")),
        "day_sha256": rel(day_bin.with_suffix(".bin.sha256")),
        "day_ots": rel(Path(f"{day_bin}.ots")),
        "block": rel(out_dir / "blocks" / f"{date}-00.block.json"),
    }
    if tsa_artifacts:
        artifacts.update({name: rel(path) for name, path in tsa_artifacts.items()})
    if peer_attest:
        artifacts["peer_attest"] = rel(peer_attest)

    manifest = {
        "date": date,
        "site": site,
        "device_id": device_id,
        "frame_count": frame_count,
        "frames_file": rel(frames_file),
        "facts_dir": rel(facts_dir),
        "artifacts": artifacts,
    }
    manifest_path = day_bin.parent / f"{date}.pipeline-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the deterministic TrackOne pipeline demo."
    )
    parser.add_argument(
        "--out-dir", default=os.environ.get("PIPELINE_OUT_DIR", DEFAULT_OUT_DIR)
    )
    parser.add_argument("--date", default=os.environ.get("PIPELINE_DATE", DEFAULT_DATE))
    parser.add_argument(
        "--device-id", default=os.environ.get("PIPELINE_DEVICE_ID", DEFAULT_DEVICE_ID)
    )
    parser.add_argument("--site", default=os.environ.get("PIPELINE_SITE", DEFAULT_SITE))
    parser.add_argument(
        "--frame-count",
        type=int,
        default=int(os.environ.get("PIPELINE_FRAME_COUNT", DEFAULT_FRAME_COUNT)),
    )
    parser.add_argument(
        "--frame-window",
        type=int,
        default=int(os.environ.get("PIPELINE_FRAME_WINDOW", DEFAULT_FRAME_WINDOW)),
    )
    parser.add_argument(
        "--keep-existing",
        action="store_true",
        help="Retain existing artifacts instead of cleaning the out directory.",
    )
    parser.add_argument(
        "--skip-verify-cli",
        action="store_true",
        help="Skip verify_cli. Useful when only artifacts are required.",
    )
    parser.add_argument(
        "--skip-validate",
        action="store_true",
        help="Skip schema validation in merkle_batcher.",
    )
    parser.add_argument(
        "--fail-on-verify",
        action="store_true",
        help="Treat verify_cli failures as fatal (default: warn only).",
    )
    parser.add_argument(
        "--tsa-url",
        default=os.environ.get("PIPELINE_TSA_URL"),
        help="RFC 3161 TSA endpoint (default: PIPELINE_TSA_URL env)",
    )
    parser.add_argument(
        "--tsa-out",
        type=Path,
        default=None,
        help="Directory for TSA artifacts (default: day/)",
    )
    parser.add_argument(
        "--tsa-ca",
        type=Path,
        default=None,
        help="Optional CA bundle for TSA verification",
    )
    parser.add_argument(
        "--tsa-chain",
        type=Path,
        default=None,
        help="Optional intermediate chain for TSA verification",
    )
    parser.add_argument(
        "--tsa-policy-oid",
        default=os.environ.get("PIPELINE_TSA_POLICY_OID"),
        help="Policy OID to include in TSA request",
    )
    parser.add_argument(
        "--tsa-timeout",
        type=float,
        default=float(os.environ.get("PIPELINE_TSA_TIMEOUT", DEFAULT_TSA_TIMEOUT)),
        help="HTTP timeout in seconds for TSA requests",
    )
    parser.add_argument(
        "--skip-tsa",
        action="store_true",
        help="Skip TSA stamping regardless of configuration",
    )
    parser.add_argument(
        "--tsa-strict",
        action="store_true",
        help="Treat TSA failures as fatal (default: warn and continue)",
    )
    parser.add_argument(
        "--tsa-verify",
        action="store_true",
        help="Force TSA verification even without CA bundle",
    )
    parser.add_argument(
        "--peer-config",
        type=Path,
        default=None,
        help="Peer key JSON for co-signatures",
    )
    parser.add_argument(
        "--peer-dir",
        type=Path,
        default=None,
        help="Directory for peer signatures (default: day/peers)",
    )
    parser.add_argument(
        "--peer-min",
        type=int,
        default=int(os.environ.get("PIPELINE_PEER_MIN", "1")),
        help="Minimum peer signatures required",
    )
    parser.add_argument(
        "--peer-context",
        default=os.environ.get("PIPELINE_PEER_CONTEXT", "trackone:day-root:v1"),
        help="Context string embedded in peer signatures",
    )
    parser.add_argument(
        "--skip-peers",
        action="store_true",
        help="Skip peer attestation regardless of configuration",
    )
    parser.add_argument(
        "--peers-strict",
        action="store_true",
        help="Treat peer attestation failures as fatal",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = (REPO_ROOT / out_dir).resolve()

    frames_file = out_dir / "frames.ndjson"
    facts_dir = out_dir / "facts"
    device_table = out_dir / "device_table.json"
    day_dir = out_dir / "day"
    day_bin = day_dir / f"{args.date}.bin"
    tsa_out_dir = resolve_repo_path(args.tsa_out) or day_dir
    peer_dir = resolve_repo_path(args.peer_dir) or (day_dir / "peers")
    tsa_artifacts: dict[str, Path] | None = None
    peer_attest_path: Path | None = None

    clean_outputs(out_dir, frames_file, keep_existing=args.keep_existing)
    ensure_dirs(out_dir, facts_dir, day_dir)

    scripts_dir = REPO_ROOT / "scripts"
    gateway_dir = scripts_dir / "gateway"

    run_cmd(
        "Generating framed telemetry",
        [
            sys.executable,
            str(scripts_dir / "pod_sim" / "pod_sim.py"),
            "--framed",
            "--device-id",
            args.device_id,
            "--count",
            str(args.frame_count),
            "--device-table",
            str(device_table),
            "--out",
            str(frames_file),
        ],
        cwd=REPO_ROOT,
    )

    run_cmd(
        "Deriving facts",
        [
            sys.executable,
            str(gateway_dir / "frame_verifier.py"),
            "--in",
            str(frames_file),
            "--out-facts",
            str(facts_dir),
            "--device-table",
            str(device_table),
            "--window",
            str(args.frame_window),
        ],
        cwd=REPO_ROOT,
    )

    merkle_cmd = [
        sys.executable,
        str(gateway_dir / "merkle_batcher.py"),
        "--facts",
        str(facts_dir),
        "--out",
        str(out_dir),
        "--site",
        args.site,
        "--date",
        args.date,
    ]
    if not args.skip_validate:
        merkle_cmd.append("--validate-schemas")

    run_cmd("Batching facts", merkle_cmd, cwd=REPO_ROOT)

    run_cmd(
        "Anchoring day blob",
        [
            sys.executable,
            str(gateway_dir / "ots_anchor.py"),
            str(day_bin),
        ],
        cwd=REPO_ROOT,
    )

    tsa_url = args.tsa_url or os.environ.get("PIPELINE_TSA_URL")
    if tsa_url and not args.skip_tsa:
        tsa_ca = resolve_repo_path(args.tsa_ca)
        tsa_chain = resolve_repo_path(args.tsa_chain)
        try:
            print("[pipeline] Anchoring day blob with RFC 3161 TSA")
            tsa_result = tsa_stamp_day_blob(
                day_blob=day_bin,
                tsa_url=tsa_url,
                out_dir=tsa_out_dir,
                tsa_ca_pem=tsa_ca,
                tsa_chain_pem=tsa_chain,
                policy_oid=args.tsa_policy_oid,
                timeout_s=args.tsa_timeout,
                verify_response=args.tsa_verify or bool(tsa_ca or tsa_chain),
            )
            print(
                f"[pipeline] TSA response stored: {rel(tsa_result.tsr)} (verified={tsa_result.verified})"
            )
            tsa_artifacts = {
                "tsa_tsq": tsa_result.tsq,
                "tsa_tsr": tsa_result.tsr,
                "tsa_meta": tsa_result.tsr_json,
            }
        except (
            TsaStampError,
            subprocess.CalledProcessError,
        ) as exc:
            message = f"[pipeline] WARN: TSA stamping failed ({exc})"
            if args.tsa_strict:
                raise RuntimeError(message) from exc
            print(message, file=sys.stderr)
    elif not tsa_url:
        print("[pipeline] INFO: TSA URL not configured; skipping RFC 3161 step")

    peer_config = resolve_repo_path(args.peer_config)
    if peer_config and not args.skip_peers:
        try:
            peer_dir.mkdir(parents=True, exist_ok=True)
            result = write_peer_attestations(
                site_id=args.site,
                day=args.date,
                day_root_hex=json.loads(
                    day_bin.with_suffix(".json").read_text(encoding="utf-8")
                )["day_root"],
                peer_config=peer_config,
                out_dir=peer_dir,
                min_signatures=args.peer_min,
                context=args.peer_context.encode(),
            )
            print(
                f"[pipeline] Peer signatures stored: {rel(result.path)} ({len(result.signatures)} signatures)"
            )
            peer_attest_path = result.path
        except (PeerAttestationError, FileNotFoundError, json.JSONDecodeError) as exc:
            message = f"[pipeline] WARN: peer attestation failed ({exc})"
            if args.peers_strict:
                raise RuntimeError(message) from exc
            print(message, file=sys.stderr)
    elif not peer_config:
        print("[pipeline] INFO: peer config not provided; skipping co-signing")

    if not args.skip_verify_cli:
        try:
            run_cmd(
                "Verifying pipeline outputs",
                [
                    sys.executable,
                    str(gateway_dir / "verify_cli.py"),
                    "--root",
                    str(out_dir),
                    "--facts",
                    str(facts_dir),
                ],
                cwd=REPO_ROOT,
            )
        except subprocess.CalledProcessError as exc:
            if args.fail_on_verify:
                raise
            print(
                "[pipeline] WARN: verify_cli failed but continuing (set --fail-on-verify to enforce).",
                file=sys.stderr,
            )
            print(
                f"[pipeline] WARN: verify_cli exited with code {exc.returncode}",
                file=sys.stderr,
            )

    expected_artifacts = [
        day_bin,
        day_bin.with_suffix(".json"),
        day_bin.with_suffix(".bin.sha256"),
        Path(f"{day_bin}.ots"),
    ]
    missing = [p for p in expected_artifacts if not p.exists()]
    if missing:
        missing_str = ", ".join(rel(p) for p in missing)
        raise RuntimeError(f"Missing expected artifacts: {missing_str}")

    manifest_path = artifact_manifest(
        args.date,
        args.site,
        args.device_id,
        args.frame_count,
        frames_file,
        facts_dir,
        day_bin,
        out_dir,
        tsa_artifacts=tsa_artifacts,
        peer_attest=peer_attest_path,
    )

    if tsa_url and not args.skip_tsa:
        expected_artifacts.extend(
            [
                tsa_out_dir / f"{args.date}.tsq",
                tsa_out_dir / f"{args.date}.tsr",
                tsa_out_dir / f"{args.date}.tsr.json",
            ]
        )

    if peer_config and not args.skip_peers:
        expected_artifacts.append(peer_dir / f"{args.date}.peers.json")

    missing = [p for p in expected_artifacts if not p.exists()]
    if missing:
        missing_str = ", ".join(rel(p) for p in missing)
        raise RuntimeError(f"Missing expected artifacts: {missing_str}")

    print("[pipeline] ✓ Pipeline completed successfully")
    for path in expected_artifacts + [manifest_path]:
        print(f"[pipeline]   - {rel(path)}")


if __name__ == "__main__":
    main()
