#!/usr/bin/env python3
"""Deterministic TrackOne pipeline runner writing artifacts to out/site_demo."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from trackone_core.constants import DEFAULT_INGEST_PROFILE
from trackone_core.ledger import sha256_hex
from trackone_core.release import (
    DEFAULT_COMMITMENT_PROFILE_ID,
    verification_bundle_from_summary,
)

try:  # Support both package imports and direct script execution.
    from .anchoring_config import (
        STRICT,
        AnchoringConfig,
        compute_overall_status,
        load_anchoring_config,
    )
except ImportError:  # pragma: no cover - fallback when run as a script
    from anchoring_config import (  # type: ignore
        STRICT,
        AnchoringConfig,
        compute_overall_status,
        load_anchoring_config,
    )

try:  # Support both package imports and direct script execution.
    from .schema_validation import (
        load_schema,
        require_schema_validation,
        validate_instance,
    )
    from .tsa_stamp import TsaStampError, tsa_stamp_day_blob
    from .verification_gate import local_verification_failure
    from .verification_manifest import verify_manifest_path
except ImportError:  # pragma: no cover - fallback when run as a script
    from schema_validation import (  # type: ignore
        load_schema,
        require_schema_validation,
        validate_instance,
    )
    from tsa_stamp import (  # type: ignore
        TsaStampError,
        tsa_stamp_day_blob,
    )
    from verification_gate import local_verification_failure  # type: ignore
    from verification_manifest import verify_manifest_path  # type: ignore

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT_DIR = "out/site_demo"
DEFAULT_DATE = "2025-10-07"
DEFAULT_DEVICE_ID = "pod-003"
DEFAULT_SITE = "an-001"
DEFAULT_FRAME_COUNT = 7
DEFAULT_FRAME_WINDOW = 64

STATUS_VERIFIED = "verified"
STATUS_FAILED = "failed"
STATUS_MISSING = "missing"
STATUS_PENDING = "pending"
STATUS_SKIPPED = "skipped"


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


def _artifact_ref(path: Path, *, root: Path) -> dict[str, str]:
    try:
        rel_path = str(path.relative_to(root))
    except ValueError:
        raise ValueError(
            f"artifact path {path} is outside the pipeline root {root}; "
            "use --tsa-out / --peer-dir paths that live under --out-dir"
        ) from None
    digest = sha256_hex(path.read_bytes())
    if not isinstance(digest, str):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "path": rel_path,
        "sha256": digest,
    }


def run_cmd(label: str, cmd: Iterable[str], *, cwd: Path) -> None:
    printable = " ".join(shlex.quote(str(part)) for part in cmd)
    print(f"[pipeline] {label}\n[pipeline] -> {printable}")
    subprocess.run(list(cmd), check=True, cwd=cwd)


def clean_outputs(out_dir: Path, frames_file: Path, *, keep_existing: bool) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    if keep_existing:
        return
    for path in (frames_file, out_dir / "frames.ndjson"):
        if Path(path).is_file():
            Path(path).unlink()
    for subdir in ("facts", "blocks", "day", "sensorthings", "provisioning", "audit"):
        target = out_dir / subdir
        if target.exists():
            shutil.rmtree(target)


def ensure_dirs(*paths: Path) -> None:
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)


def _channel(enabled: bool, status: str, reason: str = "") -> dict[str, Any]:
    return {"enabled": enabled, "status": status, "reason": reason}


def _portable_verifier_summary(summary: dict[str, Any]) -> dict[str, Any]:
    portable: dict[str, Any] = {}
    for key in (
        "policy",
        "verification",
        "checks",
        "checks_executed",
        "checks_skipped",
        "channels",
        "overall",
    ):
        value = summary.get(key)
        if value is not None:
            portable[key] = json.loads(json.dumps(value))
    return portable


def artifact_manifest(
    date: str,
    site: str,
    device_id: str,
    frame_count: int,
    frames_file: Path,
    facts_dir: Path,
    day_artifact: Path,
    out_dir: Path,
    *,
    anchoring: dict[str, Any],
    tsa_artifacts: dict[str, Path] | None = None,
    peer_attest: Path | None = None,
    verifier_summary: dict[str, Any] | None = None,
    sensorthings_projection: Path,
    provisioning_input: Path,
    provisioning_records: Path,
    disclosure_class: str = "A",
    commitment_profile_id: str = DEFAULT_COMMITMENT_PROFILE_ID,
) -> Path:
    artifacts: dict[str, dict[str, str]] = {
        "day_cbor": _artifact_ref(day_artifact, root=out_dir),
        "day_json": _artifact_ref(day_artifact.with_suffix(".json"), root=out_dir),
        "day_sha256": _artifact_ref(
            day_artifact.with_suffix(".cbor.sha256"), root=out_dir
        ),
        "block": _artifact_ref(
            out_dir / "blocks" / f"{date}-00.block.json", root=out_dir
        ),
    }
    day_ots = Path(f"{day_artifact}.ots")
    if day_ots.exists():
        artifacts["day_ots"] = _artifact_ref(day_ots, root=out_dir)
    day_ots_meta = day_artifact.parent / f"{date}.ots.meta.json"
    if day_ots_meta.exists():
        artifacts["day_ots_meta"] = _artifact_ref(day_ots_meta, root=out_dir)
    if tsa_artifacts:
        artifacts.update(
            {
                name: _artifact_ref(path, root=out_dir)
                for name, path in tsa_artifacts.items()
            }
        )
    if peer_attest:
        artifacts["peer_attest"] = _artifact_ref(peer_attest, root=out_dir)
    artifacts["sensorthings_projection"] = _artifact_ref(
        sensorthings_projection, root=out_dir
    )
    artifacts["provisioning_input"] = _artifact_ref(provisioning_input, root=out_dir)
    artifacts["provisioning_records"] = _artifact_ref(
        provisioning_records, root=out_dir
    )

    verification_bundle = verification_bundle_from_summary(
        verifier_summary,
        disclosure_class=disclosure_class,
        commitment_profile_id=commitment_profile_id,
    )

    manifest: dict[str, Any] = {
        "version": 1,
        "date": date,
        "site": site,
        "device_id": device_id,
        "frame_count": frame_count,
        "frames_file": str(frames_file.relative_to(out_dir)),
        "facts_dir": str(facts_dir.relative_to(out_dir)),
        "artifacts": artifacts,
        "anchoring": anchoring,
        "verification_bundle": verification_bundle,
    }
    if verifier_summary is not None:
        manifest["verifier"] = _portable_verifier_summary(verifier_summary)
    verify_schema = load_schema("verify_manifest")
    if verify_schema is not None:
        require_schema_validation("pipeline verification-manifest validation")
        validate_instance(manifest, verify_schema)
    verify_path = verify_manifest_path(day_artifact.parent, date)
    payload = json.dumps(manifest, indent=2) + "\n"
    verify_path.write_text(payload, encoding="utf-8")
    return verify_path


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
        "--config",
        type=Path,
        default=None,
        help="Anchoring config path (default: ./anchoring.toml)",
    )
    parser.add_argument(
        "--policy-mode",
        choices=["warn", "strict"],
        default=None,
        help="Override anchoring policy mode",
    )
    parser.add_argument(
        "--keep-existing",
        action="store_true",
        help="Retain existing artifacts instead of cleaning the out directory.",
    )
    parser.add_argument(
        "--skip-validate",
        action="store_true",
        help="Skip schema validation in merkle_batcher.",
    )
    parser.add_argument(
        "--skip-ots",
        action="store_true",
        help="Skip OTS anchoring regardless of configuration",
    )
    parser.add_argument(
        "--tsa-url",
        default=None,
        help="RFC 3161 TSA endpoint override",
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
        default=None,
        help="Policy OID to include in TSA request",
    )
    parser.add_argument(
        "--tsa-timeout",
        type=float,
        default=None,
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
        help="Treat TSA failures as fatal (override policy)",
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
        default=None,
        help="Minimum peer signatures required",
    )
    parser.add_argument(
        "--peer-context",
        default=None,
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
        help="Treat peer attestation failures as fatal (override policy)",
    )
    parser.add_argument(
        "--disclosure-class",
        choices=["A", "B", "C"],
        default=os.environ.get("PIPELINE_DISCLOSURE_CLASS", "A"),
        help="Disclosure class passed to verify_cli and recorded in manifests.",
    )
    parser.add_argument(
        "--commitment-profile-id",
        default=os.environ.get(
            "PIPELINE_COMMITMENT_PROFILE_ID", DEFAULT_COMMITMENT_PROFILE_ID
        ),
        help="Commitment profile identifier passed to verify_cli and manifests.",
    )
    return parser.parse_args()


def _load_config(args: argparse.Namespace) -> AnchoringConfig:
    cli_overrides: dict[str, Any] = {
        "policy_mode": args.policy_mode,
        "tsa_enabled": True if args.tsa_url else None,
        "tsa_url": args.tsa_url,
        "tsa_ca_bundle": str(args.tsa_ca) if args.tsa_ca else None,
        "tsa_chain_bundle": str(args.tsa_chain) if args.tsa_chain else None,
        "tsa_policy_oid": args.tsa_policy_oid,
        "tsa_timeout_s": args.tsa_timeout,
        "tsa_verify": args.tsa_verify if args.tsa_verify else None,
        "peers_enabled": True if args.peer_config else None,
        "peers_config_path": str(args.peer_config) if args.peer_config else None,
        "peers_min_signatures": args.peer_min,
        "peers_context": args.peer_context,
    }
    cfg_path = resolve_repo_path(args.config)
    return load_anchoring_config(config_path=cfg_path, cli_overrides=cli_overrides)


def _set_ots_calendars(cfg: AnchoringConfig) -> None:
    if not cfg.ots.calendar_urls:
        os.environ.pop("OTS_CALENDARS", None)
        return
    os.environ["OTS_CALENDARS"] = ",".join(cfg.ots.calendar_urls)


def _load_peer_attestation() -> Any | None:
    """Resolve peer attestation helpers without hard dependency at import time."""
    write_peer_attestations: Any | None = None
    try:
        from .peer_attestation import (
            write_peer_attestations as write_peer_attestations_primary,
        )

        write_peer_attestations = write_peer_attestations_primary
    except ImportError:
        try:
            from peer_attestation import (  # type: ignore[import-not-found]
                write_peer_attestations as write_peer_attestations_fallback,
            )

            write_peer_attestations = write_peer_attestations_fallback
        except ImportError:
            pass
    return write_peer_attestations


def _run_verify_cli(
    *,
    gateway_dir: Path,
    root: Path,
    facts_dir: Path,
    cfg: AnchoringConfig,
    skip_ots: bool,
    skip_tsa: bool,
    skip_peers: bool,
    disclosure_class: str,
    commitment_profile_id: str,
) -> tuple[int, dict[str, Any] | None]:
    verify_cmd = [
        sys.executable,
        str(gateway_dir / "verify_cli.py"),
        "--root",
        str(root),
        "--facts",
        str(facts_dir),
        "--json",
        "--policy-mode",
        cfg.policy.mode,
        "--disclosure-class",
        disclosure_class,
        "--commitment-profile-id",
        commitment_profile_id,
    ]
    if cfg.path.exists():
        verify_cmd.extend(["--config", str(cfg.path)])

    verify_env = os.environ.copy()
    if skip_ots:
        verify_env["ANCHOR_OTS_ENABLED"] = "0"
    if skip_tsa:
        verify_env["ANCHOR_TSA_ENABLED"] = "0"
    if skip_peers:
        verify_env["ANCHOR_PEERS_ENABLED"] = "0"

    proc = subprocess.run(
        verify_cmd,
        check=False,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=verify_env,
    )
    if proc.stdout:
        print(proc.stdout.strip())
    if proc.stderr:
        print(proc.stderr.strip(), file=sys.stderr)

    summary: dict[str, Any] | None = None
    if proc.stdout.strip():
        try:
            summary_val = json.loads(proc.stdout)
            if isinstance(summary_val, dict):
                summary = summary_val
        except json.JSONDecodeError:
            summary = None

    return proc.returncode, summary


def main() -> None:
    args = parse_args()
    cfg = _load_config(args)
    strict_mode = cfg.policy.mode == STRICT

    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = (REPO_ROOT / out_dir).resolve()

    frames_file = out_dir / "frames.ndjson"
    facts_dir = out_dir / "facts"
    device_table = out_dir / "device_table.json"
    day_dir = out_dir / "day"
    day_cbor = day_dir / f"{args.date}.cbor"
    sensorthings_dir = out_dir / "sensorthings"
    sensorthings_projection = sensorthings_dir / f"{args.date}.observations.json"
    provisioning_dir = out_dir / "provisioning"
    provisioning_input = provisioning_dir / "authoritative-input.json"
    provisioning_records = provisioning_dir / "records.json"
    tsa_out_dir = resolve_repo_path(args.tsa_out) or day_dir
    peer_dir = resolve_repo_path(args.peer_dir) or (day_dir / "peers")
    tsa_artifacts: dict[str, Path] | None = None
    peer_attest_path: Path | None = None

    clean_outputs(out_dir, frames_file, keep_existing=args.keep_existing)
    ensure_dirs(out_dir, facts_dir, day_dir, sensorthings_dir, provisioning_dir)

    scripts_dir = REPO_ROOT / "scripts"
    gateway_dir = scripts_dir / "gateway"

    _set_ots_calendars(cfg)

    channels: dict[str, dict[str, Any]] = {
        "ots": _channel(
            cfg.ots.enabled and not args.skip_ots, STATUS_SKIPPED, "disabled"
        ),
        "tsa": _channel(
            cfg.tsa.enabled and not args.skip_tsa, STATUS_SKIPPED, "disabled"
        ),
        "peers": _channel(
            cfg.peers.enabled and not args.skip_peers, STATUS_SKIPPED, "disabled"
        ),
    }

    run_cmd(
        "Generating framed telemetry",
        [
            sys.executable,
            str(gateway_dir / "framed_fixture.py"),
            "--device-id",
            args.device_id,
            "--site",
            args.site,
            "--count",
            str(args.frame_count),
            "--device-table",
            str(device_table),
            "--provisioning-input",
            str(provisioning_input),
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
            "--ingest-profile",
            DEFAULT_INGEST_PROFILE,
            "--window",
            str(args.frame_window),
        ],
        cwd=REPO_ROOT,
    )

    run_cmd(
        "Materializing canonical provisioning records",
        [
            sys.executable,
            str(gateway_dir / "provisioning_records.py"),
            "--authoritative-input",
            str(provisioning_input),
            "--site",
            args.site,
            "--out",
            str(provisioning_records),
        ],
        cwd=REPO_ROOT,
    )

    run_cmd(
        "Projecting SensorThings view",
        [
            sys.executable,
            str(gateway_dir / "sensorthings_projection.py"),
            "--facts",
            str(facts_dir),
            "--site",
            args.site,
            "--provisioning-records",
            str(provisioning_records),
            "--out",
            str(sensorthings_projection),
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

    if channels["ots"]["enabled"]:
        try:
            run_cmd(
                "Anchoring day artifact",
                [sys.executable, str(gateway_dir / "ots_anchor.py"), str(day_cbor)],
                cwd=REPO_ROOT,
            )
            channels["ots"] = _channel(True, STATUS_PENDING, "proof-created")
        except subprocess.CalledProcessError as exc:
            channels["ots"] = _channel(
                True, STATUS_FAILED, f"ots-stamp-error:{exc.returncode}"
            )
            if strict_mode:
                raise RuntimeError("OTS anchoring failed under strict policy") from exc

    tsa_enabled = channels["tsa"]["enabled"]
    if tsa_enabled:
        tsa_url = cfg.tsa.url
        tsa_ca = (
            resolve_repo_path(Path(cfg.tsa.ca_bundle)) if cfg.tsa.ca_bundle else None
        )
        tsa_chain = (
            resolve_repo_path(Path(cfg.tsa.chain_bundle))
            if cfg.tsa.chain_bundle
            else None
        )
        tsa_strict = args.tsa_strict or strict_mode
        if not tsa_url:
            channels["tsa"] = _channel(True, STATUS_MISSING, "tsa-url-not-configured")
            if tsa_strict:
                raise RuntimeError("TSA enabled under strict policy but URL is missing")
        else:
            try:
                print("[pipeline] Anchoring day artifact with RFC 3161 TSA")
                tsa_result = tsa_stamp_day_blob(
                    day_blob=day_cbor,
                    tsa_url=tsa_url,
                    out_dir=tsa_out_dir,
                    tsa_ca_pem=tsa_ca,
                    tsa_chain_pem=tsa_chain,
                    policy_oid=cfg.tsa.policy_oid or None,
                    timeout_s=cfg.tsa.timeout_s,
                    verify_response=cfg.tsa.verify or bool(tsa_ca or tsa_chain),
                )
                tsa_artifacts = {
                    "tsa_tsq": tsa_result.tsq,
                    "tsa_tsr": tsa_result.tsr,
                    "tsa_meta": tsa_result.tsr_json,
                }
                status = STATUS_VERIFIED if tsa_result.verified else STATUS_PENDING
                channels["tsa"] = _channel(True, status, "tsa-stamp-ok")
                print(
                    f"[pipeline] TSA response stored: {rel(tsa_result.tsr)} (verified={tsa_result.verified})"
                )
            except (
                TsaStampError,
                subprocess.CalledProcessError,
            ) as exc:
                channels["tsa"] = _channel(True, STATUS_FAILED, f"tsa-error:{exc}")
                if tsa_strict:
                    raise RuntimeError(
                        "TSA anchoring failed under strict policy"
                    ) from exc
                print(f"[pipeline] WARN: TSA stamping failed ({exc})", file=sys.stderr)

    peers_enabled = channels["peers"]["enabled"]
    if peers_enabled:
        peer_config_path = (
            resolve_repo_path(Path(cfg.peers.config_path))
            if cfg.peers.config_path
            else None
        )
        peers_strict = args.peers_strict or strict_mode
        if peer_config_path is None or not peer_config_path.exists():
            channels["peers"] = _channel(True, STATUS_MISSING, "peer-config-not-found")
            if peers_strict:
                raise RuntimeError(
                    "Peers enabled under strict policy but peer config is missing"
                )
        else:
            try:
                peer_mod = _load_peer_attestation()
                if peer_mod is None:
                    raise RuntimeError("peer-attestation-module-unavailable")
                write_peer_attestations = peer_mod

                peer_dir.mkdir(parents=True, exist_ok=True)
                day_root_hex = json.loads(
                    day_cbor.with_suffix(".json").read_text(encoding="utf-8")
                )["day_root"]
                result = write_peer_attestations(
                    site_id=args.site,
                    day=args.date,
                    day_root_hex=day_root_hex,
                    peer_config=peer_config_path,
                    out_dir=peer_dir,
                    min_signatures=cfg.peers.min_signatures,
                    context=cfg.peers.context.encode(),
                )
                peer_attest_path = result.path
                channels["peers"] = _channel(
                    True, STATUS_VERIFIED, "peer-signatures-collected"
                )
                print(
                    f"[pipeline] Peer signatures stored: {rel(result.path)} ({len(result.signatures)} signatures)"
                )
            except (
                FileNotFoundError,
                json.JSONDecodeError,
                RuntimeError,
                ValueError,
            ) as exc:
                channels["peers"] = _channel(True, STATUS_FAILED, f"peer-error:{exc}")
                if peers_strict:
                    raise RuntimeError(
                        "Peer attestation failed under strict policy"
                    ) from exc
                print(
                    f"[pipeline] WARN: peer attestation failed ({exc})", file=sys.stderr
                )

    expected_artifacts = [
        day_cbor,
        day_cbor.with_suffix(".json"),
        day_cbor.with_suffix(".cbor.sha256"),
        provisioning_records,
        sensorthings_projection,
        provisioning_input,
    ]
    if channels["ots"]["status"] in {STATUS_VERIFIED, STATUS_PENDING}:
        expected_artifacts.append(Path(f"{day_cbor}.ots"))
    if tsa_artifacts:
        expected_artifacts.extend(tsa_artifacts.values())
    if peer_attest_path:
        expected_artifacts.append(peer_attest_path)

    missing = [p for p in expected_artifacts if not p.exists()]
    if missing:
        missing_str = ", ".join(rel(p) for p in missing)
        raise RuntimeError(f"Missing expected artifacts: {missing_str}")

    overall = compute_overall_status(policy_mode=cfg.policy.mode, channels=channels)
    anchoring_summary = {
        "policy": {"mode": cfg.policy.mode},
        "channels": channels,
        "overall": overall,
    }
    verifier_summary: dict[str, Any] | None = None

    manifest_path = artifact_manifest(
        args.date,
        args.site,
        args.device_id,
        args.frame_count,
        frames_file,
        facts_dir,
        day_cbor,
        out_dir,
        anchoring=anchoring_summary,
        tsa_artifacts=tsa_artifacts,
        peer_attest=peer_attest_path,
        verifier_summary=verifier_summary,
        sensorthings_projection=sensorthings_projection,
        provisioning_input=provisioning_input,
        provisioning_records=provisioning_records,
        disclosure_class=args.disclosure_class,
        commitment_profile_id=args.commitment_profile_id,
    )

    verify_rc, verifier_summary = _run_verify_cli(
        gateway_dir=gateway_dir,
        root=out_dir,
        facts_dir=facts_dir,
        cfg=cfg,
        skip_ots=args.skip_ots,
        skip_tsa=args.skip_tsa,
        skip_peers=args.skip_peers,
        disclosure_class=args.disclosure_class,
        commitment_profile_id=args.commitment_profile_id,
    )
    if verify_rc != 0:
        local_failure = local_verification_failure(verifier_summary)
        if local_failure is not None:
            raise RuntimeError(
                f"verify_cli failed local verification gate: {local_failure}"
            )
        print(
            f"[pipeline] WARN: verify_cli exited with code {verify_rc} "
            "(local integrity checks passed; anchoring remains policy-driven)",
            file=sys.stderr,
        )
    if verifier_summary is None:
        raise RuntimeError("verify_cli did not emit a machine-readable summary")
    local_failure = local_verification_failure(verifier_summary)
    if local_failure is not None:
        raise RuntimeError(
            f"verify_cli failed local verification gate: {local_failure}"
        )

    channels_val = verifier_summary.get("channels")
    if isinstance(channels_val, dict):
        for name in ("ots", "tsa", "peers"):
            item = channels_val.get(name)
            if isinstance(item, dict):
                channels[name] = dict(item)

    overall = compute_overall_status(policy_mode=cfg.policy.mode, channels=channels)
    anchoring_summary = {
        "policy": {"mode": cfg.policy.mode},
        "channels": channels,
        "overall": overall,
    }
    manifest_path = artifact_manifest(
        args.date,
        args.site,
        args.device_id,
        args.frame_count,
        frames_file,
        facts_dir,
        day_cbor,
        out_dir,
        anchoring=anchoring_summary,
        tsa_artifacts=tsa_artifacts,
        peer_attest=peer_attest_path,
        verifier_summary=verifier_summary,
        sensorthings_projection=sensorthings_projection,
        provisioning_input=provisioning_input,
        provisioning_records=provisioning_records,
        disclosure_class=args.disclosure_class,
        commitment_profile_id=args.commitment_profile_id,
    )

    if overall == "success":
        print("[pipeline] ✓ Pipeline completed successfully")
    else:
        print(
            f"[pipeline] WARN: pipeline completed with overall anchoring status "
            f"{overall!r} (policy mode={cfg.policy.mode})",
            file=sys.stderr,
        )
        if cfg.policy.mode == STRICT:
            raise SystemExit(1)
    for path in expected_artifacts + [manifest_path]:
        print(f"[pipeline]   - {rel(path)}")


if __name__ == "__main__":
    main()
