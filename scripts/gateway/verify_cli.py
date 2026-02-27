#!/usr/bin/env python3
"""Verify Merkle root and anchoring artifacts for a day's telemetry batch."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # nosec B404
import sys
from collections.abc import Iterable
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

try:  # Support both package imports and direct script execution.
    from .anchoring_config import (
        STRICT,
        AnchoringConfig,
        compute_overall_status,
        load_anchoring_config,
    )
    from .canonical_cbor import canonicalize_obj_to_cbor
except ImportError:  # pragma: no cover - fallback when run as a script
    from anchoring_config import (  # type: ignore
        STRICT,
        AnchoringConfig,
        compute_overall_status,
        load_anchoring_config,
    )
    from canonical_cbor import canonicalize_obj_to_cbor  # type: ignore

EXIT_OTS_NOT_FOUND = 3
EXIT_OTS_FAILED = 4
EXIT_TSA_FAILED = 5
EXIT_PEERS_FAILED = 6
EXIT_ARTIFACT_PATH_MISMATCH = 7
EXIT_META_INVALID = 8
EXIT_ARTIFACT_HASH_MISMATCH = 9

STATUS_VERIFIED = "verified"
STATUS_FAILED = "failed"
STATUS_MISSING = "missing"
STATUS_PENDING = "pending"
STATUS_SKIPPED = "skipped"

# Optional Rust extension (`trackone_core`) for single-sourced ledger policy.
_RUST_MERKLE: Any | None = None
_RUST_LEDGER: Any | None = None
try:  # pragma: no cover - optional acceleration
    import trackone_core

    native = getattr(trackone_core, "_native", None)
    if native is not None:
        rust_mod = native
    elif not hasattr(trackone_core, "__path__"):
        rust_mod = trackone_core
    else:
        rust_mod = None

    if rust_mod is not None:
        _RUST_MERKLE = getattr(rust_mod, "merkle", None)
        _RUST_LEDGER = getattr(rust_mod, "ledger", None)
except Exception:  # pragma: no cover - extension not built/installed or init failed
    trackone_core = None  # type: ignore[assignment]
    _RUST_MERKLE = None
    _RUST_LEDGER = None


def merkle_root(leaves: Iterable[bytes]) -> str:
    leaves_list = list(leaves)
    if _RUST_MERKLE is not None:
        try:  # pragma: no cover - exercised when Rust extension is available
            root_hex, _leaf_hashes = cast(
                tuple[str, list[str]],
                _RUST_MERKLE.merkle_root_hex_and_leaf_hashes(leaves_list),
            )
            return root_hex
        except (ImportError, RuntimeError, TypeError, ValueError) as e:
            print(
                f"[WARN] Rust merkle failed, falling back to Python: {e}",
                file=sys.stderr,
            )
    if not leaves_list:
        return sha256(b"").hexdigest()
    leaf_hashes = [sha256(leaf).hexdigest() for leaf in leaves_list]
    leaf_hashes_sorted = sorted(leaf_hashes)
    layer = [bytes.fromhex(hx) for hx in leaf_hashes_sorted]
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            a = layer[i]
            b = layer[i + 1] if i + 1 < len(layer) else layer[i]
            nxt.append(sha256(a + b).digest())
        layer = nxt
    return layer[0].hex()


def verify_ots(
    ots_path: Path,
    allow_placeholder: bool = True,
    expected_artifact_sha: str | None = None,
) -> bool:
    """Verify an OTS proof file."""
    try:
        raw = ots_path.read_bytes()
        if raw.startswith(b"STATIONARY-OTS:"):
            if not allow_placeholder:
                return False
            try:
                parts = raw.split(b":", 1)
                if len(parts) != 2:
                    return False
                stub_hex = parts[1].strip().splitlines()[0].decode("ascii")
                if expected_artifact_sha:
                    return stub_hex == expected_artifact_sha
                artifact_candidate = ots_path.with_suffix("")
                if artifact_candidate.exists():
                    actual_sha = sha256(artifact_candidate.read_bytes()).hexdigest()
                    return actual_sha == stub_hex
                return False
            except (OSError, UnicodeDecodeError):
                return False
        if raw.strip() == b"OTS_PROOF_PLACEHOLDER" and allow_placeholder:
            return True
    except (OSError, UnicodeDecodeError):
        pass

    ots_exe = shutil.which("ots")
    if not ots_exe:
        return False
    ots_path_obj = Path(ots_exe).resolve()
    if not ots_path_obj.is_file() or not os.access(str(ots_path_obj), os.X_OK):
        return False
    try:
        result = subprocess.run(
            [str(ots_path_obj), "verify", str(ots_path)], capture_output=True, text=True
        )  # nosec B603
        return result.returncode == 0
    except (subprocess.CalledProcessError, OSError):
        return False


def verify_tsa(tsr_path: Path, day_artifact: Path) -> bool:
    """Verify RFC 3161 TSA timestamp response against day artifact."""
    if not tsr_path.exists() or not day_artifact.exists():
        return False

    openssl_exe = shutil.which("openssl")
    if not openssl_exe:
        tsr_json = tsr_path.with_suffix(".tsr.json")
        if not tsr_json.exists():
            return False
        try:
            meta = json.loads(tsr_json.read_text(encoding="utf-8"))
            day_hash = sha256(day_artifact.read_bytes()).hexdigest()
            imprint = meta.get("message_imprint", "").replace(":", "").lower()
            return imprint == day_hash  # type: ignore
        except (json.JSONDecodeError, OSError):
            return False

    try:
        result = subprocess.run(
            [
                openssl_exe,
                "ts",
                "-verify",
                "-in",
                str(tsr_path),
                "-data",
                str(day_artifact),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False


def verify_peer_signatures(
    peer_attest_path: Path, site_id: str, day: str, day_root_hex: str
) -> tuple[bool, int]:
    """Verify peer co-signatures from peer attestation file."""
    if not peer_attest_path.exists():
        return False, 0
    verify_fn = _load_peer_verify_fn()
    if verify_fn is None:
        return False, 0
    try:
        data = json.loads(peer_attest_path.read_text(encoding="utf-8"))
        signatures = data.get("signatures", [])
        context = data.get("context", "trackone:day-root:v1").encode()
        valid_count = 0
        for sig in signatures:
            if verify_fn(
                site_id=site_id,
                day=day,
                day_root_hex=day_root_hex,
                signature_hex=sig["signature_hex"],
                pubkey_hex=sig["pubkey_hex"],
                context=context,
            ):
                valid_count += 1
        return valid_count == len(signatures) and len(signatures) > 0, len(signatures)
    except (json.JSONDecodeError, OSError, KeyError, ImportError):
        return False, 0


def _load_peer_verify_fn() -> Any | None:
    """Resolve peer signature verifier without hard dependency at import time."""
    verify_fn: Any | None = None
    try:
        from .peer_attestation import verify_peer_signature as verify_fn_primary

        verify_fn = verify_fn_primary
    except ImportError:
        try:
            from peer_attestation import (  # type: ignore[import-not-found]
                verify_peer_signature as verify_fn_fallback,
            )

            verify_fn = verify_fn_fallback
        except ImportError:
            pass
    return verify_fn


def _channel(enabled: bool, status: str, reason: str = "") -> dict[str, Any]:
    return {"enabled": enabled, "status": status, "reason": reason}


def _emit(summary: dict[str, Any], json_mode: bool) -> None:
    if json_mode:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return
    print(
        f"Policy={summary['policy']['mode']} Overall={summary['overall']} "
        f"RootMatch={summary['checks']['root_match']}"
    )
    for name in ("ots", "tsa", "peers"):
        item = summary["channels"][name]
        print(
            f"{name.upper()}: enabled={item['enabled']} status={item['status']} reason={item['reason']}"
        )


def _load_cfg(args: argparse.Namespace) -> AnchoringConfig:
    cli_overrides: dict[str, Any] = {
        "policy_mode": args.policy_mode,
        "peers_min_signatures": args.peers_min,
    }
    return load_anchoring_config(config_path=args.config, cli_overrides=cli_overrides)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Verify Merkle root and anchoring artifacts for a day"
    )
    p.add_argument(
        "--root", type=Path, required=True, help="Path to out/site_demo root directory"
    )
    p.add_argument(
        "--facts",
        type=Path,
        required=True,
        help="Directory with fact CBOR files to recompute the Merkle root",
    )
    p.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Anchoring config path (default: ./anchoring.toml)",
    )
    p.add_argument(
        "--policy-mode",
        choices=["warn", "strict"],
        default=None,
        help="Override policy mode from config",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable summary JSON",
    )
    p.add_argument(
        "--verify-tsa",
        action="store_true",
        help="Force RFC 3161 TSA verification check",
    )
    p.add_argument(
        "--tsa-strict",
        action="store_true",
        help="Treat TSA verification failure as fatal (exit 5)",
    )
    p.add_argument(
        "--verify-peers",
        action="store_true",
        help="Force peer co-signature verification check",
    )
    p.add_argument(
        "--peers-strict",
        action="store_true",
        help="Treat peer verification failure as fatal (exit 6)",
    )
    p.add_argument(
        "--peers-min",
        type=int,
        default=None,
        help="Minimum peer signatures required (defaults from config)",
    )

    group = p.add_mutually_exclusive_group()
    group.add_argument(
        "--require-ots",
        action="store_true",
        help="Require a real OTS proof (placeholder not accepted).",
    )
    group.add_argument(
        "--allow-placeholder",
        action="store_true",
        help="Allow placeholder OTS proofs explicitly.",
    )

    args = p.parse_args(argv)
    cfg = _load_cfg(args)
    strict_mode = cfg.policy.mode == STRICT

    allow_placeholder = True
    if args.require_ots:
        allow_placeholder = False
    elif args.allow_placeholder:
        allow_placeholder = True
    elif strict_mode:
        allow_placeholder = False

    root_dir = args.root
    facts_dir = args.facts
    blocks_dir = root_dir / "blocks"
    day_dir = root_dir / "day"

    block_files = sorted(blocks_dir.glob("*.block.json"))
    if not block_files:
        print("ERROR: No block header found.")
        return 1
    block_path = block_files[0]
    with block_path.open("r", encoding="utf-8") as f:
        block_header = json.load(f)
    day = block_header.get("day")
    if not isinstance(day, str) or len(day) != 10:
        print(f"ERROR: Invalid or missing 'day' in block header: {block_path}")
        return 1

    day_cbor_path = day_dir / f"{day}.cbor"
    day_bin_legacy = day_dir / f"{day}.bin"
    using_legacy_day_bin = False
    if day_cbor_path.exists():
        day_artifact = day_cbor_path
    elif day_bin_legacy.exists():
        using_legacy_day_bin = True
        day_artifact = day_bin_legacy
        print(
            f"[WARN] Using legacy day artifact ({day_bin_legacy}). "
            "Please migrate to .cbor commitments.",
            file=sys.stderr,
        )
    else:
        day_artifact = day_cbor_path
    ots_path = day_artifact.with_suffix(day_artifact.suffix + ".ots")
    recorded_root = block_header.get("merkle_root")
    if not isinstance(recorded_root, str) or len(recorded_root) != 64:
        print(f"ERROR: Invalid or missing 'merkle_root' in block header: {block_path}")
        return 1

    summary: dict[str, Any] = {
        "policy": {"mode": cfg.policy.mode},
        "artifacts": {
            "block": str(block_path),
            "day_cbor": str(day_artifact),
            "day_ots": str(ots_path),
        },
        "checks": {
            "root_match": False,
            "artifact_valid": False,
            "meta_valid": True,
        },
        "channels": {
            "ots": _channel(
                cfg.ots.enabled or args.require_ots, STATUS_SKIPPED, "disabled"
            ),
            "tsa": _channel(
                args.verify_tsa or cfg.tsa.enabled, STATUS_SKIPPED, "disabled"
            ),
            "peers": _channel(
                args.verify_peers or cfg.peers.enabled, STATUS_SKIPPED, "disabled"
            ),
        },
        "overall": "failed",
    }

    # Optional OTS metadata sidecar checks
    repo_root = root_dir.parent
    meta_path = repo_root / "proofs" / f"{day}.ots.meta.json"
    meta: dict[str, Any] | None = None
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            print(f"ERROR: Failed to parse OTS meta file {meta_path}")
            summary["checks"]["meta_valid"] = False
            _emit(summary, args.json)
            return EXIT_META_INVALID

        artifact_rel = meta.get("artifact")
        expected_sha = meta.get("artifact_sha256")
        meta_ots_rel = meta.get("ots_proof")

        if isinstance(artifact_rel, str):
            resolved_artifact = (repo_root / artifact_rel).resolve()
            if resolved_artifact != day_artifact.resolve():
                print(
                    f"ERROR: OTS meta artifact path mismatch. Meta artifact={resolved_artifact}, "
                    f"expected {day_artifact}"
                )
                summary["checks"]["meta_valid"] = False
                _emit(summary, args.json)
                return EXIT_ARTIFACT_PATH_MISMATCH

        if isinstance(expected_sha, str) and len(expected_sha) == 64:
            if not day_artifact.exists():
                print(f"ERROR: OTS meta present but artifact missing: {day_artifact}")
                summary["checks"]["meta_valid"] = False
                _emit(summary, args.json)
                return EXIT_META_INVALID
            actual_sha = sha256(day_artifact.read_bytes()).hexdigest()
            if actual_sha != expected_sha:
                print(
                    f"ERROR: OTS meta artifact_sha256 mismatch. Expected={expected_sha}, Actual={actual_sha}"
                )
                summary["checks"]["meta_valid"] = False
                _emit(summary, args.json)
                return EXIT_ARTIFACT_HASH_MISMATCH

        if isinstance(meta_ots_rel, str):
            resolved_meta_ots = (repo_root / meta_ots_rel).resolve()
            if resolved_meta_ots != ots_path.resolve():
                print(
                    f"ERROR: OTS meta ots_proof path mismatch. Meta ots={resolved_meta_ots}, "
                    f"expected {ots_path}"
                )
                summary["checks"]["meta_valid"] = False
                _emit(summary, args.json)
                return EXIT_ARTIFACT_PATH_MISMATCH
            if not ots_path.exists():
                print(f"ERROR: OTS meta present but proof missing: {ots_path}")
                summary["checks"]["meta_valid"] = False
                _emit(summary, args.json)
                return EXIT_OTS_NOT_FOUND

    # Parse and validate day artifact
    if day_artifact.exists():
        day_json_path = day_artifact.with_suffix(".json")
        if not day_json_path.exists():
            print(f"ERROR: day projection not found: {day_json_path}")
            _emit(summary, args.json)
            return 1

        try:
            day_bytes = day_artifact.read_bytes()
            any_val = json.loads(day_json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"ERROR: Failed to parse day projection {day_json_path}: {exc}")
            _emit(summary, args.json)
            return 1
        if not isinstance(any_val, dict):
            print(f"ERROR: day projection must be a JSON object: {day_json_path}")
            _emit(summary, args.json)
            return 1
        day_record: dict[str, Any] = any_val

        try:
            day_json_bytes = day_json_path.read_bytes()
            canon: bytes | None = None
            if using_legacy_day_bin:
                canon = json.dumps(
                    day_record, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            else:
                if _RUST_LEDGER is not None and hasattr(
                    _RUST_LEDGER, "canonicalize_json_to_cbor_bytes"
                ):
                    try:  # pragma: no cover - exercised when Rust extension is available
                        canon = bytes(
                            _RUST_LEDGER.canonicalize_json_to_cbor_bytes(day_json_bytes)
                        )
                    except (RuntimeError, TypeError, ValueError):
                        canon = None
                if canon is None:
                    canon = canonicalize_obj_to_cbor(day_record)
        except (OSError, TypeError, ValueError) as exc:
            print(
                f"ERROR: Failed to canonicalize day projection {day_json_path} into "
                f"{'JSON' if using_legacy_day_bin else 'CBOR'} commitment bytes: {exc}"
            )
            _emit(summary, args.json)
            return 1

        if canon != day_bytes:
            if using_legacy_day_bin:
                print(
                    f"ERROR: legacy day artifact is not canonical JSON commitment bytes: {day_artifact}"
                )
            else:
                print(
                    f"ERROR: day artifact is not canonical commitment bytes: {day_artifact}"
                )
            _emit(summary, args.json)
            return 1

        day_root = day_record.get("day_root")
        if day_root != recorded_root:
            print(
                "ERROR: day_root mismatch between day artifact and block header. "
                f"day={day_root}, block_header={recorded_root}"
            )
            _emit(summary, args.json)
            return 2

        if day_record.get("date") != day:
            print(
                "ERROR: day artifact date mismatch. "
                f"day.date={day_record.get('date')}, block_header.day={day}"
            )
            _emit(summary, args.json)
            return 1
        if day_record.get("site_id") != block_header.get("site_id"):
            print(
                "ERROR: day artifact site_id mismatch. "
                f"day.site_id={day_record.get('site_id')}, block_header.site_id={block_header.get('site_id')}"
            )
            _emit(summary, args.json)
            return 1
        summary["checks"]["artifact_valid"] = True
    else:
        print(f"ERROR: day artifact not found: {day_artifact}")
        _emit(summary, args.json)
        return 1

    # Recompute Merkle root
    fact_files = sorted(facts_dir.glob("*.cbor"))
    if not fact_files:
        json_candidates = sorted(facts_dir.glob("*.json"))
        if json_candidates:
            print(
                "ERROR: JSON facts found but CBOR facts are required for commitments (ADR-039)."
            )
            _emit(summary, args.json)
            return 1
    leaves: list[bytes] = []
    for fpath in fact_files:
        try:
            leaves.append(fpath.read_bytes())
        except OSError as exc:
            print(f"ERROR: Failed to read fact artifact {fpath}: {exc}")
            _emit(summary, args.json)
            return 1

    recomputed_root = merkle_root(leaves)
    if recomputed_root != recorded_root:
        print(
            f"ERROR: Merkle root mismatch. Computed: {recomputed_root}, Recorded: {recorded_root}"
        )
        summary["checks"]["root_match"] = False
        _emit(summary, args.json)
        return 2
    summary["checks"]["root_match"] = True

    # OTS channel
    check_ots = cfg.ots.enabled or args.require_ots
    require_ots = args.require_ots or (strict_mode and check_ots)
    if check_ots:
        if not ots_path.exists():
            summary["channels"]["ots"] = _channel(
                True, STATUS_MISSING, "ots-proof-not-found"
            )
            if require_ots:
                summary["overall"] = "failed"
                _emit(summary, args.json)
                return EXIT_OTS_NOT_FOUND
        else:
            expected_sha_from_meta: str | None = None
            if meta is not None and isinstance(meta.get("artifact_sha256"), str):
                expected_sha_from_meta = cast(
                    str, cast(object, meta["artifact_sha256"])
                )
            ok = verify_ots(
                ots_path,
                allow_placeholder=allow_placeholder,
                expected_artifact_sha=expected_sha_from_meta,
            )
            if ok:
                summary["channels"]["ots"] = _channel(
                    True, STATUS_VERIFIED, "ots-verified"
                )
            else:
                summary["channels"]["ots"] = _channel(
                    True, STATUS_FAILED, "ots-verification-failed"
                )
                summary["overall"] = "failed"
                _emit(summary, args.json)
                return EXIT_OTS_FAILED
    else:
        summary["channels"]["ots"] = _channel(False, STATUS_SKIPPED, "disabled")

    # TSA channel
    check_tsa = args.verify_tsa or cfg.tsa.enabled
    tsa_strict = args.tsa_strict or (strict_mode and check_tsa)
    if check_tsa:
        tsr_path = day_artifact.parent / f"{day}.tsr"
        if tsr_path.exists():
            if verify_tsa(tsr_path, day_artifact):
                summary["channels"]["tsa"] = _channel(
                    True, STATUS_VERIFIED, "tsa-verified"
                )
            else:
                summary["channels"]["tsa"] = _channel(
                    True, STATUS_FAILED, "tsa-verification-failed"
                )
                if tsa_strict:
                    summary["overall"] = "failed"
                    _emit(summary, args.json)
                    return EXIT_TSA_FAILED
        else:
            summary["channels"]["tsa"] = _channel(
                True, STATUS_MISSING, "tsa-artifact-not-found"
            )
            if tsa_strict:
                summary["overall"] = "failed"
                _emit(summary, args.json)
                return EXIT_TSA_FAILED
    else:
        summary["channels"]["tsa"] = _channel(False, STATUS_SKIPPED, "disabled")

    # Peer channel
    check_peers = args.verify_peers or cfg.peers.enabled
    peers_strict = args.peers_strict or (strict_mode and check_peers)
    peers_min = (
        args.peers_min if args.peers_min is not None else cfg.peers.min_signatures
    )
    if check_peers:
        peer_attest_path = day_artifact.parent / "peers" / f"{day}.peers.json"
        if peer_attest_path.exists():
            site_id = block_header.get("site_id", "")
            all_valid, sig_count = verify_peer_signatures(
                peer_attest_path, site_id, day, recorded_root
            )
            if all_valid and sig_count >= peers_min:
                summary["channels"]["peers"] = _channel(
                    True, STATUS_VERIFIED, f"{sig_count}-signatures"
                )
            else:
                summary["channels"]["peers"] = _channel(
                    True,
                    STATUS_FAILED,
                    f"insufficient-or-invalid-signatures:{sig_count}",
                )
                if peers_strict:
                    summary["overall"] = "failed"
                    _emit(summary, args.json)
                    return EXIT_PEERS_FAILED
        else:
            summary["channels"]["peers"] = _channel(
                True, STATUS_MISSING, "peer-attestation-not-found"
            )
            if peers_strict:
                summary["overall"] = "failed"
                _emit(summary, args.json)
                return EXIT_PEERS_FAILED
    else:
        summary["channels"]["peers"] = _channel(False, STATUS_SKIPPED, "disabled")

    summary["overall"] = compute_overall_status(
        policy_mode=cfg.policy.mode, channels=summary["channels"]
    )
    _emit(summary, args.json)
    return 0 if summary["overall"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
