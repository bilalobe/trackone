#!/usr/bin/env python3
"""Verify Merkle root and anchoring artifacts for a day's telemetry batch."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess  # nosec B404
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

import trackone_core.ledger as ledger
import trackone_core.merkle as merkle
import trackone_core.ots as ots
from trackone_core.constants import OTS_VERIFY_TIMEOUT_SECS
from trackone_core.release import DEFAULT_COMMITMENT_PROFILE_ID
from trackone_core.verification import (
    CHECK_BATCH_METADATA,
    CHECK_DAY_ARTIFACT,
    CHECK_FACT_RECOMPUTE,
    CHECK_MANIFEST,
    CHECK_OTS,
    CHECK_PEERS,
    CHECK_TSA,
    STATUS_FAILED,
    STATUS_MISSING,
    STATUS_PENDING,
    STATUS_SKIPPED,
    STATUS_VERIFIED,
    build_verifier_summary,
    record_executed_check,
    record_skipped_check,
    refresh_publicly_recomputable,
    set_channel,
    set_manifest_status,
)

try:  # Support both package imports and direct script execution.
    from .anchoring_config import (
        STRICT,
        AnchoringConfig,
        compute_overall_status,
        load_anchoring_config,
    )
    from .schema_validation import (
        SCHEMA_VALIDATION_EXCEPTIONS,
        load_schema,
        require_schema_validation,
        validate_instance,
    )
    from .verification_manifest import manifest_candidates
except ImportError:  # pragma: no cover - fallback when run as a script
    from anchoring_config import (  # type: ignore
        STRICT,
        AnchoringConfig,
        compute_overall_status,
        load_anchoring_config,
    )
    from schema_validation import (  # type: ignore
        SCHEMA_VALIDATION_EXCEPTIONS,
        load_schema,
        require_schema_validation,
        validate_instance,
    )
    from verification_manifest import manifest_candidates  # type: ignore

_MANIFEST_EXCEPTIONS: tuple[type[BaseException], ...] = (
    OSError,
    UnicodeDecodeError,
    json.JSONDecodeError,
    ValueError,
    RuntimeError,
) + SCHEMA_VALIDATION_EXCEPTIONS

EXIT_OTS_NOT_FOUND = 3
EXIT_OTS_FAILED = 4
EXIT_TSA_FAILED = 5
EXIT_PEERS_FAILED = 6
EXIT_ARTIFACT_PATH_MISMATCH = 7
EXIT_META_INVALID = 8
EXIT_ARTIFACT_HASH_MISMATCH = 9


def merkle_root(leaves: Iterable[bytes]) -> str:
    leaves_list = list(leaves)
    try:  # pragma: no cover - exercised when Rust extension is available
        root_hex, _leaf_hashes = cast(
            tuple[str, list[str]],
            merkle.merkle_root_hex_and_leaf_hashes(leaves_list),
        )
        return root_hex
    except (AttributeError, ImportError) as exc:
        raise RuntimeError(
            "trackone_core native merkle helper is required for authoritative "
            "verification paths. Build/install the native extension or run via tox."
        ) from exc
    except (RuntimeError, TypeError, ValueError) as exc:
        raise RuntimeError(
            "trackone_core native merkle helper failed during authoritative "
            "verification"
        ) from exc


def _coerce_ots_status_name(result: Any) -> str:
    status_name = getattr(result, "status_name", None)
    if isinstance(status_name, str):
        return status_name

    status = getattr(result, "status", None)
    if isinstance(status, str):
        return status

    value = getattr(status, "value", None)
    if isinstance(value, str):
        return value

    text = str(status).strip().lower()
    if text.startswith("otsstatus."):
        return text.split(".", 1)[1]
    return text or STATUS_FAILED


def verify_ots_proof(
    ots_path: Path,
    allow_placeholder: bool = True,
    expected_artifact_sha: str | None = None,
) -> Any:
    """Verify an OTS proof through the public trackone_core.ots boundary."""
    try:  # pragma: no cover - exercised when Rust extension is available
        return ots.verify_ots_proof(
            str(ots_path),
            allow_placeholder=allow_placeholder,
            expected_artifact_sha=expected_artifact_sha,
            ots_binary=shutil.which("ots"),
            timeout_secs=OTS_VERIFY_TIMEOUT_SECS,
        )
    except (AttributeError, ImportError, RuntimeError, TypeError, ValueError) as exc:
        raise RuntimeError(
            "trackone_core native ots helper failed during proof verification"
        ) from exc


def verify_ots(
    ots_path: Path,
    allow_placeholder: bool = True,
    expected_artifact_sha: str | None = None,
) -> bool:
    """Verify an OTS proof file via the public OTS boundary."""
    return bool(
        verify_ots_proof(
            ots_path,
            allow_placeholder=allow_placeholder,
            expected_artifact_sha=expected_artifact_sha,
        )
    )


def validate_meta_sidecar(
    meta_path: Path,
    repo_root: Path,
    day_artifact: Path,
    ots_path: Path,
) -> Any:
    """Validate the OTS sidecar binding through the public OTS boundary."""
    try:  # pragma: no cover - exercised when Rust extension is available
        return ots.validate_meta_sidecar(
            str(meta_path.resolve()),
            str(repo_root.resolve()),
            str(day_artifact.resolve()),
            str(ots_path.resolve()),
        )
    except (AttributeError, ImportError, RuntimeError, TypeError, ValueError) as exc:
        raise RuntimeError(
            "trackone_core native ots helper failed during meta validation"
        ) from exc


def _meta_failure_exit(reason: str) -> int:
    if reason in {"meta-artifact-path-mismatch", "meta-ots-path-mismatch"}:
        return EXIT_ARTIFACT_PATH_MISMATCH
    if reason == "meta-artifact-hash-mismatch":
        return EXIT_ARTIFACT_HASH_MISMATCH
    if reason == "ots-proof-not-found":
        return EXIT_OTS_NOT_FOUND
    return EXIT_META_INVALID


def _meta_failure_message(
    reason: str, meta_path: Path, day_artifact: Path, ots_path: Path
) -> str:
    messages = {
        "meta-read-failed": f"ERROR: Failed to read OTS meta file {meta_path}",
        "meta-parse-failed": f"ERROR: Failed to parse OTS meta file {meta_path}",
        "meta-missing-fields": f"ERROR: OTS meta file missing required fields: {meta_path}",
        "meta-artifact-path-mismatch": (
            f"ERROR: OTS meta artifact path mismatch for {day_artifact}"
        ),
        "meta-day-mismatch": f"ERROR: OTS meta day mismatch for {day_artifact}",
        "meta-artifact-missing": f"ERROR: OTS meta present but artifact missing: {day_artifact}",
        "meta-artifact-hash-mismatch": (
            f"ERROR: OTS meta artifact_sha256 mismatch for {day_artifact}"
        ),
        "meta-ots-path-mismatch": f"ERROR: OTS meta ots_proof path mismatch for {ots_path}",
        "ots-proof-not-found": f"ERROR: OTS meta present but proof missing: {ots_path}",
    }
    return messages.get(reason, f"ERROR: OTS metadata validation failed: {meta_path}")


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
            day_hash = ledger.sha256_hex(day_artifact.read_bytes())
            imprint = ledger.normalize_hex64(
                meta.get("message_imprint", "").replace(":", "")
            )
            return imprint == day_hash  # type: ignore
        except (json.JSONDecodeError, OSError, ValueError):
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


def _emit(summary: dict[str, Any], json_mode: bool) -> None:
    refresh_publicly_recomputable(summary)
    if json_mode:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return
    verification = summary.get("verification", {})
    disclosure = verification.get("disclosure_class", "A")
    public_claim = verification.get("publicly_recomputable", False)
    manifest = summary.get("manifest", {})
    manifest_status = manifest.get("status", "missing")
    manifest_source = manifest.get("source") or "n/a"
    print(
        f"Policy={summary['policy']['mode']} Disclosure={disclosure} "
        f"Overall={summary['overall']} RootMatch={summary['checks']['root_match']} "
        f"PubliclyRecomputable={public_claim} "
        f"Manifest={manifest_status}:{manifest_source}"
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


def _load_verification_manifest(
    manifest_path: Path, *, schema_name: str
) -> dict[str, Any] | None:
    if not manifest_path.exists():
        return None
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(
            f"verification manifest must be a JSON object: {manifest_path}"
        )
    schema = load_schema(schema_name)
    if schema is not None:
        require_schema_validation("verification manifest validation")
        validate_instance(data, schema)
    return data


def _manifest_artifact_path(root_dir: Path, artifact: dict[str, Any]) -> Path:
    path = artifact.get("path")
    if not isinstance(path, str) or not path:
        raise ValueError("manifest artifact entry missing path")
    resolved = (root_dir / path).resolve()
    if root_dir.resolve() not in resolved.parents and resolved != root_dir.resolve():
        raise ValueError(f"manifest artifact path escapes root: {path}")
    return resolved


def _resolve_meta_sidecar(root_dir: Path, day: str) -> tuple[Path, Path] | None:
    candidates: list[tuple[Path, Path]] = [
        (root_dir / "day" / f"{day}.ots.meta.json", root_dir),
        (root_dir / "proofs" / f"{day}.ots.meta.json", root_dir),
        (root_dir.parent / "proofs" / f"{day}.ots.meta.json", root_dir.parent),
    ]
    if root_dir.name == "site_demo" and root_dir.parent.name == "out":
        repo_root = root_dir.parent.parent
        candidates.append((repo_root / "proofs" / f"{day}.ots.meta.json", repo_root))

    seen: set[Path] = set()
    for meta_path, meta_root in candidates:
        resolved = meta_path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if meta_path.exists():
            return meta_path, meta_root

    return None


def _validate_verification_manifest(
    manifest: dict[str, Any],
    *,
    root_dir: Path,
    day: str,
    block_path: Path,
    day_artifact: Path,
    ots_path: Path,
    expected_site: str,
    disclosure_class: str,
    commitment_profile_id: str,
) -> None:
    if manifest.get("date") != day:
        raise ValueError(
            f"manifest date mismatch: expected {day}, got {manifest.get('date')}"
        )
    if manifest.get("site") != expected_site:
        raise ValueError(
            f"manifest site mismatch: expected {expected_site}, got {manifest.get('site')}"
        )

    verification_bundle = manifest.get("verification_bundle")
    if not isinstance(verification_bundle, dict):
        raise ValueError("manifest verification_bundle must be an object")
    if verification_bundle.get("disclosure_class") != disclosure_class:
        raise ValueError(
            "manifest disclosure_class mismatch: "
            f"expected {disclosure_class}, got {verification_bundle.get('disclosure_class')}"
        )
    if verification_bundle.get("commitment_profile_id") != commitment_profile_id:
        raise ValueError(
            "manifest commitment_profile_id mismatch: "
            f"expected {commitment_profile_id}, got {verification_bundle.get('commitment_profile_id')}"
        )

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("manifest artifacts must be an object")

    expected_paths = {
        "block": block_path.resolve(),
        "day_cbor": day_artifact.resolve(),
        "day_ots": ots_path.resolve(),
    }
    for name, artifact in artifacts.items():
        if not isinstance(artifact, dict):
            raise ValueError(f"manifest artifact must be an object: {name}")
        resolved = _manifest_artifact_path(root_dir, artifact)
        expected = expected_paths.get(name)
        if expected is not None and resolved != expected:
            raise ValueError(
                f"manifest artifact path mismatch for {name}: expected {expected}, got {resolved}"
            )
        if not resolved.exists():
            raise ValueError(f"manifest artifact missing on disk: {name} -> {resolved}")
        declared_sha = artifact.get("sha256")
        if not isinstance(declared_sha, str):
            raise ValueError(f"manifest artifact missing sha256: {name}")
        declared_sha = ledger.normalize_hex64(declared_sha)
        actual_sha = ledger.sha256_hex(resolved.read_bytes())
        if actual_sha != declared_sha:
            raise ValueError(
                f"manifest artifact sha256 mismatch for {name}: expected {declared_sha}, got {actual_sha}"
            )


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
    p.add_argument(
        "--disclosure-class",
        choices=["A", "B", "C"],
        default="A",
        help=(
            "Verification disclosure class: "
            "A=public recompute (uses --facts for fact-level recomputation), "
            "B=partner audit (skips fact-level recomputation; --facts is not used), "
            "C=anchor-only (skips fact-level recomputation; --facts is not used)."
        ),
    )
    p.add_argument(
        "--commitment-profile-id",
        default=DEFAULT_COMMITMENT_PROFILE_ID,
        help="Commitment profile identifier for verifier output metadata.",
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

    day_artifact = day_dir / f"{day}.cbor"
    _manifest_label, manifest_path, manifest_schema = manifest_candidates(day_dir, day)[
        0
    ]
    ots_path = day_artifact.with_suffix(day_artifact.suffix + ".ots")
    recorded_root = block_header.get("merkle_root")
    if not isinstance(recorded_root, str):
        print(f"ERROR: Invalid or missing 'merkle_root' in block header: {block_path}")
        return 1
    try:
        recorded_root = ledger.normalize_hex64(recorded_root)
    except ValueError:
        print(f"ERROR: Invalid or missing 'merkle_root' in block header: {block_path}")
        return 1

    summary = build_verifier_summary(
        policy_mode=cfg.policy.mode,
        disclosure_class=args.disclosure_class,
        commitment_profile_id=args.commitment_profile_id,
        manifest_schema=manifest_schema,
        block_path=block_path,
        day_artifact=day_artifact,
        ots_path=ots_path,
        manifest_path=manifest_path,
        ots_enabled=cfg.ots.enabled or args.require_ots,
        tsa_enabled=args.verify_tsa or cfg.tsa.enabled,
        peers_enabled=args.verify_peers or cfg.peers.enabled,
    )
    record_executed_check(summary, CHECK_DAY_ARTIFACT)

    if manifest_path.exists():
        record_executed_check(summary, CHECK_MANIFEST)
        record_executed_check(summary, CHECK_BATCH_METADATA)
        try:
            manifest = _load_verification_manifest(
                manifest_path, schema_name=manifest_schema
            )
            _validate_verification_manifest(
                manifest or {},
                root_dir=root_dir,
                day=day,
                block_path=block_path,
                day_artifact=day_artifact,
                ots_path=ots_path,
                expected_site=str(block_header.get("site_id", "")),
                disclosure_class=args.disclosure_class,
                commitment_profile_id=args.commitment_profile_id,
            )
        except _MANIFEST_EXCEPTIONS as exc:
            print(f"ERROR: verification manifest validation failed: {exc}")
            summary["checks"]["meta_valid"] = False
            set_manifest_status(
                summary,
                status="invalid",
                source=manifest_path.name,
                schema=manifest_schema,
            )
            _emit(summary, args.json)
            return EXIT_META_INVALID
        set_manifest_status(
            summary,
            status="present",
            source=manifest_path.name,
            schema=manifest_schema,
        )
    else:
        record_skipped_check(summary, CHECK_MANIFEST, "manifest-absent")
        record_skipped_check(summary, CHECK_BATCH_METADATA, "manifest-absent")

    # Optional OTS metadata sidecar checks
    meta: dict[str, Any] | None = None
    meta_binding = _resolve_meta_sidecar(root_dir, day)
    if meta_binding is not None:
        meta_path, meta_root = meta_binding
        meta_check = validate_meta_sidecar(meta_path, meta_root, day_artifact, ots_path)
        if not bool(getattr(meta_check, "ok", False)):
            reason = str(getattr(meta_check, "reason", "meta-invalid"))
            print(_meta_failure_message(reason, meta_path, day_artifact, ots_path))
            summary["checks"]["meta_valid"] = False
            _emit(summary, args.json)
            return _meta_failure_exit(reason)

        try:
            loaded_meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            print(f"ERROR: Failed to parse OTS meta file {meta_path}")
            summary["checks"]["meta_valid"] = False
            _emit(summary, args.json)
            return EXIT_META_INVALID
        if isinstance(loaded_meta, dict):
            meta = loaded_meta
        else:
            print(f"ERROR: OTS meta file missing required fields: {meta_path}")
            summary["checks"]["meta_valid"] = False
            _emit(summary, args.json)
            return EXIT_META_INVALID

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
            canon = bytes(ledger.canonicalize_json_to_cbor_bytes(day_json_bytes))
        except (AttributeError, ImportError):
            print(
                "ERROR: Failed to canonicalize day projection "
                f"{day_json_path} into CBOR commitment bytes: "
                "trackone_core native ledger helper is required for authoritative "
                "verification paths. Build/install the native extension or run via tox."
            )
            _emit(summary, args.json)
            return 1
        except (
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            print(
                f"ERROR: Failed to canonicalize day projection {day_json_path} into "
                f"CBOR commitment bytes: {exc}"
            )
            _emit(summary, args.json)
            return 1

        if canon != day_bytes:
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

    # Fact-level recomputation is only valid for disclosure class A.
    if args.disclosure_class == "A":
        record_executed_check(summary, CHECK_FACT_RECOMPUTE)
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

        try:
            recomputed_root = merkle_root(leaves)
        except RuntimeError as exc:
            print(f"ERROR: Failed to recompute authoritative Merkle root: {exc}")
            summary["checks"]["root_match"] = False
            _emit(summary, args.json)
            return 1
        if recomputed_root != recorded_root:
            print(
                f"ERROR: Merkle root mismatch. Computed: {recomputed_root}, Recorded: {recorded_root}"
            )
            summary["checks"]["root_match"] = False
            _emit(summary, args.json)
            return 2
        summary["checks"]["root_match"] = True
    else:
        record_skipped_check(
            summary,
            CHECK_FACT_RECOMPUTE,
            f"disclosure-class-{args.disclosure_class.lower()}",
        )

    # OTS channel
    check_ots = cfg.ots.enabled or args.require_ots
    require_ots = args.require_ots or (strict_mode and check_ots)
    if check_ots:
        record_executed_check(summary, CHECK_OTS)
        if not ots_path.exists():
            set_channel(
                summary,
                "ots",
                enabled=True,
                status=STATUS_MISSING,
                reason="ots-proof-not-found",
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
            ots_result = verify_ots_proof(
                ots_path,
                allow_placeholder=allow_placeholder,
                expected_artifact_sha=expected_sha_from_meta,
            )
            ots_ok = bool(getattr(ots_result, "ok", False))
            ots_reason = str(getattr(ots_result, "reason", "ots-verification-failed"))
            ots_status = _coerce_ots_status_name(ots_result)
            if ots_ok:
                if ots_status not in {STATUS_VERIFIED, STATUS_PENDING}:
                    ots_status = STATUS_VERIFIED
                set_channel(
                    summary,
                    "ots",
                    enabled=True,
                    status=ots_status,
                    reason=ots_reason,
                )
            else:
                if ots_status not in {STATUS_FAILED, STATUS_MISSING}:
                    ots_status = STATUS_FAILED
                set_channel(
                    summary,
                    "ots",
                    enabled=True,
                    status=ots_status,
                    reason=ots_reason,
                )
                summary["overall"] = "failed"
                _emit(summary, args.json)
                if ots_reason == "ots-proof-not-found":
                    return EXIT_OTS_NOT_FOUND
                return EXIT_OTS_FAILED
    else:
        set_channel(
            summary,
            "ots",
            enabled=False,
            status=STATUS_SKIPPED,
            reason="disabled",
        )

    # TSA channel
    check_tsa = args.verify_tsa or cfg.tsa.enabled
    tsa_strict = args.tsa_strict or (strict_mode and check_tsa)
    if check_tsa:
        record_executed_check(summary, CHECK_TSA)
        tsr_path = day_artifact.parent / f"{day}.tsr"
        if tsr_path.exists():
            if verify_tsa(tsr_path, day_artifact):
                set_channel(
                    summary,
                    "tsa",
                    enabled=True,
                    status=STATUS_VERIFIED,
                    reason="tsa-verified",
                )
            else:
                set_channel(
                    summary,
                    "tsa",
                    enabled=True,
                    status=STATUS_FAILED,
                    reason="tsa-verification-failed",
                )
                if tsa_strict:
                    summary["overall"] = "failed"
                    _emit(summary, args.json)
                    return EXIT_TSA_FAILED
        else:
            set_channel(
                summary,
                "tsa",
                enabled=True,
                status=STATUS_MISSING,
                reason="tsa-artifact-not-found",
            )
            if tsa_strict:
                summary["overall"] = "failed"
                _emit(summary, args.json)
                return EXIT_TSA_FAILED
    else:
        set_channel(
            summary,
            "tsa",
            enabled=False,
            status=STATUS_SKIPPED,
            reason="disabled",
        )

    # Peer channel
    check_peers = args.verify_peers or cfg.peers.enabled
    peers_strict = args.peers_strict or (strict_mode and check_peers)
    peers_min = (
        args.peers_min if args.peers_min is not None else cfg.peers.min_signatures
    )
    if check_peers:
        record_executed_check(summary, CHECK_PEERS)
        peer_attest_path = day_artifact.parent / "peers" / f"{day}.peers.json"
        if peer_attest_path.exists():
            site_id = block_header.get("site_id", "")
            all_valid, sig_count = verify_peer_signatures(
                peer_attest_path, site_id, day, recorded_root
            )
            if all_valid and sig_count >= peers_min:
                set_channel(
                    summary,
                    "peers",
                    enabled=True,
                    status=STATUS_VERIFIED,
                    reason=f"{sig_count}-signatures",
                )
            else:
                set_channel(
                    summary,
                    "peers",
                    enabled=True,
                    status=STATUS_FAILED,
                    reason=f"insufficient-or-invalid-signatures:{sig_count}",
                )
                if peers_strict:
                    summary["overall"] = "failed"
                    _emit(summary, args.json)
                    return EXIT_PEERS_FAILED
        else:
            set_channel(
                summary,
                "peers",
                enabled=True,
                status=STATUS_MISSING,
                reason="peer-attestation-not-found",
            )
            if peers_strict:
                summary["overall"] = "failed"
                _emit(summary, args.json)
                return EXIT_PEERS_FAILED
    else:
        set_channel(
            summary,
            "peers",
            enabled=False,
            status=STATUS_SKIPPED,
            reason="disabled",
        )

    summary["overall"] = compute_overall_status(
        policy_mode=cfg.policy.mode, channels=summary["channels"]
    )
    _emit(summary, args.json)
    return 0 if summary["overall"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
