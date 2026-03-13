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
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

try:  # pragma: no cover - optional; may not be installed when run as a script
    from trackone_core.release import (
        DEFAULT_COMMITMENT_PROFILE_ID,
        DISCLOSURE_CLASS_LABELS,
    )
except ImportError:  # pragma: no cover - fallback for direct script execution
    # Keep these in sync with trackone_core/release.py.
    DEFAULT_COMMITMENT_PROFILE_ID: str = "trackone-canonical-cbor-v1"
    DISCLOSURE_CLASS_LABELS: dict[str, str] = {
        "A": "public-recompute",
        "B": "partner-audit",
        "C": "anchor-only-evidence",
    }

try:  # pragma: no cover - optional dependency in some environments
    import jsonschema
except Exception:  # pragma: no cover - keep verifier importable without it
    jsonschema = None  # type: ignore[assignment]

# Build a tuple of schema exception types only when jsonschema is available, to
# avoid AttributeError when the module is absent but the except clause fires.
_SCHEMA_EXCEPTIONS: tuple[type[BaseException], ...] = (
    (jsonschema.ValidationError, jsonschema.SchemaError)
    if jsonschema is not None
    else ()
)
_MANIFEST_EXCEPTIONS: tuple[type[BaseException], ...] = (
    OSError,
    UnicodeDecodeError,
    json.JSONDecodeError,
    ValueError,
) + _SCHEMA_EXCEPTIONS

try:  # Support both package imports and direct script execution.
    from .anchoring_config import (
        STRICT,
        AnchoringConfig,
        compute_overall_status,
        load_anchoring_config,
    )
    from .canonical_cbor import canonicalize_obj_to_cbor
    from .schema_validation import load_schema, validate_instance
except ImportError:  # pragma: no cover - fallback when run as a script
    from anchoring_config import (  # type: ignore
        STRICT,
        AnchoringConfig,
        compute_overall_status,
        load_anchoring_config,
    )
    from canonical_cbor import canonicalize_obj_to_cbor  # type: ignore
    from schema_validation import load_schema, validate_instance  # type: ignore

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
OTS_VERIFY_TIMEOUT_SECS = 30.0
CHECK_DAY_ARTIFACT = "day_artifact_validation"
CHECK_FACT_RECOMPUTE = "fact_level_recompute"
CHECK_MANIFEST = "pipeline_manifest_validation"
CHECK_OTS = "ots_verification"
CHECK_TSA = "tsa_verification"
CHECK_PEERS = "peer_signature_verification"

# Optional Rust extension (`trackone_core`) for single-sourced ledger policy.
_RUST_MERKLE: Any | None = None
_RUST_LEDGER: Any | None = None
_RUST_OTS: Any | None = None
try:  # pragma: no cover - optional acceleration
    import trackone_core

    native = getattr(trackone_core, "_native", None)
    rust_mod = native if native is not None else None

    if rust_mod is not None:
        _RUST_MERKLE = getattr(rust_mod, "merkle", None)
        _RUST_LEDGER = getattr(rust_mod, "ledger", None)
        _RUST_OTS = getattr(rust_mod, "ots", None)
except Exception:  # pragma: no cover - extension not built/installed or init failed
    trackone_core = None  # type: ignore[assignment]
    _RUST_MERKLE = None
    _RUST_LEDGER = None
    _RUST_OTS = None


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


@dataclass(slots=True, frozen=True)
class _PythonOtsVerifyResult:
    ok: bool
    status_name: str
    reason: str


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


def _verify_ots_python(
    ots_path: Path,
    allow_placeholder: bool = True,
    expected_artifact_sha: str | None = None,
) -> _PythonOtsVerifyResult:
    try:
        raw = ots_path.read_bytes()
        if raw.startswith(b"STATIONARY-OTS:"):
            if not allow_placeholder:
                return _PythonOtsVerifyResult(
                    ok=False,
                    status_name=STATUS_FAILED,
                    reason="placeholder-not-allowed",
                )
            try:
                parts = raw.split(b":", 1)
                if len(parts) != 2:
                    return _PythonOtsVerifyResult(
                        ok=False,
                        status_name=STATUS_FAILED,
                        reason="stationary-stub-invalid",
                    )
                stub_hex = parts[1].strip().splitlines()[0].decode("ascii").lower()
                if expected_artifact_sha:
                    if stub_hex == expected_artifact_sha.strip().lower():
                        return _PythonOtsVerifyResult(
                            ok=True,
                            status_name=STATUS_VERIFIED,
                            reason="stationary-stub-verified",
                        )
                    return _PythonOtsVerifyResult(
                        ok=False,
                        status_name=STATUS_FAILED,
                        reason="stationary-stub-hash-mismatch",
                    )
                artifact_candidate = ots_path.with_suffix("")
                if artifact_candidate.exists():
                    actual_sha = sha256(artifact_candidate.read_bytes()).hexdigest()
                    if actual_sha == stub_hex:
                        return _PythonOtsVerifyResult(
                            ok=True,
                            status_name=STATUS_VERIFIED,
                            reason="stationary-stub-verified",
                        )
                    return _PythonOtsVerifyResult(
                        ok=False,
                        status_name=STATUS_FAILED,
                        reason="stationary-stub-hash-mismatch",
                    )
                return _PythonOtsVerifyResult(
                    ok=False,
                    status_name=STATUS_FAILED,
                    reason="stationary-stub-artifact-missing",
                )
            except (OSError, UnicodeDecodeError):
                return _PythonOtsVerifyResult(
                    ok=False,
                    status_name=STATUS_FAILED,
                    reason="stationary-stub-invalid",
                )
        if raw.strip() == b"OTS_PROOF_PLACEHOLDER":
            if allow_placeholder:
                return _PythonOtsVerifyResult(
                    ok=True,
                    status_name=STATUS_PENDING,
                    reason="placeholder-accepted",
                )
            return _PythonOtsVerifyResult(
                ok=False,
                status_name=STATUS_FAILED,
                reason="placeholder-not-allowed",
            )
    except OSError:
        if not ots_path.exists():
            return _PythonOtsVerifyResult(
                ok=False,
                status_name=STATUS_MISSING,
                reason="ots-proof-not-found",
            )
        return _PythonOtsVerifyResult(
            ok=False,
            status_name=STATUS_FAILED,
            reason="ots-proof-read-failed",
        )

    ots_exe = shutil.which("ots")
    if not ots_exe:
        return _PythonOtsVerifyResult(
            ok=False,
            status_name=STATUS_FAILED,
            reason="ots-binary-not-found",
        )
    ots_path_obj = Path(ots_exe).resolve()
    if not ots_path_obj.is_file() or not os.access(str(ots_path_obj), os.X_OK):
        return _PythonOtsVerifyResult(
            ok=False,
            status_name=STATUS_FAILED,
            reason="ots-binary-not-executable",
        )
    try:
        result = subprocess.run(
            [str(ots_path_obj), "verify", str(ots_path)],
            capture_output=True,
            text=True,
            timeout=OTS_VERIFY_TIMEOUT_SECS,
        )  # nosec B603
        if result.returncode == 0:
            return _PythonOtsVerifyResult(
                ok=True,
                status_name=STATUS_VERIFIED,
                reason="ots-verified",
            )
        return _PythonOtsVerifyResult(
            ok=False,
            status_name=STATUS_FAILED,
            reason="ots-verification-failed",
        )
    except subprocess.TimeoutExpired:
        return _PythonOtsVerifyResult(
            ok=False,
            status_name=STATUS_FAILED,
            reason="ots-timeout",
        )
    except (subprocess.CalledProcessError, OSError):
        return _PythonOtsVerifyResult(
            ok=False,
            status_name=STATUS_FAILED,
            reason="ots-exec-failed",
        )


def verify_ots_proof(
    ots_path: Path,
    allow_placeholder: bool = True,
    expected_artifact_sha: str | None = None,
) -> Any:
    """Verify an OTS proof using the native boundary when available."""
    if _RUST_OTS is not None and hasattr(_RUST_OTS, "verify_ots_proof"):
        try:  # pragma: no cover - exercised when Rust extension is available
            return _RUST_OTS.verify_ots_proof(
                str(ots_path),
                allow_placeholder=allow_placeholder,
                expected_artifact_sha=expected_artifact_sha,
                ots_binary=shutil.which("ots"),
                timeout_secs=OTS_VERIFY_TIMEOUT_SECS,
            )
        except (ImportError, RuntimeError, TypeError, ValueError) as e:
            print(
                f"[WARN] Rust ots verify failed, falling back to Python: {e}",
                file=sys.stderr,
            )
    return _verify_ots_python(
        ots_path,
        allow_placeholder=allow_placeholder,
        expected_artifact_sha=expected_artifact_sha,
    )


def verify_ots(
    ots_path: Path,
    allow_placeholder: bool = True,
    expected_artifact_sha: str | None = None,
) -> bool:
    """Verify an OTS proof file via the Python fallback path."""
    return _verify_ots_python(
        ots_path,
        allow_placeholder=allow_placeholder,
        expected_artifact_sha=expected_artifact_sha,
    ).ok


def _validate_meta_sidecar_python(
    meta_path: Path,
    repo_root: Path,
    day_artifact: Path,
    ots_path: Path,
) -> _PythonOtsVerifyResult:
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _PythonOtsVerifyResult(
            ok=False,
            status_name=STATUS_FAILED,
            reason="meta-parse-failed",
        )
    except OSError:
        if not meta_path.exists():
            return _PythonOtsVerifyResult(
                ok=False,
                status_name=STATUS_MISSING,
                reason="meta-not-found",
            )
        return _PythonOtsVerifyResult(
            ok=False,
            status_name=STATUS_FAILED,
            reason="meta-read-failed",
        )

    if not isinstance(meta, dict):
        return _PythonOtsVerifyResult(
            ok=False,
            status_name=STATUS_FAILED,
            reason="meta-missing-fields",
        )

    artifact_rel = meta.get("artifact")
    meta_day = meta.get("day")
    expected_sha = meta.get("artifact_sha256")
    meta_ots_rel = meta.get("ots_proof")
    if (
        not isinstance(artifact_rel, str)
        or not isinstance(meta_day, str)
        or not meta_day
        or not isinstance(expected_sha, str)
        or len(expected_sha) != 64
        or not isinstance(meta_ots_rel, str)
    ):
        return _PythonOtsVerifyResult(
            ok=False,
            status_name=STATUS_FAILED,
            reason="meta-missing-fields",
        )

    resolved_artifact = (repo_root / artifact_rel).resolve()
    if resolved_artifact != day_artifact.resolve():
        return _PythonOtsVerifyResult(
            ok=False,
            status_name=STATUS_FAILED,
            reason="meta-artifact-path-mismatch",
        )

    if meta_day != day_artifact.stem:
        return _PythonOtsVerifyResult(
            ok=False,
            status_name=STATUS_FAILED,
            reason="meta-day-mismatch",
        )

    if not day_artifact.exists():
        return _PythonOtsVerifyResult(
            ok=False,
            status_name=STATUS_MISSING,
            reason="meta-artifact-missing",
        )

    actual_sha = sha256(day_artifact.read_bytes()).hexdigest()
    if actual_sha != expected_sha.lower():
        return _PythonOtsVerifyResult(
            ok=False,
            status_name=STATUS_FAILED,
            reason="meta-artifact-hash-mismatch",
        )

    resolved_meta_ots = (repo_root / meta_ots_rel).resolve()
    if resolved_meta_ots != ots_path.resolve():
        return _PythonOtsVerifyResult(
            ok=False,
            status_name=STATUS_FAILED,
            reason="meta-ots-path-mismatch",
        )

    if not ots_path.exists():
        return _PythonOtsVerifyResult(
            ok=False,
            status_name=STATUS_MISSING,
            reason="ots-proof-not-found",
        )

    return _PythonOtsVerifyResult(
        ok=True,
        status_name=STATUS_VERIFIED,
        reason="meta-valid",
    )


def validate_meta_sidecar(
    meta_path: Path,
    repo_root: Path,
    day_artifact: Path,
    ots_path: Path,
) -> Any:
    """Validate the OTS sidecar binding, preferring the native boundary."""
    if _RUST_OTS is not None and hasattr(_RUST_OTS, "validate_meta_sidecar"):
        try:  # pragma: no cover - exercised when Rust extension is available
            return _RUST_OTS.validate_meta_sidecar(
                str(meta_path.resolve()),
                str(repo_root.resolve()),
                str(day_artifact.resolve()),
                str(ots_path.resolve()),
            )
        except (ImportError, RuntimeError, TypeError, ValueError) as e:
            print(
                f"[WARN] Rust ots meta validation failed, falling back to Python: {e}",
                file=sys.stderr,
            )
    return _validate_meta_sidecar_python(meta_path, repo_root, day_artifact, ots_path)


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


def _record_executed(summary: dict[str, Any], check: str) -> None:
    checks = summary.setdefault("checks_executed", [])
    if isinstance(checks, list):
        checks.append(check)


def _record_skipped(summary: dict[str, Any], check: str, reason: str) -> None:
    checks = summary.setdefault("checks_skipped", [])
    if isinstance(checks, list):
        checks.append({"check": check, "reason": reason})


def _refresh_publicly_recomputable(summary: dict[str, Any]) -> None:
    verification = summary.get("verification")
    checks = summary.get("checks")
    if not isinstance(verification, dict) or not isinstance(checks, dict):
        return
    verification["publicly_recomputable"] = (
        verification.get("disclosure_class") == "A"
        and checks.get("artifact_valid") is True
        and checks.get("root_match") is True
    )


def _emit(summary: dict[str, Any], json_mode: bool) -> None:
    _refresh_publicly_recomputable(summary)
    if json_mode:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return
    verification = summary.get("verification", {})
    disclosure = verification.get("disclosure_class", "A")
    public_claim = verification.get("publicly_recomputable", False)
    print(
        f"Policy={summary['policy']['mode']} Disclosure={disclosure} "
        f"Overall={summary['overall']} RootMatch={summary['checks']['root_match']} "
        f"PubliclyRecomputable={public_claim}"
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


def _load_pipeline_manifest(manifest_path: Path) -> dict[str, Any] | None:
    if not manifest_path.exists():
        return None
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"pipeline manifest must be a JSON object: {manifest_path}")
    schema = load_schema("pipeline_manifest")
    if schema is not None:
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


def _validate_pipeline_manifest(
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
        actual_sha = sha256(resolved.read_bytes()).hexdigest()
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
    manifest_path = day_dir / f"{day}.pipeline-manifest.json"
    legacy_day_artifact = day_dir / f"{day}.bin"
    if not day_artifact.exists() and legacy_day_artifact.exists():
        print(
            "ERROR: legacy day artifact found at "
            f"{legacy_day_artifact}; migrate it to canonical CBOR at {day_artifact}",
            file=sys.stderr,
        )
        return 1
    ots_path = day_artifact.with_suffix(day_artifact.suffix + ".ots")
    recorded_root = block_header.get("merkle_root")
    if not isinstance(recorded_root, str) or len(recorded_root) != 64:
        print(f"ERROR: Invalid or missing 'merkle_root' in block header: {block_path}")
        return 1

    summary: dict[str, Any] = {
        "policy": {"mode": cfg.policy.mode},
        "verification": {
            "disclosure_class": args.disclosure_class,
            "disclosure_label": DISCLOSURE_CLASS_LABELS[args.disclosure_class],
            "commitment_profile_id": args.commitment_profile_id,
            "publicly_recomputable": False,
        },
        "artifacts": {
            "block": str(block_path),
            "day_cbor": str(day_artifact),
            "day_ots": str(ots_path),
            "pipeline_manifest": str(manifest_path),
        },
        "checks": {
            "root_match": None,
            "artifact_valid": False,
            "meta_valid": True,
        },
        "checks_executed": [],
        "checks_skipped": [],
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
    _record_executed(summary, CHECK_DAY_ARTIFACT)

    if manifest_path.exists():
        _record_executed(summary, CHECK_MANIFEST)
        try:
            manifest = _load_pipeline_manifest(manifest_path)
            _validate_pipeline_manifest(
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
            print(f"ERROR: pipeline manifest validation failed: {exc}")
            _emit(summary, args.json)
            return EXIT_META_INVALID

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
            canon: bytes | None = None
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
        _record_executed(summary, CHECK_FACT_RECOMPUTE)
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
    else:
        _record_skipped(
            summary,
            CHECK_FACT_RECOMPUTE,
            f"disclosure-class-{args.disclosure_class.lower()}",
        )

    # OTS channel
    check_ots = cfg.ots.enabled or args.require_ots
    require_ots = args.require_ots or (strict_mode and check_ots)
    if check_ots:
        _record_executed(summary, CHECK_OTS)
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
                summary["channels"]["ots"] = _channel(True, ots_status, ots_reason)
            else:
                if ots_status not in {STATUS_FAILED, STATUS_MISSING}:
                    ots_status = STATUS_FAILED
                summary["channels"]["ots"] = _channel(True, ots_status, ots_reason)
                summary["overall"] = "failed"
                _emit(summary, args.json)
                if ots_reason == "ots-proof-not-found":
                    return EXIT_OTS_NOT_FOUND
                return EXIT_OTS_FAILED
    else:
        summary["channels"]["ots"] = _channel(False, STATUS_SKIPPED, "disabled")

    # TSA channel
    check_tsa = args.verify_tsa or cfg.tsa.enabled
    tsa_strict = args.tsa_strict or (strict_mode and check_tsa)
    if check_tsa:
        _record_executed(summary, CHECK_TSA)
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
        _record_executed(summary, CHECK_PEERS)
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
