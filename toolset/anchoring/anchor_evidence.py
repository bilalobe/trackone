#!/usr/bin/env python3
"""Create, advance, and verify detached TrackOne anchor-evidence bundles."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any


PROVIDER = (
    "https://raw.githubusercontent.com/bilalobe/trackone/main/toolset/unified/schemas/"
)
SUBJECT_SCHEMA = "trackone-anchor-subject-v1"
SUBJECT_SCHEMA_URI = f"{PROVIDER}anchor_subject_v1.schema.json"
EVIDENCE_SCHEMA = "trackone-anchor-evidence-v1"
EVIDENCE_SCHEMA_URI = f"{PROVIDER}anchor_evidence_v1.schema.json"
PROVENANCE_SCHEMA = "trackone-anchor-provenance-v1"
INDEX_SCHEMA = "trackone-anchor-evidence-index-v1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VERIFY_CACHE_HEADER_SIZE = 16
VERIFY_CACHE_RECORD_SIZE = 84
STATE_ORDER = {
    "stationary": 0,
    "calendar-pending": 1,
    "bitcoin-attested-structure": 2,
    "bitcoin-header-quorum-verified": 3,
    "failed": -1,
}


class AnchorError(RuntimeError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def write_pretty_json(path: Path, value: Any) -> None:
    if path.is_symlink():
        raise AnchorError(f"refusing to replace a symlink: {path}")
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnchorError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AnchorError(f"JSON root is not an object: {path}")
    return value


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise AnchorError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def require_hex(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise AnchorError(f"{label} is not canonical lowercase hexadecimal")
    return value


def portable_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or Path(value).name != value:
        raise AnchorError(f"{label} is not a portable filename")
    return value


def copy_exact(source: Path, destination: Path, expected_sha256: str) -> None:
    if not source.is_file() or source.is_symlink():
        raise AnchorError(f"evidence source is missing or unsafe: {source}")
    if destination.is_symlink():
        raise AnchorError(f"evidence destination is a symlink: {destination}")
    if destination.exists():
        if not destination.is_file():
            raise AnchorError(f"evidence destination is not a file: {destination}")
        if sha256_file(destination) != expected_sha256:
            raise AnchorError(f"existing evidence file drifted: {destination}")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    if sha256_file(destination) != expected_sha256:
        raise AnchorError(f"copied evidence digest drifted: {destination}")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment.update({"LC_ALL": "C", "TZ": "UTC"})
    try:
        return subprocess.run(
            command,
            capture_output=True,
            check=False,
            env=environment,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(command, 124, "", str(exc))


def write_command_log(
    path: Path, command: list[str], completed: subprocess.CompletedProcess[str]
) -> None:
    # Credentials are never accepted by this tool, but redact URL user-info
    # defensively before persisting diagnostics.
    safe_command = [
        re.sub(r"(https?://)[^/@\s]+@", r"\1<redacted>@", item) for item in command
    ]
    path.write_text(
        "command: "
        + json.dumps(safe_command)
        + f"\nexit_code: {completed.returncode}\nstdout:\n{completed.stdout}"
        + f"\nstderr:\n{completed.stderr}",
        encoding="utf-8",
    )


def preserve_revision(path: Path, history: Path, suffix: str) -> str:
    digest = sha256_file(path)
    destination = history / f"{digest}{suffix}"
    copy_exact(path, destination, digest)
    return digest


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    repository = args.repository
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise AnchorError("--repository must use owner/name form")
    commit = require_hex(args.git_commit, HEX40, "Git commit")
    if args.source_ci_run_id <= 0:
        raise AnchorError("--source-ci-run-id must be positive")

    archive = args.archive.resolve()
    manifest_path = args.archive_manifest.resolve()
    verification_path = args.independent_verification.resolve()
    sanity_path = args.verifier_sanity.resolve()
    bundle_verifier_path = getattr(
        args, "bundle_verifier", Path(__file__).resolve()
    ).resolve()
    for path, label in (
        (archive, "conformance archive"),
        (manifest_path, "conformance manifest"),
        (verification_path, "independent verification"),
        (sanity_path, "verifier sanity result"),
        (bundle_verifier_path, "detached anchor-evidence verifier"),
    ):
        if not path.is_file() or path.is_symlink():
            raise AnchorError(f"{label} is missing or unsafe: {path}")

    manifest = read_json(manifest_path)
    verification = read_json(verification_path)
    sanity = read_json(sanity_path)
    manifest_subject = manifest.get("subject")
    if (
        not isinstance(manifest_subject, dict)
        or manifest_subject.get("git_commit") != commit
    ):
        raise AnchorError(
            "conformance manifest is not bound to the selected Git commit"
        )
    if manifest.get("repository") != repository:
        raise AnchorError("conformance manifest repository mismatch")
    if (
        verification.get("ok") is not True
        or verification.get("subject") != manifest_subject
    ):
        raise AnchorError(
            "independent verification did not validate the conformance subject"
        )
    if (
        sanity.get("schema") != "trackone-ots-verifier-sanity-v1"
        or sanity.get("ok") is not True
    ):
        raise AnchorError("OTS verifier sanity result is not successful")
    clients = sanity.get("clients", {})
    if clients.get("json", {}).get("commit") != args.json_client_commit:
        raise AnchorError("JSON verifier sanity commit mismatch")
    if clients.get("headers", {}).get("commit") != args.headers_client_commit:
        raise AnchorError("header verifier sanity commit mismatch")

    carrier = manifest.get("carrier", {})
    carrier_ref = carrier.get("oci_ref")
    artifact_type = carrier.get("artifact_type")
    if not isinstance(carrier_ref, str) or not carrier_ref.startswith("ghcr.io/"):
        raise AnchorError("conformance manifest has no canonical GHCR carrier")
    if artifact_type != "application/vnd.trackone.conformance.archive.v2+tar":
        raise AnchorError("conformance archive artifact type mismatch")

    archive_sha256 = sha256_file(archive)
    if args.expected_archive_sha256:
        expected = require_hex(
            args.expected_archive_sha256, HEX64, "expected archive digest"
        )
        if archive_sha256 != expected:
            raise AnchorError(
                "conformance archive digest differs from its handoff sidecar"
            )

    subject = {
        "schema": SUBJECT_SCHEMA,
        "schema_uri": SUBJECT_SCHEMA_URI,
        "version": 1,
        "repository": repository,
        "git_commit": commit,
        "bundle_verifier": {
            "path": "verify-anchor-evidence.py",
            "sha256": sha256_file(bundle_verifier_path),
        },
        "conformance_archive": {
            "filename": portable_name(archive.name, "archive filename"),
            "sha256": archive_sha256,
            "manifest_sha256": sha256_file(manifest_path),
            "artifact_type": artifact_type,
            "carrier": carrier_ref,
        },
        "independent_verification": {
            "path": "independent-verification.json",
            "sha256": sha256_file(verification_path),
            "result_schema": verification.get("schema"),
            "ok": True,
        },
        "ots_verifier_sanity": {
            "path": "verifier-sanity.json",
            "sha256": sha256_file(sanity_path),
            "fixture": sanity.get("fixture", {}).get("id"),
            "json_client_commit": args.json_client_commit,
            "headers_client_commit": args.headers_client_commit,
        },
    }
    subject_bytes = canonical_json_bytes(subject)
    subject_sha256 = sha256_bytes(subject_bytes)
    anchors_root = args.state_root.resolve() / "anchors"
    if anchors_root.is_symlink() or (
        anchors_root.exists() and not anchors_root.is_dir()
    ):
        raise AnchorError(f"anchor state directory is unsafe: {anchors_root}")
    anchors_root.mkdir(parents=True, exist_ok=True)
    anchor_dir = anchors_root / subject_sha256
    if anchor_dir.is_symlink() or (anchor_dir.exists() and not anchor_dir.is_dir()):
        raise AnchorError(f"anchor subject directory is unsafe: {anchor_dir}")
    anchor_dir.mkdir(parents=True, exist_ok=True)
    subject_path = anchor_dir / "subject.json"
    created = not subject_path.exists()
    if subject_path.exists() and subject_path.read_bytes() != subject_bytes:
        raise AnchorError(f"anchor subject collision or drift: {subject_path}")
    subject_path.write_bytes(subject_bytes)

    copy_exact(
        manifest_path,
        anchor_dir / "conformance-manifest.json",
        subject["conformance_archive"]["manifest_sha256"],
    )
    copy_exact(
        verification_path,
        anchor_dir / "independent-verification.json",
        subject["independent_verification"]["sha256"],
    )
    copy_exact(
        sanity_path,
        anchor_dir / "verifier-sanity.json",
        subject["ots_verifier_sanity"]["sha256"],
    )
    copy_exact(
        bundle_verifier_path,
        anchor_dir / "verify-anchor-evidence.py",
        subject["bundle_verifier"]["sha256"],
    )

    provenance_path = anchor_dir / "provenance.json"
    provenance = {
        "schema": PROVENANCE_SCHEMA,
        "repository": repository,
        "git_commit": commit,
        "source_ci_run_id": args.source_ci_run_id,
    }
    if provenance_path.exists():
        existing = read_json(provenance_path)
        if (
            existing.get("repository") != repository
            or existing.get("git_commit") != commit
        ):
            raise AnchorError("existing anchor provenance drifted")
    else:
        write_pretty_json(provenance_path, provenance)

    result = {
        "anchor_dir": str(anchor_dir),
        "anchor_id": subject_sha256,
        "created": created,
        "subject_path": str(subject_path),
    }
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as output:
            for key, value in result.items():
                output.write(
                    f"{key}={str(value).lower() if isinstance(value, bool) else value}\n"
                )
    return result


def parse_info_json(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    if completed.returncode != 0:
        raise AnchorError(
            f"pinned JSON client could not inspect proof: {completed.stdout}{completed.stderr}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AnchorError("pinned JSON client emitted malformed JSON") from exc
    if not isinstance(payload, dict):
        raise AnchorError("pinned JSON client emitted a non-object JSON root")
    return payload


def compact_target(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if not mantissa or bits & 0x00800000:
        raise AnchorError(f"invalid compact proof-of-work target: {bits:#x}")
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def parse_sparse_sidecar(path: Path) -> list[dict[str, Any]]:
    raw = path.read_bytes()
    if len(raw) < VERIFY_CACHE_HEADER_SIZE or raw[:4] != b"OTSV":
        raise AnchorError("header sidecar is not an OTSV sparse archive")
    if raw[4:8] != bytes((1, 0, 0, 0)) or any(raw[8:16]):
        raise AnchorError(
            "header sidecar version, network, or reserved bytes are invalid"
        )
    body = raw[VERIFY_CACHE_HEADER_SIZE:]
    if len(body) % VERIFY_CACHE_RECORD_SIZE:
        raise AnchorError("header sidecar has a truncated record")
    result: list[dict[str, Any]] = []
    seen: set[int] = set()
    for offset in range(0, len(body), VERIFY_CACHE_RECORD_SIZE):
        record = body[offset : offset + VERIFY_CACHE_RECORD_SIZE]
        height = struct.unpack("<I", record[:4])[0]
        if height in seen:
            raise AnchorError(f"header sidecar repeats Bitcoin height {height}")
        seen.add(height)
        header = record[4:]
        digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
        bits = int.from_bytes(header[72:76], "little")
        if int.from_bytes(digest, "little") > compact_target(bits):
            raise AnchorError(
                f"header at height {height} fails its declared proof-of-work"
            )
        result.append(
            {
                "height": height,
                "block_hash": digest[::-1].hex(),
                "merkle_root": header[36:68][::-1].hex(),
                "header_sha256": sha256_bytes(header),
            }
        )
    return sorted(result, key=lambda item: item["height"])


def verify_with_sidecar(
    executable: Path,
    proof: Path,
    sidecar: Path,
    log_path: Path,
    timeout: int,
) -> bool:
    command = [
        str(executable),
        "--no-cache",
        "verify",
        "--headers",
        str(sidecar),
        str(proof),
    ]
    completed = run(command, timeout)
    write_command_log(log_path, command, completed)
    return completed.returncode == 0


def material_without_observation(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in receipt.items() if key != "observed_at_utc"}


def write_receipt_if_changed(path: Path, material: dict[str, Any]) -> bool:
    if path.exists():
        previous = read_json(path)
        if material_without_observation(previous) == material:
            return False
    write_pretty_json(path, {**material, "observed_at_utc": utc_now()})
    return True


def _advance_one(anchor_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    subject_path = anchor_dir / "subject.json"
    subject_raw = subject_path.read_bytes()
    anchor_id = sha256_bytes(subject_raw)
    if anchor_dir.name != anchor_id:
        raise AnchorError(
            f"anchor directory does not match subject digest: {anchor_dir}"
        )
    subject = read_json(subject_path)
    if subject.get("schema") != SUBJECT_SCHEMA:
        raise AnchorError(f"unsupported anchor subject in {anchor_dir}")
    provenance_path = anchor_dir / "provenance.json"
    provenance = read_json(provenance_path)
    sanity_path = anchor_dir / "verifier-sanity.json"
    if sha256_file(sanity_path) != subject.get("ots_verifier_sanity", {}).get("sha256"):
        raise AnchorError(
            "verifier sanity evidence no longer matches the anchored subject"
        )
    previous_receipt = anchor_dir / "receipt.json"
    if previous_receipt.exists():
        previous_result = verify_bundle(anchor_dir)
        if previous_result["state"] == "bitcoin-header-quorum-verified":
            return {
                "anchor_id": anchor_id,
                "changed": False,
                "git_commit": subject.get("git_commit"),
                "liveness_warnings": [],
                "receipt_sha256": sha256_file(previous_receipt),
                "state": previous_result["state"],
            }

    pinned_clients = subject.get("ots_verifier_sanity", {})
    if args.json_client_commit != pinned_clients.get(
        "json_client_commit"
    ) or args.headers_client_commit != pinned_clients.get("headers_client_commit"):
        raise AnchorError(
            "pending anchor uses verifier commits different from its sanity gate"
        )

    history = anchor_dir / "history"
    history.mkdir(exist_ok=True)
    attempts = anchor_dir / "attempts"
    attempts.mkdir(exist_ok=True)
    proof = anchor_dir / "subject.json.ots"
    stamp_or_upgrade_log = attempts / "stamp-or-upgrade.log"
    liveness: list[str] = []

    if proof.exists():
        preserve_revision(proof, history, ".ots")
        command = [str(args.stable_ots), "upgrade", str(proof)]
        completed = run(command, args.calendar_timeout)
        write_command_log(stamp_or_upgrade_log, command, completed)
        if completed.returncode != 0:
            liveness.append("calendar-upgrade-unavailable")
        if not proof.exists() or not proof.stat().st_size:
            raise AnchorError(f"OTS upgrade destroyed the proof: {proof}")
        preserve_revision(proof, history, ".ots")
        backup = proof.with_name(proof.name + ".bak")
        if backup.exists():
            preserve_revision(backup, history, ".ots")
            backup.unlink()
    else:
        command = [str(args.stable_ots), "stamp"]
        for calendar in args.calendar:
            command.extend(("-c", calendar))
        command.extend(
            ("-m", "1", "--timeout", str(args.stamp_timeout), str(subject_path))
        )
        completed = run(command, args.calendar_timeout)
        write_command_log(stamp_or_upgrade_log, command, completed)
        if completed.returncode != 0 or not proof.exists() or not proof.stat().st_size:
            liveness.append("calendar-stamp-unavailable")
        else:
            preserve_revision(proof, history, ".ots")

    pending_calendars: list[str] = []
    bitcoin_heights: list[int] = []
    file_digest: str | None = None
    subject_binding = False
    proof_sha256: str | None = None
    header_records: list[dict[str, Any]] = []
    sidecar_ref: dict[str, str] | None = None
    header_verified = False
    state = "stationary"

    if proof.exists() and proof.stat().st_size:
        proof_sha256 = sha256_file(proof)
        info_command = [str(args.json_ots), "info", "--json", str(proof)]
        info = run(info_command, args.client_timeout)
        write_command_log(attempts / "info-json.log", info_command, info)
        payload = parse_info_json(info)
        file_digest = require_hex(payload.get("file_digest"), HEX64, "OTS file digest")
        if file_digest != anchor_id:
            raise AnchorError(
                f"OTS proof is bound to {file_digest}, expected {anchor_id}"
            )
        subject_binding = True
        attestations = payload.get("timestamp", {}).get("attestations")
        if not isinstance(attestations, list):
            raise AnchorError("pinned JSON client omitted the attestation list")
        for item in attestations:
            if not isinstance(item, dict):
                raise AnchorError("pinned JSON client emitted a malformed attestation")
            if item.get("type") == "PendingAttestation":
                calendar = item.get("calendar")
                if isinstance(calendar, str) and calendar:
                    pending_calendars.append(calendar)
            if item.get("type") == "BitcoinBlockHeaderAttestation":
                height = item.get("height")
                if not isinstance(height, int) or height < 0:
                    raise AnchorError(
                        "pinned JSON client emitted an invalid Bitcoin height"
                    )
                bitcoin_heights.append(height)
        pending_calendars = sorted(set(pending_calendars))
        bitcoin_heights = sorted(set(bitcoin_heights))

        if bitcoin_heights:
            sidecar = anchor_dir / "bitcoin-headers.bin"
            if sidecar.is_file():
                try:
                    existing_records = parse_sparse_sidecar(sidecar)
                    covered = {item["height"] for item in existing_records}
                    if set(bitcoin_heights) <= covered and verify_with_sidecar(
                        args.headers_ots,
                        proof,
                        sidecar,
                        attempts / "headers-verify-existing.log",
                        args.client_timeout,
                    ):
                        header_records = existing_records
                        header_verified = True
                except (AnchorError, OSError):
                    header_verified = False

            if not header_verified:
                fetch_command = [
                    str(args.headers_ots),
                    "--no-cache",
                    "headers",
                    "fetch",
                    "--output",
                    str(sidecar),
                    "--force",
                ]
                for source in args.header_source:
                    fetch_command.extend(("--source", source))
                fetch_command.extend(("--quorum", str(args.header_quorum), str(proof)))
                fetched = run(fetch_command, args.header_timeout)
                write_command_log(
                    attempts / "headers-fetch.log", fetch_command, fetched
                )
                if fetched.returncode == 0 and sidecar.is_file():
                    try:
                        candidate_records = parse_sparse_sidecar(sidecar)
                        covered = {item["height"] for item in candidate_records}
                        if set(bitcoin_heights) <= covered and verify_with_sidecar(
                            args.headers_ots,
                            proof,
                            sidecar,
                            attempts / "headers-verify-fetched.log",
                            args.client_timeout,
                        ):
                            header_records = candidate_records
                            header_verified = True
                    except (AnchorError, OSError) as exc:
                        liveness.append(f"header-sidecar-invalid:{exc}")
                if not header_verified:
                    liveness.append("header-quorum-verification-unavailable")

            if header_verified:
                sidecar_sha = preserve_revision(sidecar, history, ".headers.bin")
                sidecar_ref = {"path": "bitcoin-headers.bin", "sha256": sidecar_sha}
                state = "bitcoin-header-quorum-verified"
            else:
                state = "bitcoin-attested-structure"
        elif pending_calendars:
            state = "calendar-pending"
        else:
            state = "failed"

    if previous_receipt.exists():
        previous = read_json(previous_receipt)
        previous_state = previous.get("proof", {}).get("state")
        previous_heights = previous.get("proof", {}).get("bitcoin_heights", [])
        if isinstance(previous_heights, list) and not set(previous_heights) <= set(
            bitcoin_heights
        ):
            raise AnchorError(
                "Bitcoin attestation heights regressed across an OTS upgrade"
            )
        if (
            previous_state in STATE_ORDER
            and state in STATE_ORDER
            and STATE_ORDER[state] < STATE_ORDER[previous_state]
            and state != "failed"
        ):
            raise AnchorError(
                f"anchor evidence state regressed: {previous_state} -> {state}"
            )

    conformance_manifest = anchor_dir / "conformance-manifest.json"
    independent_verification = anchor_dir / "independent-verification.json"
    receipt_material = {
        "schema": EVIDENCE_SCHEMA,
        "schema_uri": EVIDENCE_SCHEMA_URI,
        "version": 1,
        "subject": {"path": "subject.json", "sha256": anchor_id},
        "bundle_verifier": {
            "path": "verify-anchor-evidence.py",
            "sha256": sha256_file(anchor_dir / "verify-anchor-evidence.py"),
        },
        "provenance": {
            "path": "provenance.json",
            "sha256": sha256_file(provenance_path),
            "source_ci_run_id": provenance.get("source_ci_run_id"),
        },
        "conformance": {
            "manifest": {
                "path": "conformance-manifest.json",
                "sha256": sha256_file(conformance_manifest),
            },
            "independent_verification": {
                "path": "independent-verification.json",
                "sha256": sha256_file(independent_verification),
            },
        },
        "proof": {
            "state": state,
            "path": "subject.json.ots" if proof_sha256 else None,
            "sha256": proof_sha256,
            "file_digest": file_digest,
            "pending_calendars": pending_calendars,
            "bitcoin_heights": bitcoin_heights,
        },
        "verification": {
            "subject_binding": subject_binding,
            "method": "public-header-source-quorum" if header_verified else "none",
            "full_bitcoin_consensus_validated": False,
            "configured_header_sources": args.header_source,
            "required_header_quorum": args.header_quorum,
            "bitcoin_headers": header_records if header_verified else [],
            "header_sidecar": sidecar_ref,
            "sanity": {
                "path": "verifier-sanity.json",
                "sha256": sha256_file(sanity_path),
            },
        },
        "upstream": {
            "stable_client": args.stable_client_version,
            "json_client": {
                "repository": "bilalobe/opentimestamps-client",
                "commit": args.json_client_commit,
            },
            "headers_client": {
                "repository": "djdarcy/dazzle-opentimestamps-client",
                "commit": args.headers_client_commit,
            },
        },
    }
    changed = write_receipt_if_changed(previous_receipt, receipt_material)
    attempt = {
        "schema": "trackone-anchor-advance-attempt-v1",
        "attempted_at_utc": utc_now(),
        "state": state,
        "liveness_warnings": liveness,
    }
    write_pretty_json(anchor_dir / "attempt.json", attempt)
    return {
        "anchor_id": anchor_id,
        "changed": changed,
        "git_commit": subject.get("git_commit"),
        "liveness_warnings": liveness,
        "receipt_sha256": sha256_file(previous_receipt),
        "state": state,
    }


def snapshot_regular_file(path: Path, label: str) -> bytes | None:
    if path.is_symlink():
        raise AnchorError(f"{label} is a symlink: {path}")
    if not path.exists():
        return None
    if not path.is_file():
        raise AnchorError(f"{label} is not a regular file: {path}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise AnchorError(f"cannot snapshot {label} {path}: {exc}") from exc


def restore_files(snapshots: dict[Path, bytes | None]) -> None:
    for path, original in snapshots.items():
        try:
            if path.is_symlink():
                path.unlink()
            elif path.exists() and not path.is_file():
                raise AnchorError(f"rollback target is not a regular file: {path}")
            if original is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(original)
        except OSError as exc:
            raise AnchorError(
                f"cannot roll back anchor state file {path}: {exc}"
            ) from exc


def advance_one(anchor_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    if anchor_dir.is_symlink() or not anchor_dir.is_dir():
        raise AnchorError(f"anchor subject directory is unsafe: {anchor_dir}")
    for name in (
        "subject.json",
        "provenance.json",
        "conformance-manifest.json",
        "independent-verification.json",
        "verifier-sanity.json",
        "verify-anchor-evidence.py",
    ):
        if snapshot_regular_file(anchor_dir / name, name) is None:
            raise AnchorError(
                f"required anchor state file is missing: {anchor_dir / name}"
            )
    for name in ("history", "attempts"):
        path = anchor_dir / name
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise AnchorError(f"anchor state directory is unsafe: {path}")

    mutable = (
        anchor_dir / "subject.json.ots",
        anchor_dir / "subject.json.ots.bak",
        anchor_dir / "bitcoin-headers.bin",
        anchor_dir / "receipt.json",
        anchor_dir / "attempt.json",
    )
    snapshots = {path: snapshot_regular_file(path, path.name) for path in mutable}
    try:
        return _advance_one(anchor_dir, args)
    except Exception as exc:
        try:
            restore_files(snapshots)
        except Exception as rollback_exc:
            raise AnchorError(
                f"anchor advancement failed and rollback was incomplete: {rollback_exc}"
            ) from exc
        raise


def advance(args: argparse.Namespace) -> dict[str, Any]:
    for executable in (args.stable_ots, args.json_ots, args.headers_ots):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise AnchorError(
                f"OTS executable is missing or not executable: {executable}"
            )
    if not args.calendar:
        raise AnchorError("at least one calendar is required")
    if any(not value.startswith("https://") for value in args.calendar):
        raise AnchorError("calendar endpoints must use HTTPS")
    if len(set(args.header_source)) < 2 or len(set(args.header_source)) != len(
        args.header_source
    ):
        raise AnchorError("at least two distinct header sources are required")
    if any(not value.startswith("https://") for value in args.header_source):
        raise AnchorError("header source endpoints must use HTTPS")
    if not 2 <= args.header_quorum <= len(args.header_source):
        raise AnchorError("header quorum must be between two and the source count")

    anchors_root = args.state_root.resolve() / "anchors"
    if anchors_root.is_symlink() or not anchors_root.is_dir():
        raise AnchorError(f"anchor state directory is unsafe: {anchors_root}")
    anchor_dirs = sorted(path for path in anchors_root.glob("*") if path.is_dir())
    if not anchor_dirs:
        raise AnchorError(f"no anchor subjects found under {anchors_root}")
    anchors = [advance_one(path, args) for path in anchor_dirs]
    index = {
        "schema": INDEX_SCHEMA,
        "anchors": [
            {
                "anchor_id": item["anchor_id"],
                "git_commit": item["git_commit"],
                "receipt_sha256": item["receipt_sha256"],
                "state": item["state"],
            }
            for item in anchors
        ],
    }
    write_pretty_json(args.state_root.resolve() / "index.json", index)
    return {
        "anchors": anchors,
        "changed": sum(1 for item in anchors if item["changed"]),
        "warnings": sum(len(item["liveness_warnings"]) for item in anchors),
    }


def verify_artifact_ref(root: Path, reference: Any, label: str) -> Path:
    if not isinstance(reference, dict):
        raise AnchorError(f"{label} reference is not an object")
    relative = reference.get("path")
    digest = reference.get("sha256")
    if (
        not isinstance(relative, str)
        or Path(relative).is_absolute()
        or ".." in Path(relative).parts
    ):
        raise AnchorError(f"{label} path is not portable")
    require_hex(digest, HEX64, f"{label} digest")
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise AnchorError(f"{label} path escapes the evidence root") from exc
    if not path.is_file() or path.is_symlink() or sha256_file(path) != digest:
        raise AnchorError(f"{label} file is missing or has the wrong digest")
    return path


def verify_bundle(root: Path) -> dict[str, Any]:
    root = root.resolve()
    receipt = read_json(root / "receipt.json")
    if (
        receipt.get("schema") != EVIDENCE_SCHEMA
        or receipt.get("schema_uri") != EVIDENCE_SCHEMA_URI
        or receipt.get("version") != 1
    ):
        raise AnchorError("anchor evidence receipt version mismatch")
    subject_path = verify_artifact_ref(root, receipt.get("subject"), "subject")
    subject = read_json(subject_path)
    if (
        subject.get("schema") != SUBJECT_SCHEMA
        or subject.get("schema_uri") != SUBJECT_SCHEMA_URI
        or subject.get("version") != 1
    ):
        raise AnchorError("anchor subject version mismatch")
    bundle_verifier_path = verify_artifact_ref(
        root, receipt.get("bundle_verifier"), "bundle verifier"
    )
    if receipt.get("bundle_verifier", {}).get("sha256") != subject.get(
        "bundle_verifier", {}
    ).get("sha256") or bundle_verifier_path.name != subject.get(
        "bundle_verifier", {}
    ).get("path"):
        raise AnchorError("detached bundle verifier does not match the anchor subject")
    provenance_path = verify_artifact_ref(root, receipt.get("provenance"), "provenance")
    provenance = read_json(provenance_path)
    if (
        provenance.get("schema") != PROVENANCE_SCHEMA
        or provenance.get("repository") != subject.get("repository")
        or provenance.get("git_commit") != subject.get("git_commit")
        or provenance.get("source_ci_run_id")
        != receipt.get("provenance", {}).get("source_ci_run_id")
    ):
        raise AnchorError("anchor provenance does not match the subject")
    conformance = receipt.get("conformance", {})
    manifest_path = verify_artifact_ref(
        root, conformance.get("manifest"), "conformance manifest"
    )
    independent_path = verify_artifact_ref(
        root, conformance.get("independent_verification"), "independent verification"
    )
    manifest = read_json(manifest_path)
    independent = read_json(independent_path)
    if (
        conformance.get("manifest", {}).get("sha256")
        != subject.get("conformance_archive", {}).get("manifest_sha256")
        or conformance.get("independent_verification", {}).get("sha256")
        != subject.get("independent_verification", {}).get("sha256")
        or manifest.get("repository") != subject.get("repository")
        or manifest.get("subject", {}).get("git_commit") != subject.get("git_commit")
        or independent.get("ok") is not True
        or independent.get("subject") != manifest.get("subject")
    ):
        raise AnchorError("conformance verification does not match the anchor subject")
    verification = receipt.get("verification", {})
    sanity_path = verify_artifact_ref(
        root, verification.get("sanity"), "verifier sanity"
    )
    sanity = read_json(sanity_path)
    if (
        verification.get("sanity", {}).get("sha256")
        != subject.get("ots_verifier_sanity", {}).get("sha256")
        or sanity.get("schema") != "trackone-ots-verifier-sanity-v1"
        or sanity.get("ok") is not True
        or sanity.get("clients", {}).get("json", {}).get("commit")
        != subject.get("ots_verifier_sanity", {}).get("json_client_commit")
        or sanity.get("clients", {}).get("headers", {}).get("commit")
        != subject.get("ots_verifier_sanity", {}).get("headers_client_commit")
    ):
        raise AnchorError("verifier sanity does not match the anchor subject")

    proof = receipt.get("proof", {})
    state = proof.get("state")
    if state not in STATE_ORDER:
        raise AnchorError("anchor evidence has an unknown proof state")
    proof_path = proof.get("path")
    proof_sha = proof.get("sha256")
    if proof_path is None or proof_sha is None:
        if state != "stationary" or proof.get("file_digest") is not None:
            raise AnchorError("non-stationary receipt has no OTS proof")
    else:
        verify_artifact_ref(
            root, {"path": proof_path, "sha256": proof_sha}, "OTS proof"
        )
        if proof.get("file_digest") != receipt["subject"]["sha256"]:
            raise AnchorError(
                "OTS proof file digest is not bound to the anchor subject"
            )
        if verification.get("subject_binding") is not True or state == "stationary":
            raise AnchorError("OTS proof receipt does not assert its subject binding")

    pending = proof.get("pending_calendars")
    heights = proof.get("bitcoin_heights")
    if not isinstance(pending, list) or not isinstance(heights, list):
        raise AnchorError("anchor proof attestation lists are malformed")
    if state == "calendar-pending" and not pending:
        raise AnchorError("calendar-pending receipt has no pending calendar")
    if (
        state in {"bitcoin-attested-structure", "bitcoin-header-quorum-verified"}
        and not heights
    ):
        raise AnchorError("Bitcoin receipt has no attested height")

    sidecar_ref = verification.get("header_sidecar")
    if sidecar_ref is not None:
        sidecar = verify_artifact_ref(root, sidecar_ref, "Bitcoin header sidecar")
        actual_records = parse_sparse_sidecar(sidecar)
        if actual_records != verification.get("bitcoin_headers"):
            raise AnchorError("Bitcoin header receipt records do not match the sidecar")
        if verification.get("method") != "public-header-source-quorum":
            raise AnchorError(
                "header sidecar is present under the wrong verification method"
            )
        if state != "bitcoin-header-quorum-verified":
            raise AnchorError("header sidecar is present under the wrong proof state")
        covered = {item["height"] for item in actual_records}
        if not set(heights) <= covered:
            raise AnchorError("header sidecar does not cover every Bitcoin attestation")
    elif (
        state == "bitcoin-header-quorum-verified"
        or verification.get("method") != "none"
        or verification.get("bitcoin_headers")
    ):
        raise AnchorError("header-quorum claim has no matching sidecar")
    sources = verification.get("configured_header_sources")
    quorum = verification.get("required_header_quorum")
    if (
        not isinstance(sources, list)
        or len(set(sources)) < 2
        or not isinstance(quorum, int)
        or not 2 <= quorum <= len(sources)
    ):
        raise AnchorError("configured Bitcoin header quorum is invalid")
    if verification.get("full_bitcoin_consensus_validated") is not False:
        raise AnchorError(
            "beta header-quorum receipt overclaims full Bitcoin consensus"
        )
    upstream = receipt.get("upstream", {})
    if (
        upstream.get("json_client", {}).get("commit")
        != subject.get("ots_verifier_sanity", {}).get("json_client_commit")
        or upstream.get("headers_client", {}).get("commit")
        != subject.get("ots_verifier_sanity", {}).get("headers_client_commit")
        or not re.fullmatch(
            r"opentimestamps-client==[0-9]+\.[0-9]+\.[0-9]+",
            str(upstream.get("stable_client", "")),
        )
    ):
        raise AnchorError("upstream client identity does not match the subject")
    return {
        "ok": True,
        "anchor_id": receipt["subject"]["sha256"],
        "git_commit": subject.get("git_commit"),
        "state": state,
    }


def add_prepare_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser("prepare")
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--archive-manifest", type=Path, required=True)
    parser.add_argument("--independent-verification", type=Path, required=True)
    parser.add_argument("--verifier-sanity", type=Path, required=True)
    parser.add_argument(
        "--bundle-verifier", type=Path, default=Path(__file__).resolve()
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--git-commit", required=True)
    parser.add_argument("--source-ci-run-id", type=int, required=True)
    parser.add_argument("--expected-archive-sha256")
    parser.add_argument("--json-client-commit", required=True)
    parser.add_argument("--headers-client-commit", required=True)
    parser.add_argument("--github-output", type=Path)
    parser.set_defaults(handler=prepare)


def add_advance_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser("advance")
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--stable-ots", type=Path, required=True)
    parser.add_argument("--json-ots", type=Path, required=True)
    parser.add_argument("--headers-ots", type=Path, required=True)
    parser.add_argument("--stable-client-version", required=True)
    parser.add_argument("--json-client-commit", required=True)
    parser.add_argument("--headers-client-commit", required=True)
    parser.add_argument("--calendar", action="append", default=[])
    parser.add_argument("--header-source", action="append", default=[])
    parser.add_argument("--header-quorum", type=int, default=2)
    parser.add_argument("--stamp-timeout", type=int, default=15)
    parser.add_argument("--calendar-timeout", type=int, default=90)
    parser.add_argument("--header-timeout", type=int, default=120)
    parser.add_argument("--client-timeout", type=int, default=45)
    parser.set_defaults(handler=advance)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_prepare_parser(subparsers)
    add_advance_parser(subparsers)
    verify_parser = subparsers.add_parser("verify-bundle")
    verify_parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "verify-bundle":
            result = verify_bundle(args.root)
        else:
            result = args.handler(args)
    except Exception as exc:
        print(f"anchor evidence {args.command} failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
