"""Detached replay of shipped evidence; all mutations live in temporary copies."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

EXPANDED_CLAIMS = {
    "vtl_disclosure_fixture_replay": True,
    "vtl_tsa_fixture_rejection_replay": True,
}


class EvidenceReplayError(ValueError):
    def __init__(self, report: dict):
        self.report = report
        failed = [case["case"] for case in report["cases"] if not case["passed"]]
        super().__init__(f"detached evidence replay failed: {', '.join(failed)}")


def fixture_path(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or not relative:
        raise ValueError("unsafe evidence fixture path")
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise ValueError("missing or escaping evidence fixture path")
    return resolved


def der_parts(data: bytes) -> list[tuple[int, bytes]]:
    parts = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 2:
            raise ValueError("truncated DER fixture header")
        tag, length = data[offset : offset + 2]
        offset += 2
        if length & 128:
            size = length & 127
            if not size or offset + size > len(data):
                raise ValueError("invalid DER fixture length")
            length = int.from_bytes(data[offset : offset + size], "big")
            offset += size
        body = data[offset : offset + length]
        if len(body) != length:
            raise ValueError("truncated DER fixture")
        parts.append((tag, body))
        offset += length
    return parts


def der_encode(parts: list[tuple[int, bytes]]) -> bytes:
    result = bytearray()
    for tag, body in parts:
        length = len(body)
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        result.extend(
            bytes([tag])
            + (
                bytes([length])
                if length < 128
                else bytes([128 + len(encoded)]) + encoded
            )
            + body
        )
    return bytes(result)


def mutate_tsa(response: bytes, operation: str, digest: str) -> bytes:
    if operation == "tsa_imprint":
        imprint = bytes.fromhex(digest)
        if response.count(imprint) != 1:
            raise ValueError("ambiguous TSA imprint fixture")
        return response.replace(imprint, bytes([imprint[0] ^ 1]) + imprint[1:])
    if operation == "legacy-signing-certificate-is-rejected":
        oid = bytes.fromhex("060b2a864886f70d010910022f")
        if response.count(oid) != 1:
            raise ValueError("ambiguous SigningCertificateV2 fixture")
        return response.replace(oid, oid[:-1] + b"\x0c")
    outer = der_parts(response)
    if len(outer) != 1 or outer[0][0] != 0x30:
        raise ValueError("invalid timestamp response fixture")
    fields = der_parts(outer[0][1])
    if operation == "granted-with-mods-is-rejected":
        status = der_parts(fields[0][1])
        if status[0] != (2, b"\x00"):
            raise ValueError("TSA fixture is not granted")
        status[0] = (2, b"\x01")
        fields[0] = (0x30, der_encode(status))
    elif operation == "multiple-signer-infos-are-rejected":
        content = der_parts(fields[1][1])
        wrapped = der_parts(content[1][1])
        signed = der_parts(wrapped[0][1])
        signers = der_parts(signed[-1][1])
        if signed[-1][0] != 0x31 or len(signers) != 1:
            raise ValueError("TSA fixture must have exactly one signer")
        signed[-1] = (0x31, der_encode(signers * 2))
        content[1] = (0xA0, der_encode([(0x30, der_encode(signed))]))
        fields[1] = (0x30, der_encode(content))
    else:
        raise ValueError(f"unknown TSA mutation: {operation}")
    return der_encode([(0x30, der_encode(fields))])


def verify_evidence_cases(vectors: Path, binary: Path) -> dict:
    tsa_root = vectors / "vtl-interoperability"
    tsa = json.loads((tsa_root / "cases.json").read_text())["timestamp_channel_cases"][
        "valid_nonce_case"
    ]
    digest = tsa["segment_sha256"]
    request = base64.b64decode(
        fixture_path(tsa_root, tsa["request_der_base64_path"]).read_text()
    )
    if hashlib.sha256(request).hexdigest() != tsa["request_der_sha256"]:
        raise ValueError("TSA request fixture digest mismatch")
    policy = [
        "--tsa-ca-file",
        str(fixture_path(tsa_root, tsa["trust_anchor_pem_path"])),
        "--tsa-crls-file",
        str(fixture_path(tsa_root, tsa["revocation_crl_pem_path"])),
        "--tsa-policy",
        tsa["tsa_policy_oid"],
        "--tsa-signer-cert-sha256",
        tsa["signer_certificate_der_sha256"],
    ]
    scenarios = [
        ("class_a", "class-a", "public_recompute", "success", "verified", None),
        (
            "class_b",
            "class-b",
            "disclosed_batch_recompute",
            "success",
            "verified",
            None,
        ),
        ("class_c", "class-c", "anchor_only", "success", "verified", None),
        (
            "wrong_digest",
            "class-a",
            "public_recompute",
            "failure",
            None,
            "commitment_mismatch",
        ),
        (
            "altered_record",
            "class-a",
            "public_recompute",
            "failure",
            None,
            "commitment_mismatch",
        ),
        (
            "scope_downgrade",
            "class-c",
            "public_recompute",
            "failure",
            None,
            "disclosure",
        ),
        ("tsa_policy", "class-a", "public_recompute", "failure", "failed", "policy"),
        ("tsa_pin", "class-a", "public_recompute", "failure", "failed", "pin"),
        ("tsa_imprint", "class-a", "public_recompute", "failure", "failed", "imprint"),
        (
            "tsa_pending",
            "class-a",
            "public_recompute",
            "incomplete",
            "pending_claim",
            None,
        ),
        (
            "tsa_unavailable",
            "class-a",
            "public_recompute",
            "failure",
            "missing",
            "channel_failure",
        ),
        (
            "missing_request",
            "class-a",
            "public_recompute",
            "failure",
            "failed",
            "tsa_req",
        ),
        ("wrong_nonce", "class-a", "public_recompute", "failure", "failed", "nonce"),
        (
            "granted-with-mods-is-rejected",
            "class-a",
            "public_recompute",
            "failure",
            "failed",
            "status",
        ),
        (
            "multiple-signer-infos-are-rejected",
            "class-a",
            "public_recompute",
            "failure",
            "failed",
            "SignerInfo",
        ),
        (
            "legacy-signing-certificate-is-rejected",
            "class-a",
            "public_recompute",
            "failure",
            "failed",
            "SigningCertificate|ess cert digest error",
        ),
    ]
    results = []
    for name, bundle, scope, overall, channel, diagnostic in scenarios:
        with tempfile.TemporaryDirectory(prefix="trackone-detached-case-") as temporary:
            root = Path(temporary) / "bundle"
            shutil.copytree(vectors / "vtl-http-binding" / bundle, root)
            manifest = json.loads((root / "segment.verify.json").read_text())
            artifacts = manifest["artifacts"]
            # The fixed response echoes a nonce. Bind the shipped request too.
            (root / "timestamp.tsq").write_bytes(request)
            artifacts["tsa_req"] = {
                "path": "timestamp.tsq",
                "sha256": hashlib.sha256(request).hexdigest(),
            }
            flags = copy.copy(policy)
            if name == "wrong_digest":
                artifacts["segment_cbor"]["sha256"] = "00" * 32
            elif name == "altered_record":
                ref = artifacts["record_batches"][0]["records"][0]
                path = fixture_path(root, ref["path"])
                path.write_bytes(path.read_bytes() + b"\x00")
            elif name in ("tsa_policy", "tsa_pin"):
                flag = (
                    "--tsa-policy"
                    if name == "tsa_policy"
                    else "--tsa-signer-cert-sha256"
                )
                flags[flags.index(flag) + 1] = (
                    "1.3.6.1.4.1.55555.999" if name == "tsa_policy" else "00" * 32
                )
            elif name in ("tsa_pending", "tsa_unavailable"):
                artifacts.pop("tsa_tsr")
                artifacts.pop("tsa_req")
                manifest["anchoring"]["tsa"]["status"] = name.removeprefix("tsa_")
            elif name == "missing_request":
                artifacts.pop("tsa_req")
            elif name == "wrong_nonce":
                nonce = bytes.fromhex(tsa["nonce_hex"])
                if request.count(nonce) != 1:
                    raise ValueError("ambiguous nonce fixture")
                changed = request.replace(nonce, bytes([nonce[0] ^ 1]) + nonce[1:])
                (root / "timestamp.tsq").write_bytes(changed)
                artifacts["tsa_req"]["sha256"] = hashlib.sha256(changed).hexdigest()
            elif name == "tsa_imprint" or name.endswith("-rejected"):
                ref = artifacts["tsa_tsr"]
                path = fixture_path(root, ref["path"])
                changed = mutate_tsa(path.read_bytes(), name, digest)
                path.write_bytes(changed)
                ref["sha256"] = hashlib.sha256(changed).hexdigest()
            (root / "segment.verify.json").write_text(json.dumps(manifest))
            command = [
                str(binary),
                "verify",
                "--root",
                str(root),
                "--json",
                "--scope",
                scope,
                *flags,
            ]
            if scope == "disclosed_batch_recompute":
                command += ["--batch", "0"]
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=60, check=False
            )
            try:
                result = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{name}: verifier did not emit a result: {completed.stderr}"
                ) from exc
            observed_channel = result.get("channels", {}).get("tsa", {}).get("status")
            detail = json.dumps(result)
            passed = (
                result.get("overall") == overall
                and (completed.returncode == 0) == (overall == "success")
                and result.get("claimed_disclosure_class") == bundle[-1].upper()
                and result.get("verification_scope") == scope
                and (channel is None or observed_channel == channel)
                and (
                    diagnostic is None
                    or re.search(diagnostic, detail, re.IGNORECASE) is not None
                )
                and (overall != "success" or result.get("artifact_sha256") == digest)
            )
            results.append(
                {
                    "case": name,
                    "passed": passed,
                    "expected_overall": overall,
                    "result": result,
                }
            )
    report = {
        "required_cases": [case[0] for case in scenarios],
        "executed": len(results),
        "passed": all(case["passed"] for case in results),
        "cases": results,
    }
    if not report["passed"]:
        raise EvidenceReplayError(report)
    return report
