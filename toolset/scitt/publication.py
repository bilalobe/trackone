#!/usr/bin/env python3
"""Companion SCITT publication checks. These do not perform VTL verification."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "toolset/independent-verifier"))
from verify_https_bundle import CborDecoder, portable_path  # noqa: E402

PROFILE_ID = "c08ade4e-1785-4eb6-9648-b7003d76288d"
SEGMENT_KIND = "trackone.segment-artifact.v1"
BUNDLE_KIND = "trackone.disclosure-bundle.v1"
CONTENT_TYPE = "application/vnd.trackone.scitt-publication.v1+json"
SERVICE_REVISION = "c276f12328fde2907512ffb8c4fbe9adacd19788"
MAX_STATEMENT = 1024 * 1024
MAX_BUNDLE = 64 * 1024 * 1024


class PublicationError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise PublicationError(reason)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON member: {key}")
        result[key] = value
    return result


def parse_json(data: bytes) -> Any:
    return json.loads(data, object_pairs_hook=unique_object)


def strict_cbor(data: bytes) -> Any:
    """Decode definite-length COSE data, rejecting duplicate keys and trailing bytes."""
    require(len(data) <= MAX_STATEMENT, "COSE object exceeds size limit")
    stream = io.BytesIO(data)
    count = 0

    def take(n: int) -> bytes:
        value = stream.read(n)
        require(len(value) == n, "truncated COSE CBOR")
        return value

    def item(depth: int = 0) -> Any:
        nonlocal count
        count += 1
        require(depth <= 16 and count <= 10000, "COSE CBOR complexity limit")
        initial = take(1)[0]
        major, additional = initial >> 5, initial & 31
        require(additional < 28, "indefinite/reserved COSE CBOR")
        n = (
            additional
            if additional < 24
            else int.from_bytes(take(1 << (additional - 24)))
        )
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major in (2, 3):
            value = take(n)
            return value if major == 2 else value.decode("utf-8")
        if major == 4:
            require(n <= 10000, "COSE array complexity limit")
            return [item(depth + 1) for _ in range(n)]
        if major == 5:
            require(n <= 10000, "COSE map complexity limit")
            result = {}
            for _ in range(n):
                key = item(depth + 1)
                require(type(key) in (int, str, bytes), "unsupported COSE map key")
                require(key not in result, "duplicate COSE map key")
                result[key] = item(depth + 1)
            return result
        if major == 6:
            require(depth == 0 and n == 18, "unsupported COSE tag")
            return cbor2.CBORTag(n, item(depth + 1))
        if major == 7 and additional in (20, 21, 22):
            return {20: False, 21: True, 22: None}[additional]
        raise PublicationError("unsupported COSE CBOR value")

    value = item()
    require(stream.tell() == len(data), "trailing COSE CBOR bytes")
    return value


def envelope(data: bytes) -> tuple[list[Any], dict[Any, Any]]:
    tagged = strict_cbor(data)
    require(
        isinstance(tagged, cbor2.CBORTag) and tagged.tag == 18,
        "COSE_Sign1 tag required",
    )
    parts = list(tagged.value)
    require(len(parts) == 4, "COSE_Sign1 must have four elements")
    protected, unprotected, payload, signature = parts
    require(
        isinstance(protected, bytes)
        and isinstance(unprotected, dict)
        and isinstance(payload, bytes)
        and isinstance(signature, bytes),
        "invalid COSE_Sign1 fields",
    )
    headers = strict_cbor(protected)
    require(isinstance(headers, dict), "protected headers must be a map")
    require(
        not set(headers).intersection(unprotected), "header appears in both buckets"
    )
    return parts, headers


def subject(kind: str, digest: str) -> str:
    label = "segment-artifact" if kind == SEGMENT_KIND else "disclosure-bundle"
    return f"urn:trackone:{label}:sha256:{digest}"


def schema_validate(statement: Any) -> None:
    schemas = [
        json.loads(p.read_text())
        for p in (ROOT / "toolset/unified/schemas").glob("*.schema.json")
    ]
    registry = Registry().with_resources(
        (s["$id"], Resource.from_contents(s)) for s in schemas
    )
    kind = statement.get("statement_kind") if isinstance(statement, dict) else None
    filename = {
        SEGMENT_KIND: "scitt_segment_artifact_statement_v1.schema.json",
        BUNDLE_KIND: "scitt_disclosure_bundle_statement_v1.schema.json",
    }.get(kind)
    require(filename is not None, "unsupported statement kind")
    schema = next(s for s in schemas if s["$id"].endswith("/" + filename))
    errors = list(
        Draft202012Validator(schema, registry=registry).iter_errors(statement)
    )
    require(not errors, f"statement schema: {errors[0].message}" if errors else "")


def segment_identity(artifact: bytes) -> dict[str, Any]:
    require(len(artifact) <= MAX_BUNDLE, "segment artifact exceeds size limit")
    value = CborDecoder(artifact).decode()
    require(isinstance(value, dict), "segment artifact must be a CBOR map")
    require(
        value.get("version") == 1 and type(value.get("version")) is int,
        "unsupported artifact version",
    )
    require(
        value.get("commitment_profile_id") == PROFILE_ID,
        "unsupported commitment profile",
    )
    require(
        isinstance(value.get("ledger_id"), str)
        and re.fullmatch(r"[0-9a-f]{32}", value["ledger_id"]) is not None,
        "invalid artifact ledger ID",
    )
    require(
        type(value.get("segment_number")) is int
        and 0 <= value["segment_number"] < 2**64,
        "invalid artifact segment number",
    )
    return {
        "ledger_id": value["ledger_id"],
        "segment_number": str(value["segment_number"]),
        "commitment_profile_id": value["commitment_profile_id"],
    }


def check_artifact(statement: dict[str, Any], artifact: bytes) -> None:
    schema_validate(statement)
    reference = (
        statement["artifact"]
        if statement["statement_kind"] == SEGMENT_KIND
        else statement["bundle"]
    )
    digest = hashlib.sha256(artifact).hexdigest()
    require(reference["digest"] == digest, "published object digest mismatch")
    require(
        statement["subject"] == subject(statement["statement_kind"], digest),
        "publication subject mismatch",
    )
    if statement["statement_kind"] == SEGMENT_KIND:
        identity = segment_identity(artifact)
    else:
        require(len(artifact) <= MAX_BUNDLE, "disclosure bundle exceeds size limit")
        with tarfile.open(fileobj=io.BytesIO(artifact), mode="r:") as archive:
            files = {}
            for member in archive:
                path = portable_path(member.name)
                require(
                    member.isfile() and not member.issparse() and path not in files,
                    "non-file, sparse, or duplicate bundle entry",
                )
                require(0 <= member.size <= len(artifact), "invalid bundle member size")
                require(len(files) < 10000, "bundle member limit")
                files[path] = member
            require(
                "segment.verify.json" in files and "segment.cbor" in files,
                "bundle lacks manifest/artifact",
            )
            manifest = parse_json(
                archive.extractfile(files["segment.verify.json"]).read()
            )
            segment = archive.extractfile(files["segment.cbor"]).read()
        identity = segment_identity(segment)
        require(
            statement["disclosure_class"] == manifest["disclosure_class"],
            "bundle disclosure class mismatch",
        )
        require(
            manifest["artifacts"]["segment_cbor"]["path"] == "segment.cbor"
            and manifest["artifacts"]["segment_cbor"]["sha256"]
            == hashlib.sha256(segment).hexdigest(),
            "bundle manifest artifact reference mismatch",
        )
        require(
            all(manifest.get(k) == v for k, v in identity.items()),
            "bundle manifest identity mismatch",
        )
    require(
        all(statement[k] == v for k, v in identity.items()),
        "copied artifact identity mismatch",
    )


def make_statement(artifact: bytes, issuer: str) -> dict[str, Any]:
    digest = hashlib.sha256(artifact).hexdigest()
    return {
        "statement_kind": SEGMENT_KIND,
        "issuer": issuer,
        "subject": subject(SEGMENT_KIND, digest),
        "artifact": {"digest_algorithm": "sha-256", "digest": digest},
        **segment_identity(artifact),
    }


def sign(
    statement: dict[str, Any],
    key_pem: bytes,
    chain_pem: list[bytes],
    *,
    issuer: str | None = None,
    publication_subject: str | None = None,
) -> bytes:
    from pyscitt import crypto

    signer = crypto.Signer(
        key_pem.decode(),
        algorithm="ES256",
        issuer=issuer or statement["issuer"],
        x5c=[p.decode() for p in chain_pem],
    )
    return crypto.sign_statement(
        signer,
        json.dumps(statement, sort_keys=True, separators=(",", ":")).encode(),
        CONTENT_TYPE,
        feed=publication_subject or statement["subject"],
        cwt=True,
    )


def verify_organization(
    signed: bytes,
    policy: dict[str, Any],
    ca_file: Path,
    crls_file: Path,
    verification_time: int,
) -> dict[str, Any]:
    parts, headers = envelope(signed)
    require(
        parts[1] == {}, "submitted signed statement must have empty unprotected headers"
    )
    require(set(headers).issubset({1, 2, 3, 15, 33}), "unsupported protected header")
    require(
        headers.get(1) == -7 and type(headers.get(1)) is int, "only ES256 is supported"
    )
    require(headers.get(3) == CONTENT_TYPE, "publication content type mismatch")
    if 2 in headers:
        require(
            isinstance(headers[2], list)
            and bool(headers[2])
            and all(
                type(k) is int and k in {1, 3, 15, 33} and k in headers
                for k in headers[2]
            ),
            "unsupported critical header",
        )
    claims = headers.get(15)
    require(
        isinstance(claims, dict) and set(claims) == {1, 2},
        "issuer and subject CWT claims required",
    )
    chain = headers.get(33)
    chain = [chain] if isinstance(chain, bytes) else chain
    require(
        isinstance(chain, list)
        and 2 <= len(chain) <= 8
        and all(isinstance(c, bytes) for c in chain),
        "leaf-to-root x5chain required",
    )
    certs = [x509.load_der_x509_certificate(c) for c in chain]
    issuer = claims[1]
    require(isinstance(issuer, str), "issuer must be text")
    match = re.fullmatch(
        r"did:x509:0:sha256:([A-Za-z0-9_-]{43})::subject:CN:([A-Za-z0-9._-]+)", issuer
    )
    require(match is not None, "unsupported did:x509 identity form")
    fingerprint = (
        base64.urlsafe_b64encode(hashlib.sha256(chain[-1]).digest())
        .decode()
        .rstrip("=")
    )
    common_names = certs[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    require(
        match[1] == fingerprint
        and len(common_names) == 1
        and common_names[0].value == match[2],
        "did:x509 does not match certificate chain",
    )
    roots = x509.load_pem_x509_certificates(ca_file.read_bytes())
    require(
        any(c.public_bytes(serialization.Encoding.DER) == chain[-1] for c in roots),
        "untrusted organization root",
    )
    require(
        not certs[0].extensions.get_extension_for_class(x509.BasicConstraints).value.ca,
        "publisher certificate must be an end entity",
    )
    require(
        certs[0]
        .extensions.get_extension_for_class(x509.KeyUsage)
        .value.digital_signature,
        "publisher certificate lacks digitalSignature",
    )
    with tempfile.TemporaryDirectory(prefix="trackone-scitt-cert-") as directory:
        temp = Path(directory)
        leaf, intermediates = temp / "leaf.pem", temp / "intermediates.pem"
        claimed_root = temp / "claimed-root.pem"
        # The trust bundle admits the DID root; only that root may validate its leaf.
        claimed_root.write_bytes(certs[-1].public_bytes(serialization.Encoding.PEM))
        leaf.write_bytes(certs[0].public_bytes(serialization.Encoding.PEM))
        intermediates.write_bytes(
            b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs[1:-1])
        )
        command = [
            "openssl",
            "verify",
            "-no-CApath",
            "-no-CAstore",
            "-CAfile",
            str(claimed_root),
            "-CRLfile",
            str(crls_file),
            "-crl_check_all",
            "-attime",
            str(verification_time),
        ]
        if len(certs) > 2:
            command += ["-untrusted", str(intermediates)]
        completed = subprocess.run(
            command + [str(leaf)], capture_output=True, timeout=10, check=False
        )
        require(
            completed.returncode == 0,
            "organization certificate validity/revocation check failed",
        )
    public_key = certs[0].public_key()
    require(
        isinstance(public_key, ec.EllipticCurvePublicKey)
        and isinstance(public_key.curve, ec.SECP256R1),
        "ES256 requires a P-256 certificate key",
    )
    require(len(parts[3]) == 64, "invalid ES256 signature length")
    r, s = int.from_bytes(parts[3][:32]), int.from_bytes(parts[3][32:])
    signature_input = cbor2.dumps(["Signature1", parts[0], b"", parts[2]])
    try:
        public_key.verify(
            utils.encode_dss_signature(r, s), signature_input, ec.ECDSA(hashes.SHA256())
        )
    except Exception as exc:
        raise PublicationError("organizational signature is invalid") from exc
    statement = parse_json(parts[2])
    schema_validate(statement)
    require(
        statement["issuer"] == issuer and statement["subject"] == claims[2],
        "protected/payload identity mismatch",
    )
    grants = policy.get("issuers", {}).get(issuer, {})
    require(
        statement["ledger_id"] in grants.get("ledger_ids", [])
        and statement["statement_kind"] in grants.get("statement_kinds", []),
        "issuer is not authorized for ledger/kind",
    )
    return statement


def verify_publication(
    signed: bytes,
    transparent: bytes,
    artifact: bytes,
    *,
    policy: dict[str, Any],
    ca_file: Path,
    crls_file: Path,
    service_keys_file: Path,
    verification_time: int | None = None,
) -> dict[str, Any]:
    from pyscitt.verify import StaticTrustStore, verify_transparent_statement

    statement = verify_organization(
        signed,
        policy,
        ca_file,
        crls_file,
        int(time.time()) if verification_time is None else verification_time,
    )
    original, _ = envelope(signed)
    received, _ = envelope(transparent)
    require(
        all(original[i] == received[i] for i in (0, 2, 3)),
        "transparent statement changed signed content",
    )
    receipts = received[1].get(394)
    require(
        set(received[1]) == {394}
        and isinstance(receipts, list)
        and bool(receipts)
        and all(isinstance(r, bytes) for r in receipts),
        "SCITT receipts required",
    )
    keys = strict_cbor(service_keys_file.read_bytes())
    require(isinstance(keys, list) and bool(keys), "explicit service keys required")
    try:
        details = verify_transparent_statement(
            transparent, StaticTrustStore(cose_keys=keys), signed
        )
    except Exception as exc:
        raise PublicationError("SCITT receipt verification failed") from exc
    # The receipt proves registration of the signed bytes, not agreement with the artifact.
    check_artifact(statement, artifact)
    return {
        "publication_valid": True,
        "organizational_signature_valid": True,
        "issuer_authorized": True,
        "receipt_valid": True,
        "artifact_binding_valid": True,
        "statement_kind": statement["statement_kind"],
        "subject": statement["subject"],
        "receipt_count": len(details),
        "vtl_verification": "separate-required",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "signed",
        "transparent",
        "artifact",
        "policy",
        "ca-file",
        "crls-file",
        "service-keys-file",
        "output",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument(
        "--verification-time",
        type=int,
        help="Explicit historical replay time; default is now",
    )
    args = parser.parse_args()
    try:
        result = verify_publication(
            args.signed.read_bytes(),
            args.transparent.read_bytes(),
            args.artifact.read_bytes(),
            policy=parse_json(args.policy.read_bytes()),
            ca_file=args.ca_file,
            crls_file=args.crls_file,
            service_keys_file=args.service_keys_file,
            verification_time=args.verification_time,
        )
    except Exception as exc:  # noqa: BLE001 - report untrusted-input failures at the CLI boundary
        result = {
            "publication_valid": False,
            "reason": str(exc),
            "vtl_verification": "separate-required",
        }
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    return 0 if result["publication_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
