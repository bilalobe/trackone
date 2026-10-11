"""Synthetic PKI and disclosures shared by SCITT tests and the local exchange."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import json
import tarfile
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from publication import BUNDLE_KIND, ROOT, SEGMENT_KIND, segment_identity, subject


def create_identity(
    directory: Path, *, cn: str = "TrackOne-Publisher", revoked: bool = False
) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "TrackOne-Test-Organization")]
    )
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def certificate(name: x509.Name, key: Any, ca: bool) -> x509.Certificate:
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=ca, path_length=0 if ca else None), True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=ca,
                    crl_sign=ca,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                False,
            )
            .sign(ca_key, hashes.SHA256())
        )

    ca_cert = certificate(ca_name, ca_key, True)
    leaf_cert = certificate(leaf_name, leaf_key, False)
    crl_builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_name)
        .last_update(now - dt.timedelta(hours=1))
        .next_update(now + dt.timedelta(days=7))
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            False,
        )
    )
    if revoked:
        crl_builder = crl_builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(leaf_cert.serial_number)
            .revocation_date(now - dt.timedelta(minutes=30))
            .build()
        )
    crl = crl_builder.sign(ca_key, hashes.SHA256())
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
    key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    (directory / "organization-ca.pem").write_bytes(ca_pem)
    (directory / "organization-crls.pem").write_bytes(
        crl.public_bytes(serialization.Encoding.PEM)
    )
    (directory / "publisher.pem").write_bytes(leaf_pem)
    fingerprint = (
        base64.urlsafe_b64encode(ca_cert.fingerprint(hashes.SHA256()))
        .decode()
        .rstrip("=")
    )
    issuer = f"did:x509:0:sha256:{fingerprint}::subject:CN:{cn}"
    ledger = segment_identity(
        (ROOT / "toolset/vectors/vtl-http-binding/class-a/segment.cbor").read_bytes()
    )["ledger_id"]
    policy = {
        "issuers": {
            issuer: {
                "ledger_ids": [ledger],
                "statement_kinds": [SEGMENT_KIND, BUNDLE_KIND],
            }
        }
    }
    (directory / "authorization.json").write_text(json.dumps(policy, indent=2) + "\n")
    return {
        "issuer": issuer,
        "key": key_pem,
        "chain": [leaf_pem, ca_pem],
        "policy": policy,
        "ca_file": directory / "organization-ca.pem",
        "crls_file": directory / "organization-crls.pem",
        "verification_time": int(now.timestamp()),
    }


def bundle_fixture(issuer: str, disclosure_class: str) -> tuple[dict[str, Any], bytes]:
    """Build synthetic fixture bytes, not a production disclosure exporter."""
    fixture = (
        ROOT / "toolset/vectors/vtl-http-binding" / f"class-{disclosure_class.lower()}"
    )
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(fixture.rglob("*")):
            if path.is_file():
                content = path.read_bytes()
                member = tarfile.TarInfo(path.relative_to(fixture).as_posix())
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
    data = stream.getvalue()
    digest = hashlib.sha256(data).hexdigest()
    statement = {
        "statement_kind": BUNDLE_KIND,
        "issuer": issuer,
        "subject": subject(BUNDLE_KIND, digest),
        "bundle": {
            "media_type": "application/x-tar",
            "digest_algorithm": "sha-256",
            "digest": digest,
        },
        "disclosure_class": disclosure_class,
        **segment_identity((fixture / "segment.cbor").read_bytes()),
    }
    return statement, data
