#!/usr/bin/env python3
"""Run an independent SCITT CCF exchange, then separate VTL verification."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import httpx
from publication import (
    CONTENT_TYPE,
    ROOT,
    SEGMENT_KIND,
    SERVICE_REVISION,
    envelope,
    make_statement,
    require,
    sign,
    verify_publication,
)
from pyscitt import governance
from pyscitt.cli.governance import setup_local_development
from pyscitt.client import Client, ServiceError
from pyscitt.local_key_sign_client import LocalKeySignClient
from test_support import create_identity

sys.path.insert(0, str(ROOT / "toolset/acceptance"))
from run_vtl_https_exchange import POLICY_OID, create_pki


def run(
    command: list[str | Path], *, cwd: Path = ROOT, timeout: int = 180
) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        [str(c) for c in command],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"command failed: {command[0]}\n{completed.stdout}\n{completed.stderr}"
        )
    return completed


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def vtl_evidence(output: Path, work: Path) -> list[str]:
    """Refresh only the fixture's TSA channel; authoritative segment bytes stay exact."""
    bundle = output / "vtl-bundle"
    shutil.copytree(ROOT / "toolset/vectors/vtl-http-binding/class-a", bundle)
    pki = create_pki(work)
    query = work / "query.tsq"
    run(
        [
            "openssl",
            "ts",
            "-query",
            "-data",
            bundle / "segment.cbor",
            "-sha256",
            "-cert",
            "-out",
            query,
        ]
    )
    run(
        [
            "openssl",
            "ts",
            "-reply",
            "-config",
            pki["tsa_config"],
            "-section",
            "tsa",
            "-queryfile",
            query,
            "-out",
            bundle / "timestamp.tsr",
        ]
    )
    # Retain the request because this response contains its nonce.
    shutil.copyfile(query, bundle / "timestamp.tsq")
    manifest_path = bundle / "segment.verify.json"
    manifest = json.loads(manifest_path.read_text())
    for key, path in (("tsa_tsr", "timestamp.tsr"), ("tsa_req", "timestamp.tsq")):
        manifest["artifacts"][key] = {
            "path": path,
            "sha256": hashlib.sha256((bundle / path).read_bytes()).hexdigest(),
        }
    write_json(manifest_path, manifest)
    for key, name in (
        ("tsa_root", "tsa-ca.pem"),
        ("tsa_crls", "tsa-crls.pem"),
        ("tsa_cert", "tsa-signer.pem"),
    ):
        shutil.copyfile(pki[key], output / name)
    # Parse the public certificate directly to compute its DER fingerprint.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    signer_digest = (
        x509.load_pem_x509_certificate((output / "tsa-signer.pem").read_bytes())
        .fingerprint(hashes.SHA256())
        .hex()
    )
    write_json(
        output / "vtl-policy.json",
        {"tsa_policy_oid": POLICY_OID, "tsa_signer_cert_sha256": signer_digest},
    )
    return [
        "--tsa-ca-file",
        str(output / "tsa-ca.pem"),
        "--tsa-crls-file",
        str(output / "tsa-crls.pem"),
        "--tsa-policy",
        POLICY_OID,
        "--tsa-signer-cert-sha256",
        signer_digest,
    ]


def exchange(source: Path, output: Path, image: str | None) -> None:
    require(
        run(["git", "rev-parse", "HEAD"], cwd=source).stdout.strip()
        == SERVICE_REVISION,
        "SCITT service source revision mismatch",
    )
    require(
        not run(["git", "diff", "--stat", "HEAD"], cwd=source).stdout.strip(),
        "modified SCITT service source",
    )
    if image is None:
        image = "trackone-scitt:" + SERVICE_REVISION[:12]
        build = subprocess.run(
            [
                "docker",
                "build",
                "-t",
                image,
                "--label",
                "org.opencontainers.image.revision=" + SERVICE_REVISION,
                "--build-arg",
                "SCITT_VERSION_OVERRIDE=trackone-" + SERVICE_REVISION[:7],
                "-f",
                "docker/Dockerfile",
                ".",
            ],
            cwd=source,
            timeout=1800,
            check=False,
        )
        require(build.returncode == 0, "SCITT Docker build failed")
    image_info = json.loads(run(["docker", "image", "inspect", image]).stdout)[0]
    require(
        image_info["Config"].get("Labels", {}).get("org.opencontainers.image.revision")
        == SERVICE_REVISION,
        "SCITT Docker image must be labeled with the pinned source revision",
    )
    run(["cargo", "build", "--locked", "--package", "trackone-evidence"], timeout=600)
    name = "trackone-scitt-" + uuid.uuid4().hex[:12]
    volume = name + "-data"
    with tempfile.TemporaryDirectory(prefix="trackone-scitt-exchange-") as directory:
        work = Path(directory)
        workspace = work / "node"
        workspace.mkdir()
        identity = create_identity(output)
        vtl_arguments = vtl_evidence(output, work)
        artifact = (output / "vtl-bundle/segment.cbor").read_bytes()
        (output / "segment.cbor").write_bytes(artifact)
        statement = make_statement(artifact, identity["issuer"])
        signed = sign(statement, identity["key"], identity["chain"])
        (output / "signed.cose").write_bytes(signed)
        write_json(output / "statement.json", statement)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        url = f"https://127.0.0.1:{port}"
        node_config = json.loads(
            (source / "docker/dev-config.tmpl.json")
            .read_text()
            .replace("%CCF_PORT%", "8000")
        )
        node_config["command"]["start"]["cose_signatures"]["issuer"] = (
            f"127.0.0.1:{port}"
        )
        write_json(workspace / "dev-config.json", node_config)
        shutil.copytree(source / "app/constitution", workspace / "constitution")
        run(
            [source / "docker/keygenerator.sh", "--name", "member0", "--gen-enc-key"],
            cwd=workspace,
        )
        run(["docker", "volume", "create", volume])
        try:
            run(
                [
                    "docker",
                    "create",
                    "--name",
                    name,
                    "--publish",
                    f"127.0.0.1:{port}:8000",
                    "--cpus",
                    "2",
                    "--memory",
                    "2g",
                    "--volume",
                    volume + ":/host",
                    "--entrypoint",
                    "cchost",
                    image,
                    "--config",
                    "/host/dev-config.json",
                    "--log-level",
                    "info",
                ]
            )
            run(["docker", "cp", str(workspace) + "/.", name + ":/host"])
            run(["docker", "start", name])
            deadline = time.monotonic() + 60
            with httpx.Client(verify=False, timeout=2) as bootstrap:
                while True:
                    try:
                        if bootstrap.get(url + "/node/network").is_success:
                            break
                    except httpx.HTTPError:
                        pass
                    require(time.monotonic() < deadline, "CCF startup timeout")
                    time.sleep(0.5)
            # Obtain the service TLS root through the local Docker control plane.
            run(
                [
                    "docker",
                    "cp",
                    name + ":/host/service_cert.pem",
                    output / "service-tls-ca.pem",
                ]
            )
            client = Client(
                url,
                cacert=str(output / "service-tls-ca.pem"),
                member_auth=LocalKeySignClient(
                    (workspace / "member0_cert.pem").read_text(),
                    (workspace / "member0_privk.pem").read_text(),
                ),
            )
            setup_local_development(client, None)
            policy_script = (
                "export function apply(phdr, uhdr, payload) {\n"
                f"if (phdr.cwt.iss !== {json.dumps(identity['issuer'])}) return 'Unauthorized issuer';\n"
                f"if (phdr.cty !== {json.dumps(CONTENT_TYPE)}) return 'Wrong content type';\n"
                "const s = JSON.parse(ccf.bufToStr(payload));\n"
                f"if (s.statement_kind !== {json.dumps(SEGMENT_KIND)} || s.ledger_id !== {json.dumps(statement['ledger_id'])}) return 'Unauthorized ledger/kind';\n"
                "if (s.issuer !== phdr.cwt.iss || s.subject !== phdr.cwt.sub) return 'Header/payload mismatch';\n"
                "return true;\n}"
            )
            configuration = {
                "authentication": {"allowUnauthenticated": True},
                "acceptedAlgorithms": ["ES256"],
                "policy": {"policyScript": policy_script},
            }
            client.governance.propose(
                governance.set_scitt_configuration_proposal(configuration),
                must_pass=True,
            )
            write_json(output / "service-policy.json", configuration)
            # Record public exchange traffic after governance (never governance credentials).
            transcript = []
            wire = output / "wire"
            wire.mkdir()

            def record(response: httpx.Response) -> None:
                response.read()
                index = len(transcript)
                request_path, response_path = (
                    f"wire/{index:03d}-request.body",
                    f"wire/{index:03d}-response.body",
                )
                (output / request_path).write_bytes(response.request.content)
                (output / response_path).write_bytes(response.content)
                transcript.append(
                    {
                        "method": response.request.method,
                        "url": str(response.request.url),
                        "request_headers": dict(response.request.headers),
                        "request_body": request_path,
                        "status": response.status_code,
                        "response_headers": dict(response.headers),
                        "response_body": response_path,
                    }
                )
                write_json(output / "exchange.json", transcript)

            client = Client(url, cacert=str(output / "service-tls-ca.pem"))
            client.session.event_hooks["response"] = [record]
            # Network governance can report Open before the application frontend
            # observes that transaction. Bound this startup propagation wait.
            deadline = time.monotonic() + 60
            while True:
                response = client.session.get("/.well-known/scitt-keys")
                if response.is_success:
                    keys = response.content
                    break
                require(
                    response.status_code == 404 and "FrontendNotOpen" in response.text,
                    "unexpected SCITT keys response during startup",
                )
                require(time.monotonic() < deadline, "SCITT frontend startup timeout")
                time.sleep(0.2)
            (output / "service-keys.cbor").write_bytes(keys)
            write_json(output / "service-version.json", client.get_version())
            submission = client.submit_signed_statement_and_wait(signed)
            transparent = submission.response_bytes
            (output / "transparent.cose").write_bytes(transparent)
            parts, _ = envelope(transparent)
            (output / "receipt.cose").write_bytes(parts[1][394][0])
            report = verify_publication(
                signed,
                transparent,
                artifact,
                policy=identity["policy"],
                ca_file=identity["ca_file"],
                crls_file=identity["crls_file"],
                service_keys_file=output / "service-keys.cbor",
                verification_time=identity["verification_time"],
            )
            write_json(output / "publication-report.json", report)
            # Correctly signed but unauthorized ledger: registration must reject it.
            unauthorized = {**statement, "ledger_id": "0" * 32}
            unauthorized_signed = sign(unauthorized, identity["key"], identity["chain"])
            (output / "unauthorized-ledger.cose").write_bytes(unauthorized_signed)
            try:
                client.submit_signed_statement_and_wait(unauthorized_signed)
            except ServiceError as error:
                require(
                    "Unauthorized ledger/kind" in str(error),
                    "service rejection did not exercise authorization",
                )
            else:
                raise RuntimeError("SCITT service accepted unauthorized ledger")
            # Retain re-signed semantic mismatch fixtures; they are organizational checks,
            # not transparent statements with invented receipts.
            for field, value in (
                ("segment_number", "1"),
                ("commitment_profile_id", "00000000-0000-0000-0000-000000000000"),
            ):
                changed = {**statement, field: value}
                (output / f"mismatch-{field}.cose").write_bytes(
                    sign(changed, identity["key"], identity["chain"])
                )
            verifier = ROOT / "target/debug/trackone-evidence"
            verified = run(
                [
                    verifier,
                    "verify",
                    "--root",
                    output / "vtl-bundle",
                    "--json",
                    *vtl_arguments,
                ]
            )
            write_json(output / "vtl-report.json", json.loads(verified.stdout))
            broken = work / "broken-bundle"
            shutil.copytree(output / "vtl-bundle", broken)
            record_path = next((broken / "records").rglob("*.cbor"))
            record_path.write_bytes(record_path.read_bytes() + b"\x00")
            failed = subprocess.run(
                [
                    str(verifier),
                    "verify",
                    "--root",
                    str(broken),
                    "--json",
                    *vtl_arguments,
                ],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            require(
                failed.returncode != 0,
                "VTL verifier accepted corrupted disclosed record",
            )
            write_json(output / "vtl-negative-report.json", json.loads(failed.stdout))
            write_json(
                output / "capture.json",
                {
                    "service_revision": SERVICE_REVISION,
                    "service_image_id": image_info["Id"],
                    "verification_time": identity["verification_time"],
                    "transaction_id": submission.tx,
                    "python_version": sys.version.split()[0],
                    "registration_authorization_negative": "rejected",
                    "dependencies": {
                        d.metadata["Name"]: d.version
                        for d in importlib.metadata.distributions()
                    },
                    "claim_boundary": "SCITT publication does not prove telemetry truth or collection completeness",
                },
            )
        finally:
            logs = subprocess.run(
                ["docker", "logs", name], text=True, capture_output=True, check=False
            )
            (output / "service.log").write_text(logs.stdout + logs.stderr)
            subprocess.run(
                ["docker", "rm", "-f", name], capture_output=True, check=False
            )
            subprocess.run(
                ["docker", "volume", "rm", volume], capture_output=True, check=False
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service-source", type=Path, required=True)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New directory for public exchange artifacts",
    )
    parser.add_argument(
        "--image",
        help="Reuse an image labeled with the pinned revision; otherwise build it",
    )
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    try:
        exchange(args.service_source.resolve(), output, args.image)
    except Exception as exc:  # noqa: BLE001 - retain every exchange failure for CI diagnosis
        write_json(output / "failure.json", {"ok": False, "reason": str(exc)})
        print(f"SCITT exchange failed: {exc}", file=sys.stderr)
        return 1
    print(f"SCITT publication and separate VTL verification succeeded: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
