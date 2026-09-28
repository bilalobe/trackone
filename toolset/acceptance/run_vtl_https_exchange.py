#!/usr/bin/env python3
"""Run the PostgreSQL-backed VTL HTTPS reference-binding acceptance exchange."""

from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from source_snapshot import source_hashes
from wire_cases import run_matrix

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "toolset/acceptance/https_fixture_server.py"
CHECKER = ROOT / "toolset/independent-verifier/verify_https_bundle.py"
POLICY_OID = "1.3.6.1.4.1.57264.1.1"


class AcceptanceError(RuntimeError):
    pass


def run(
    command: list[str], *, env: dict[str, str] | None = None, cwd: Path = ROOT
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    if completed.returncode != 0:
        raise AcceptanceError(
            f"command failed ({' '.join(command)}):\n{completed.stdout}\n{completed.stderr}"
        )
    return completed


def require_tools() -> None:
    missing = [
        name
        for name in ("cargo", "curl", "docker", "openssl", "python3")
        if shutil.which(name) is None
    ]
    if missing:
        raise AcceptanceError(
            f"required acceptance tools are unavailable: {', '.join(missing)}"
        )
    run(["docker", "info"])


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def openssl(*arguments: str, cwd: Path) -> None:
    run(["openssl", *arguments], cwd=cwd)


def create_pki(root: Path) -> dict[str, Path]:
    pki = root / "pki"
    pki.mkdir()
    ca_config = pki / "tsa-ca.cnf"
    ca_config.write_text(
        f"""[ ca ]
default_ca = local_ca
[ local_ca ]
database = {pki / "index.txt"}
serial = {pki / "ca-serial"}
crlnumber = {pki / "crl-number"}
new_certs_dir = {pki / "newcerts"}
certificate = {pki / "tsa-root.pem"}
private_key = {pki / "tsa-root.key"}
default_md = sha256
default_days = 2
default_crl_days = 2
policy = policy_any
x509_extensions = tsa_signer
copy_extensions = none
[ policy_any ]
commonName = supplied
[ tsa_signer ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
""",
        encoding="utf-8",
    )
    (pki / "index.txt").write_text("", encoding="ascii")
    (pki / "ca-serial").write_text("1000\n", encoding="ascii")
    (pki / "crl-number").write_text("1000\n", encoding="ascii")
    (pki / "newcerts").mkdir()
    openssl(
        "req",
        "-new",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-sha256",
        "-subj",
        "/CN=TrackOne Acceptance TSA Root",
        "-keyout",
        "tsa-root.key",
        "-out",
        "tsa-root.pem",
        "-addext",
        "basicConstraints=critical,CA:true,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-addext",
        "subjectKeyIdentifier=hash",
        cwd=pki,
    )
    openssl(
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=TrackOne Acceptance TSA",
        "-keyout",
        "tsa.key",
        "-out",
        "tsa.csr",
        cwd=pki,
    )
    openssl(
        "ca",
        "-batch",
        "-config",
        str(ca_config),
        "-extensions",
        "tsa_signer",
        "-in",
        "tsa.csr",
        "-out",
        "tsa.pem",
        cwd=pki,
    )
    openssl("ca", "-gencrl", "-config", str(ca_config), "-out", "tsa-crls.pem", cwd=pki)

    openssl(
        "req",
        "-new",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-sha256",
        "-subj",
        "/CN=TrackOne Acceptance HTTPS Root",
        "-keyout",
        "https-root.key",
        "-out",
        "https-root.pem",
        "-addext",
        "basicConstraints=critical,CA:true,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        cwd=pki,
    )
    openssl(
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=localhost",
        "-keyout",
        "https.key",
        "-out",
        "https.csr",
        cwd=pki,
    )
    (pki / "https-ext.cnf").write_text(
        "basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n",
        encoding="ascii",
    )
    openssl(
        "x509",
        "-req",
        "-in",
        "https.csr",
        "-CA",
        "https-root.pem",
        "-CAkey",
        "https-root.key",
        "-CAcreateserial",
        "-days",
        "2",
        "-sha256",
        "-extfile",
        "https-ext.cnf",
        "-out",
        "https.pem",
        cwd=pki,
    )

    tsa_config = pki / "tsa-server.cnf"
    tsa_config.write_text(
        f"""[ tsa ]
serial = {pki / "tsa-serial"}
signer_cert = {pki / "tsa.pem"}
certs = {pki / "tsa-root.pem"}
signer_key = {pki / "tsa.key"}
signer_digest = sha256
default_policy = {POLICY_OID}
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
""",
        encoding="utf-8",
    )
    (pki / "tsa-serial").write_text("01\n", encoding="ascii")
    return {
        "dir": pki,
        "tsa_config": tsa_config,
        "tsa_root": pki / "tsa-root.pem",
        "tsa_crls": pki / "tsa-crls.pem",
        "tsa_cert": pki / "tsa.pem",
        "tsa_key": pki / "tsa.key",
        "https_root": pki / "https-root.pem",
        "https_cert": pki / "https.pem",
        "https_key": pki / "https.key",
    }


def start_server(
    mode: str,
    port: int,
    pki: dict[str, Path],
    log_dir: Path,
    *,
    root: Path | None = None,
) -> subprocess.Popen[str]:
    command = [
        sys.executable,
        str(SERVER),
        "--mode",
        mode,
        "--port",
        str(port),
        "--cert",
        str(pki["https_cert"]),
        "--key",
        str(pki["https_key"]),
        "--log-dir",
        str(log_dir),
    ]
    if root:
        command.extend(["--root", str(root)])
    else:
        command.extend(["--config", str(pki["tsa_config"])])
    process = subprocess.Popen(command, cwd=ROOT, text=True)
    atexit.register(stop_process, process)
    return process


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def wait_https(port: int, ca: Path, path: str) -> None:
    for _ in range(100):
        completed = subprocess.run(
            [
                "curl",
                "--silent",
                "--output",
                "/dev/null",
                "--cacert",
                str(ca),
                f"https://localhost:{port}{path}",
            ],
            check=False,
        )
        if completed.returncode == 0:
            return
        time.sleep(0.1)
    raise AcceptanceError(f"HTTPS fixture on port {port} did not start")


def wait_gateway(port: int) -> None:
    for _ in range(200):
        completed = subprocess.run(
            [
                "curl",
                "--silent",
                "--fail",
                "--output",
                "/dev/null",
                f"http://127.0.0.1:{port}/healthz",
            ],
            check=False,
        )
        if completed.returncode == 0:
            return
        time.sleep(0.1)
    raise AcceptanceError("gateway did not become ready")


def record(counter: int) -> bytes:
    # [1, h'00000000000000xx', fc, ingest_time, null, kind, null]
    return bytes(
        [0x87, 0x01, 0x48, 0, 0, 0, 0, 0, 0, 0, counter, counter, 0, 0xF6, 0, 0xF6]
    )


def admit_segment(
    port: int, token: str, request_id: int, counters: list[int], work: Path
) -> None:
    records = [record(counter) for counter in counters]
    body = bytes([0x80 + len(records)]) + b"".join(
        bytes([0x40 + len(item)]) + item for item in records
    )
    path = work / f"admission-{request_id}.cbor"
    path.write_bytes(body)
    run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--fail-with-body",
            "-X",
            "POST",
            "-H",
            f"Authorization: Bearer {token}",
            "-H",
            f"Idempotency-Key: acceptance-{request_id}",
            "-H",
            "Content-Type: application/vnd.trackone.record-batch.v1+cbor",
            "--data-binary",
            f"@{path}",
            f"http://127.0.0.1:{port}/v2/record-batches",
        ]
    )


def manifest_digest(bundle: Path) -> str:
    manifest = json.loads((bundle / "segment.verify.json").read_text(encoding="utf-8"))
    return manifest["artifacts"]["segment_cbor"]["sha256"]


def query_imprint(query: Path) -> str:
    """Return the message imprint hex carried by an RFC 3161 request."""
    text = run(["openssl", "ts", "-query", "-in", str(query), "-text"]).stdout
    lines = text.splitlines()
    try:
        start = next(
            index for index, line in enumerate(lines) if line.strip() == "Message data:"
        )
    except StopIteration:
        raise AcceptanceError(
            f"timestamp request {query.name} carries no message imprint"
        ) from None
    octets: list[str] = []
    for line in lines[start + 1 :]:
        # openssl renders the imprint with BIO_dump: an offset, " - ", a
        # fixed 48-column hex field whose ninth separator is "-", then ASCII.
        match = re.match(r"\s*[0-9a-fA-F]{4} - (.*)", line)
        if match is None:
            break
        for token in match.group(1)[:48].replace("-", " ").split():
            if not re.fullmatch(r"[0-9a-fA-F]{2}", token):
                raise AcceptanceError(
                    f"timestamp request {query.name} has an unparsable imprint dump"
                )
            octets.append(token.lower())
    if len(octets) != 32:
        raise AcceptanceError(
            f"timestamp request {query.name} does not carry a 32-byte SHA-256 imprint"
        )
    return "".join(octets)


def verify_request_imprints(tsa_log: Path, expected: set[str]) -> None:
    observed: set[str] = set()
    for query in sorted(tsa_log.glob("request-*.tsq")):
        imprint = query_imprint(query)
        if imprint not in expected:
            raise AcceptanceError(
                f"timestamp request {query.name} does not carry a sealed-artifact digest"
            )
        observed.add(imprint)
    if observed != expected:
        raise AcceptanceError(
            f"timestamp request imprint coverage mismatch: {observed} != {expected}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise AcceptanceError(
            "acceptance output already exists; immutable evidence is never overwritten"
        )
    require_tools()
    initial_sources = source_hashes(ROOT)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()

    container = f"trackone-vtl-acceptance-{uuid.uuid4().hex[:12]}"
    atexit.register(
        subprocess.run,
        ["docker", "rm", "-f", container],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    postgres_port, tsa_port, evidence_port, gateway_port = (
        free_port() for _ in range(4)
    )
    password = uuid.uuid4().hex
    run(
        [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--name",
            container,
            "-e",
            "POSTGRES_USER=trackone",
            "-e",
            f"POSTGRES_PASSWORD={password}",
            "-e",
            "POSTGRES_DB=trackone",
            "-p",
            f"127.0.0.1:{postgres_port}:5432",
            "postgres:17-alpine",
        ]
    )
    for _ in range(100):
        ready = subprocess.run(
            ["docker", "exec", container, "pg_isready", "-U", "trackone"],
            capture_output=True,
            check=False,
        )
        if ready.returncode == 0:
            break
        time.sleep(0.2)
    else:
        raise AcceptanceError("isolated PostgreSQL did not become ready")

    with tempfile.TemporaryDirectory(prefix="trackone-vtl-acceptance-") as temporary:
        work = Path(temporary)
        pki = create_pki(work)
        tsa_log = output / "tsa-exchange"
        tsa = start_server("tsa", tsa_port, pki, tsa_log)
        wait_https(tsa_port, pki["https_root"], "/not-a-tsa-get")
        run(
            [
                "cargo",
                "build",
                "--locked",
                "-p",
                "trackone-gateway-svc",
                "--bins",
                "-p",
                "trackone-evidence",
            ]
        )
        signer_der = subprocess.check_output(
            ["openssl", "x509", "-in", pki["tsa_cert"], "-outform", "DER"]
        )
        signer_digest = hashlib.sha256(signer_der).hexdigest()
        ledger_id = uuid.uuid4().hex
        token = "acceptance-bearer-token-000000000000"
        gateway_env = os.environ.copy()
        gateway_env.update(
            {
                "TRACKONE_DATABASE_URL": f"postgresql://trackone:{password}@localhost:{postgres_port}/trackone",
                "TRACKONE_POSTGRES_TLS_MODE": "disable",
                "TRACKONE_INGEST_BEARER_TOKEN": token,
                "TRACKONE_LEDGER_ID": ledger_id,
                "TRACKONE_SITE_ID": "controlled-acceptance",
                "TRACKONE_TSA_URL": f"https://localhost:{tsa_port}/tsa",
                "TRACKONE_TSA_CA_FILE": str(pki["tsa_root"]),
                "TRACKONE_TSA_CRLS_FILE": str(pki["tsa_crls"]),
                "TRACKONE_TSA_POLICY_OID": POLICY_OID,
                "TRACKONE_TSA_SIGNER_CERT_SHA256": signer_digest,
                "TRACKONE_BIND": f"127.0.0.1:{gateway_port}",
                "TRACKONE_INTERVAL_MS": "3600000",
                "TRACKONE_BATCH_RECORD_LIMIT": "2",
                "TRACKONE_RECORD_LIMIT": "5",
                "CURL_CA_BUNDLE": str(pki["https_root"]),
            }
        )
        gateway = subprocess.Popen(
            [ROOT / "target/debug/trackone-vtl-gateway"],
            cwd=ROOT,
            env=gateway_env,
            text=True,
        )
        atexit.register(stop_process, gateway)
        wait_gateway(gateway_port)
        admit_segment(gateway_port, token, 0, [3, 1, 1, 2, 4], work)
        admit_segment(gateway_port, token, 1, [8, 7, 6, 5, 5], work)

        publish = output / "published"
        publish.mkdir()
        export_env = os.environ.copy()
        export_env.update(
            {
                "TRACKONE_DATABASE_URL": gateway_env["TRACKONE_DATABASE_URL"],
                "TRACKONE_POSTGRES_TLS_MODE": "disable",
            }
        )
        export_binary = ROOT / "target/debug/trackone-vtl-export"
        for name, class_name, batches in (
            ("class-a", "A", []),
            ("class-b", "B", ["0"]),
            ("class-c", "C", []),
        ):
            command = [
                str(export_binary),
                "--ledger-id",
                ledger_id,
                "--segment-number",
                "1",
                "--class",
                class_name,
            ]
            for batch in batches:
                command.extend(["--batch", batch])
            command.extend(["--output", str(publish / name)])
            run(command, env=export_env)
        overwrite = subprocess.run(
            [
                str(export_binary),
                "--ledger-id",
                ledger_id,
                "--segment-number",
                "1",
                "--class",
                "C",
                "--output",
                str(publish / "class-c"),
            ],
            env=export_env,
            capture_output=True,
            text=True,
            check=False,
        )
        if overwrite.returncode == 0:
            raise AcceptanceError("snapshot exporter overwrote an existing destination")

        expected = {
            manifest_digest(publish / name)
            for name in ("class-a", "class-b", "class-c")
        }
        if len(expected) != 1:
            raise AcceptanceError(
                "disclosure classes did not retain identical artifact bytes"
            )
        digest = expected.pop()
        predecessor_digest = json.loads(
            (publish / "class-a/segment.verify.json").read_text()
        )["artifacts"]["predecessor_segment_cbor"]["sha256"]
        verify_request_imprints(tsa_log, {digest, predecessor_digest})
        private_canary = publish / ".acceptance.private-staging"
        private_canary.mkdir()
        (private_canary / "secret").write_text("must not be served\n", encoding="ascii")
        evidence_log = output / "https-evidence"
        evidence = start_server(
            "static", evidence_port, pki, evidence_log, root=publish
        )
        wait_https(evidence_port, pki["https_root"], "/class-a/segment.verify.json")
        hidden = run(
            [
                "curl",
                "--silent",
                "--output",
                os.devnull,
                "--write-out",
                "%{http_code}",
                "--cacert",
                str(pki["https_root"]),
                f"https://localhost:{evidence_port}/.acceptance.private-staging/secret",
            ]
        )
        if hidden.stdout != "404":
            raise AcceptanceError("static host exposed the private staging namespace")
        (private_canary / "secret").unlink()
        private_canary.rmdir()
        evaluation_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        (output / "evaluation-time.txt").write_text(
            evaluation_time + "\n", encoding="ascii"
        )
        reports = output / "reports"
        reports.mkdir()
        detached = work / "detached-checker.py"
        shutil.copy2(CHECKER, detached)
        common = [
            "--expected-segment-sha256",
            digest,
            "--https-ca-file",
            str(pki["https_root"]),
            "--tsa-ca-file",
            str(pki["tsa_root"]),
            "--tsa-crls-file",
            str(pki["tsa_crls"]),
            "--tsa-policy",
            POLICY_OID,
            "--tsa-signer-cert-sha256",
            signer_digest,
            "--evaluation-time",
            evaluation_time,
            "--max-future-skew-seconds",
            "5",
        ]
        rust_common = [
            "--expected-segment-sha256",
            digest,
            "--https-ca-file",
            str(pki["https_root"]),
            "--tsa-ca-file",
            str(pki["tsa_root"]),
            "--tsa-crls-file",
            str(pki["tsa_crls"]),
            "--tsa-policy",
            POLICY_OID,
            "--tsa-signer-cert-sha256",
            signer_digest,
            "--tsa-max-future-skew-seconds",
            "5",
            "--json",
            "--pretty",
        ]
        cases = [
            ("class-a", "public_recompute", []),
            ("class-b", "disclosed_batch_recompute", ["0"]),
            ("class-c", "anchor_only", []),
        ]
        for name, scope, batches in cases:
            url = f"https://localhost:{evidence_port}/{name}/"
            independent_command = [
                sys.executable,
                str(detached),
                "--bundle-url",
                url,
                "--scope",
                scope,
                *common,
                "--output",
                str(reports / f"{name}-independent.json"),
            ]
            rust_command = [
                str(ROOT / "target/debug/trackone-evidence"),
                "verify",
                "--bundle-url",
                url,
                "--scope",
                scope,
                *rust_common,
            ]
            for batch in batches:
                independent_command.extend(["--batch", batch])
                rust_command.extend(["--batch", batch])
            run(independent_command, cwd=work)
            rust_result = json.loads(run(rust_command).stdout)
            (reports / f"{name}-trackone.json").write_text(
                json.dumps(rust_result, indent=2, sort_keys=True) + "\n"
            )
            independent_result = json.loads(
                (reports / f"{name}-independent.json").read_text()
            )
            for key in (
                "artifact_sha256",
                "claimed_disclosure_class",
                "verification_scope",
                "chain_status",
                "overall",
            ):
                if independent_result[key] != rust_result[key]:
                    raise AcceptanceError(
                        f"{name}: verifier conclusion mismatch for {key}"
                    )
            if (
                independent_result["channels"]["tsa"]["status"]
                != rust_result["channels"]["tsa"]["status"]
            ):
                raise AcceptanceError(f"{name}: TSA conclusion mismatch")
        wrong = subprocess.run(
            [
                str(ROOT / "target/debug/trackone-evidence"),
                "verify",
                "--bundle-url",
                f"https://localhost:{evidence_port}/class-c/",
                "--scope",
                "anchor_only",
                *["--expected-segment-sha256", "0" * 64, *rust_common[2:]],
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if wrong.returncode == 0 or "commitment_mismatch" not in wrong.stdout:
            raise AcceptanceError(
                "wrong independently provisioned digest was not rejected as an integrity failure"
            )

        trust_out = output / "trust-inputs"
        trust_out.mkdir()
        for key in ("https_root", "tsa_root", "tsa_crls", "tsa_cert"):
            shutil.copy2(pki[key], trust_out / pki[key].name)
        verification_inputs = {
            "expected_segment_sha256": digest,
            "tsa_policy": POLICY_OID,
            "tsa_signer_cert_sha256": signer_digest,
            "evaluation_time": evaluation_time,
            "max_future_skew_seconds": 5,
            "cases": [
                {"bundle": name, "scope": scope, "batches": batches}
                for name, scope, batches in cases
            ],
        }
        (output / "verification-inputs.json").write_text(
            json.dumps(verification_inputs, indent=2, sort_keys=True) + "\n"
        )
        run_matrix(
            publish,
            pki,
            [str(ROOT / "target/debug/trackone-evidence"), "verify", *rust_common],
            [sys.executable, str(detached), *common],
            reports / "wire-coverage.json",
            (tsa_log / "response-0000.tsr").read_bytes(),
        )
        if source_hashes(ROOT) != initial_sources:
            raise AcceptanceError(
                "source changed during the run; rerun before publication"
            )
        (output / "source-sha256.json").write_text(
            json.dumps(initial_sources, indent=2, sort_keys=True) + "\n"
        )
        versions = {
            "cargo": run(["cargo", "--version"]).stdout.strip(),
            "rustc": run(["rustc", "--version"]).stdout.strip(),
            "openssl": run(["openssl", "version"]).stdout.strip(),
            "curl": run(["curl", "--version"]).stdout.splitlines()[0],
            "postgres_image": "postgres:17-alpine",
            "postgres_image_id": run(
                ["docker", "inspect", "--format", "{{.Image}}", container]
            ).stdout.strip(),
            "postgres_repo_digests": json.loads(
                run(
                    [
                        "docker",
                        "image",
                        "inspect",
                        "--format",
                        "{{json .RepoDigests}}",
                        "postgres:17-alpine",
                    ]
                ).stdout
            ),
        }
        (output / "tool-versions.json").write_text(
            json.dumps(versions, indent=2, sort_keys=True) + "\n"
        )
        stop_process(evidence)
        stop_process(gateway)
        stop_process(tsa)
        (output / "SHA256SUMS").write_text(
            "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(output).as_posix()}\n"
                for path in sorted(output.rglob("*"))
                if path.is_file() and path.name != "SHA256SUMS"
            ),
            encoding="ascii",
        )
    print(f"acceptance exchange succeeded; replayable evidence: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ACCEPTANCE ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
