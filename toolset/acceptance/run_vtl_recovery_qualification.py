#!/usr/bin/env python3
"""Qualify gateway recovery using disposable services and real process failures."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from recovery_assertions import (
    BOUNDARIES, REQUIRED_SCENARIOS, assert_artifacts, assert_chain,
    assert_complete, assert_occurrences,
)
from run_vtl_https_exchange import (
    ROOT, CHECKER, POLICY_OID, create_pki, free_port, record, require_tools,
    run, start_server, stop_process, wait_gateway, wait_https,
)
from source_snapshot import source_hashes

TARGET = ROOT / "target/recovery-qualification/debug"
TOKEN = "qualification-ingest-token-000000000000"
PROFILE = "c08ade4e-1785-4eb6-9648-b7003d76288d"


def write_json(path: Path, value) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def wait_for(predicate, label: str, seconds: int = 30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError(f"deadline exceeded: {label}")


def cbor_bytes(data: bytes) -> bytes:
    size = len(data)
    if size < 24:
        return bytes([0x40 + size]) + data
    for marker, width, maximum in ((0x58, 1, 256), (0x59, 2, 65536), (0x5A, 4, 2**32)):
        if size < maximum:
            return bytes([marker]) + size.to_bytes(width, "big") + data
    raise ValueError("fixture too large")


def independent_module():
    spec = importlib.util.spec_from_file_location("recovery_checker", CHECKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Database:
    def __init__(self, stack: ExitStack, output: Path):
        self.container = "trackone-recovery-" + uuid.uuid4().hex[:12]
        self.port = free_port()
        self.password = uuid.uuid4().hex
        self.output = output
        run(["docker", "run", "--detach", "--name", self.container,
             "--tmpfs", "/qualification:rw,size=32m,uid=70,gid=70",
             "-e", "POSTGRES_USER=trackone", "-e", "POSTGRES_PASSWORD=" + self.password,
             "-e", "POSTGRES_DB=trackone", "-p", f"127.0.0.1:{self.port}:5432",
             "postgres:17-alpine"])
        stack.callback(self.cleanup)
        self.ready()
        self.image = json.loads(run(["docker", "image", "inspect", "postgres:17-alpine"]).stdout)[0]

    def cleanup(self):
        result = subprocess.run(["docker", "logs", self.container], capture_output=True, text=True)
        (self.output / (self.container + ".log")).write_text(result.stdout + result.stderr)
        subprocess.run(["docker", "rm", "-f", self.container], capture_output=True, check=False)

    def ready(self):
        wait_for(lambda: subprocess.run(
            ["docker", "exec", self.container, "pg_isready", "-h", "127.0.0.1", "-U", "trackone"],
            capture_output=True).returncode == 0, "PostgreSQL readiness")

    def sql(self, database: str, query: str, *, check: bool = True):
        result = subprocess.run(
            ["docker", "exec", "-i", self.container, "psql", "-U", "trackone", "-d", database,
             "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1"],
            input=query, text=True, capture_output=True, timeout=30)
        if check and result.returncode:
            raise AssertionError(f"fixture SQL failed: {result.stderr}")
        return result

    def url(self, database: str):
        return f"postgresql://trackone:{self.password}@localhost:{self.port}/{database}"


class Scenario:
    def __init__(self, name: str, db: Database, work: Path, output: Path, pki: dict,
                 tsa_port: int, signer: str, checker):
        self.name, self.db, self.pki, self.signer, self.checker = name, db, pki, signer, checker
        self.database = "q_" + uuid.uuid4().hex[:16]
        db.sql("trackone", f"CREATE DATABASE {self.database}")
        self.output = output / name
        self.output.mkdir()
        self.work = work / name
        self.work.mkdir()
        self.control = self.work / "control"
        self.control.mkdir()
        self.port = free_port()
        self.ledger = uuid.uuid4().hex
        self.process = None
        self.logs = []
        self.journal = []
        self.requests = {}
        self.acknowledged = set()
        self.committed = set()
        self.hooks = []
        self.lease_updates = []
        self.observed_artifacts = {}
        self.observed_timestamps = {}
        self.env = os.environ.copy()
        self.env.update({
            "TRACKONE_DATABASE_URL": db.url(self.database),
            "TRACKONE_POSTGRES_TLS_MODE": "disable", "TRACKONE_INGEST_BEARER_TOKEN": TOKEN,
            "TRACKONE_LEDGER_ID": self.ledger, "TRACKONE_SITE_ID": "recovery-qualification",
            "TRACKONE_TSA_URL": f"https://localhost:{tsa_port}/tsa",
            "TRACKONE_TSA_CA_FILE": str(pki["tsa_root"]),
            "TRACKONE_TSA_CRLS_FILE": str(pki["tsa_crls"]),
            "TRACKONE_TSA_POLICY_OID": POLICY_OID, "TRACKONE_TSA_SIGNER_CERT_SHA256": signer,
            "TRACKONE_TSA_MAX_FUTURE_SKEW_SECONDS": "5",
            "TRACKONE_BIND": f"127.0.0.1:{self.port}", "TRACKONE_INTERVAL_MS": "3600000",
            "TRACKONE_BATCH_RECORD_LIMIT": "2", "TRACKONE_RECORD_LIMIT": "4",
            "TRACKONE_TSA_WORKER_CONCURRENCY": "1", "TRACKONE_TSA_RETRY_INITIAL_MS": "100",
            "TRACKONE_TSA_RETRY_MAX_MS": "500", "TRACKONE_TSA_MAX_ATTEMPTS": "100",
            "TRACKONE_QUALIFICATION_CONTROL": str(self.control),
            "CURL_CA_BUNDLE": str(pki["https_root"]),
        })
        # Prevent inherited controls or deployment configuration altering fixtures.
        for key in list(self.env):
            if key.startswith("TRACKONE_") and key not in {
                "TRACKONE_DATABASE_URL", "TRACKONE_POSTGRES_TLS_MODE", "TRACKONE_INGEST_BEARER_TOKEN",
                "TRACKONE_LEDGER_ID", "TRACKONE_SITE_ID", "TRACKONE_TSA_URL", "TRACKONE_TSA_CA_FILE",
                "TRACKONE_TSA_CRLS_FILE", "TRACKONE_TSA_POLICY_OID", "TRACKONE_TSA_SIGNER_CERT_SHA256",
                "TRACKONE_TSA_MAX_FUTURE_SKEW_SECONDS", "TRACKONE_BIND", "TRACKONE_INTERVAL_MS",
                "TRACKONE_BATCH_RECORD_LIMIT", "TRACKONE_RECORD_LIMIT", "TRACKONE_TSA_WORKER_CONCURRENCY",
                "TRACKONE_TSA_RETRY_INITIAL_MS", "TRACKONE_TSA_RETRY_MAX_MS", "TRACKONE_TSA_MAX_ATTEMPTS",
                "TRACKONE_QUALIFICATION_CONTROL",
            }:
                del self.env[key]

    def start(self):
        log = (self.output / f"gateway-{len(self.logs)}.log").open("w")
        self.logs.append(log)
        self.process = subprocess.Popen([str(TARGET / "trackone-vtl-gateway")],
                                        cwd=ROOT, env=self.env, stdout=log, stderr=log)
        wait_gateway(self.port)

    def kill(self):
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=10)
        self.process = None

    def restart(self):
        self.kill()
        self.clear_control()
        self.start()

    def close(self):
        self.kill()
        for log in self.logs:
            log.close()
        write_json(self.output / "admissions.json", self.journal)
        write_json(self.output / "hooks.json", self.hooks)
        write_json(self.output / "lease-adjustments.json", self.lease_updates)
        self.db.sql("trackone", f"DROP DATABASE IF EXISTS {self.database} WITH (FORCE)", check=False)

    def sql(self, query, **kwargs):
        return self.db.sql(self.database, query, **kwargs)

    def snapshot(self):
        query = """
        SELECT json_build_object(
          'state', (SELECT json_build_object('next', next_segment_number::text,
             'predecessor', encode(predecessor_cbor,'hex'), 'revision',revision::text,
             'opened_at_ms',opened_at_ms::text) FROM trackone_vtl_ledger_state),
          'segments', COALESCE((SELECT json_agg(x ORDER BY x.number::numeric) FROM (
             SELECT segment_number::text AS number, encode(artifact_cbor,'hex') AS artifact,
             artifact_sha256 AS sha256, close_reason AS reason, tsa_status AS tsa,
             encode(tsa_response,'hex') AS response FROM trackone_vtl_sealed_segment) x),'[]'),
          'records', COALESCE((SELECT json_agg(x ORDER BY x.segment::numeric NULLS LAST,x.ordinal::numeric)
             FROM (SELECT segment_number::text AS segment,ordinal::text,encode(record_cbor,'hex') AS record
                 FROM trackone_vtl_sealed_record UNION ALL SELECT NULL,ordinal::text,encode(record_cbor,'hex')
                 FROM trackone_vtl_open_record) x),'[]'),
          'keys', COALESCE((SELECT json_agg(idempotency_key ORDER BY idempotency_key)
              FROM trackone_vtl_idempotency),'[]'));
        """
        return json.loads(self.sql(query).stdout)

    def request(self, key: str, records: list[bytes], *, port: int | None = None):
        assert key not in self.requests or self.requests[key] == [r.hex() for r in records], "fixture changed retry payload"
        self.requests[key] = [r.hex() for r in records]
        body = bytes([0x80 + len(records)]) + b"".join(cbor_bytes(r) for r in records)
        connection = http.client.HTTPConnection("127.0.0.1", port or self.port, timeout=15)
        event = {"key": key, "records": self.requests[key]}
        try:
            connection.request("POST", "/v2/record-batches", body=body, headers={
                "Authorization": "Bearer " + TOKEN, "Idempotency-Key": key,
                "Content-Type": "application/vnd.trackone.record-batch.v1+cbor"})
            response = connection.getresponse()
            data = response.read()
            event.update(status=response.status, body=data.decode())
            if response.status in (200, 201):
                self.acknowledged.add(key)
                self.committed.add(key)
            return response.status, json.loads(data)
        except (OSError, http.client.HTTPException) as error:
            event["error"] = type(error).__name__
            return None
        finally:
            connection.close()
            self.journal.append(event)
            write_json(self.output / "admissions.json", self.journal)

    def admit(self, key, records):
        result = self.request(key, records)
        assert result is not None and result[0] in (200, 201), f"admission failed: {result}"
        return result

    def verify_state(self, label: str, baseline: dict | None = None):
        snapshot = self.snapshot()
        expected = [r for key in self.committed for r in self.requests[key]]
        assert_occurrences(expected, [r["record"] for r in snapshot["records"]])
        assert set(snapshot["keys"]) == self.committed, "durable retry key mismatch"
        current = {s["number"]: s["artifact"] for s in snapshot["segments"]}
        assert_artifacts(self.observed_artifacts, current)
        self.observed_artifacts.update(current)
        timestamps = {s["number"]: s["response"] for s in snapshot["segments"] if s["tsa"] == "verified"}
        assert_artifacts(self.observed_timestamps, timestamps)
        self.observed_timestamps.update(timestamps)
        if baseline:
            assert_artifacts({s["number"]: s["artifact"] for s in baseline["segments"]}, current)
        profile = assert_chain(snapshot, lambda data: self.checker.CborDecoder(data).decode())
        assert profile == PROFILE, "unexpected commitment profile"
        write_json(self.output / (label + ".json"), snapshot)
        return snapshot

    def wait_timestamps(self):
        def complete():
            snapshot = self.snapshot()
            assert all(s["tsa"] != "failed" for s in snapshot["segments"]), "timestamp retries exhausted"
            return all(s["tsa"] == "verified" for s in snapshot["segments"])
        wait_for(complete, "timestamp completion", 60)

    def seed(self):
        self.start()
        self.admit("baseline", [record(1), record(1), record(2), record(3)])
        self.wait_timestamps()
        self.admit("seed-a", [record(4)])
        self.admit("seed-b", [record(4)])
        return self.verify_state("baseline")

    def clear_control(self):
        for path in self.control.iterdir():
            path.unlink()

    def arm(self, boundary, *, key=None, segment=None):
        self.clear_control()
        write_json(self.control / "arm.json", {
            "boundary": boundary, "ledger_id": self.ledger, "key": key, "segment_number": segment,
        })

    def reached(self):
        event = wait_for(lambda: json.loads((self.control / "reached.json").read_text())
                         if (self.control / "reached.json").exists() else None, "selected crash boundary")
        assert event["pid"] == self.process.pid, "hook reached by unexpected process"
        self.hooks.append(event)
        write_json(self.output / "hooks.json", self.hooks)
        return event

    def expire_lease(self):
        before = self.sql("SELECT segment_number::text,tsa_attempt_count,tsa_lease_until::text "
                          "FROM trackone_vtl_sealed_segment WHERE tsa_status='queued'").stdout
        self.sql("UPDATE trackone_vtl_sealed_segment SET tsa_lease_until=CURRENT_TIMESTAMP - INTERVAL '1 second', "
                 "tsa_next_attempt=CURRENT_TIMESTAMP - INTERVAL '1 second' WHERE tsa_status='queued'")
        self.lease_updates.append({"reason": "accelerate five-minute crash lease in fixture", "before": before})

    def clock(self, now_ms: int, continuity: int = 1):
        path = self.work / "clock.json"
        write_json(path, {"now_ms": now_ms, "continuity_id": str(continuity)})
        self.env["TRACKONE_QUALIFICATION_CLOCK"] = str(path)

    def export_verify(self):
        self.wait_timestamps()
        snapshot = self.verify_state("final")
        publish = self.output / "published"
        publish.mkdir()
        reports = self.output / "verification"
        reports.mkdir()
        verification = []
        with ExitStack() as services:
            port = free_port()
            server = start_server("static", port, self.pki, self.output / "https-evidence", root=publish)
            services.callback(stop_process, server)
            for segment in snapshot["segments"]:
                number = segment["number"]
                bundle = publish / ("segment-" + number)
                run([str(TARGET / "trackone-vtl-export"), "--ledger-id", self.ledger,
                     "--segment-number", number, "--class", "A", "--output", str(bundle)], env=self.env)
                url = f"https://localhost:{port}/{bundle.name}/"
                wait_https(port, self.pki["https_root"], f"/{bundle.name}/segment.verify.json")
                trust = ["--tsa-ca-file", str(self.pki["tsa_root"]), "--tsa-crls-file", str(self.pki["tsa_crls"]),
                         "--tsa-policy", POLICY_OID, "--tsa-signer-cert-sha256", self.signer]
                evaluation = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                write_json(reports / (number + "-inputs.json"), {
                    "evaluation_time": evaluation, "expected_segment_sha256": segment["sha256"],
                    "scope": "public_recompute", "policy_oid": POLICY_OID,
                    "signer_sha256": self.signer, "max_future_skew_seconds": 5,
                })
                independent_report = reports / (number + "-independent.json")
                run([sys.executable, str(CHECKER), "--bundle-url", url, "--scope", "public_recompute",
                     "--expected-segment-sha256", segment["sha256"], "--https-ca-file", str(self.pki["https_root"]),
                     *trust, "--evaluation-time", evaluation,
                     "--max-future-skew-seconds", "5", "--output", str(independent_report)])
                rust = json.loads(run([str(TARGET / "trackone-evidence"), "verify", "--root", str(bundle),
                                      *trust, "--tsa-max-future-skew-seconds", "5", "--json"]).stdout)
                write_json(reports / (number + "-trackone.json"), rust)
                independent = json.loads(independent_report.read_text())
                assert rust["overall"] == independent["overall"] == "success", "independent verification failed"
                assert rust["artifact_sha256"] == independent["artifact_sha256"] == segment["sha256"]
                exported = json.loads((bundle / "segment.verify.json").read_text())
                artifact = bundle / exported["artifacts"]["segment_cbor"]["path"]
                assert artifact.read_bytes().hex() == segment["artifact"], "export changed artifact bytes"
                verification.extend([str(p.relative_to(self.output.parent)) for p in
                                     (independent_report, reports / (number + "-trackone.json"))])
        return verification


def crash_case(case: Scenario, boundary: str):
    target = [record(5), record(5)]
    case.arm(boundary, key="target" if boundary.startswith("ledger_") or boundary == "admission_response" else None,
             segment=1 if boundary.startswith("timestamp_") or boundary in ("seal_construct", "seal_inserted", "records_copied") else None)
    with ThreadPoolExecutor(max_workers=1) as executor:
        request = executor.submit(case.request, "target", target)
        case.reached()
        committed = "target" in case.snapshot()["keys"]
        if boundary in ("ledger_after_commit", "admission_response", "timestamp_before_commit", "timestamp_after_commit"):
            assert committed, "expected admission commit missing"
        else:
            assert not committed, "transaction committed before selected boundary"
        if committed:
            case.committed.add("target")
        case.verify_state("at-boundary")
        case.kill()
        request.result(timeout=20)
    case.clear_control()
    case.start()
    case.verify_state("before-retry")
    case.expire_lease()
    status, _ = case.admit("target", target)
    assert status == (200 if committed else 201), "unexpected retry disposition"


def lost_response(case: Scenario):
    observed = []

    class DropResponse(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            connection = http.client.HTTPConnection("127.0.0.1", case.port, timeout=15)
            try:
                connection.request("POST", self.path, body, dict(self.headers))
                response = connection.getresponse()
                response.read()
                observed.append({"upstream_status": response.status, "response_dropped": True})
                # Close without sending any response bytes to the uploader.
                self.close_connection = True
            finally:
                connection.close()

        def log_message(self, *_):
            pass

    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), DropResponse) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = case.request("target", [record(5), record(5)], port=server.server_port)
            assert result is None and observed == [{"upstream_status": 201, "response_dropped": True}]
        finally:
            server.shutdown()
            thread.join(timeout=5)
    write_json(case.output / "lost-response.json", observed)
    assert "target" in case.snapshot()["keys"] and "target" not in case.acknowledged
    case.committed.add("target")
    case.verify_state("committed-without-response")
    case.restart()
    assert case.admit("target", [record(5), record(5)])[0] == 200


def transaction_error(case: Scenario, kind: str):
    table = {"admission": "trackone_vtl_idempotency", "sealing": "trackone_vtl_sealed_record",
             "timestamp": "trackone_vtl_sealed_segment"}[kind]
    operation = "UPDATE" if kind == "timestamp" else "INSERT"
    condition = "IF NEW.tsa_status <> 'verified' THEN RETURN NEW; END IF;" if kind == "timestamp" else ""
    marker = "qualification_" + kind + "_transaction_error"
    case.sql(f"CREATE FUNCTION qualification_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {condition} "
             f"RAISE EXCEPTION '{marker}' USING ERRCODE='40001'; END $$; "
             f"CREATE TRIGGER qualification_fail BEFORE {operation} ON {table} FOR EACH ROW EXECUTE FUNCTION qualification_fail();")
    result = case.request("target", [record(5), record(5)])
    if kind == "timestamp":
        assert result and result[0] == 201, "TSA failure revoked admission"
        wait_for(lambda: marker in (case.output / "gateway-0.log").read_text(), "timestamp transaction error")
        assert case.snapshot()["segments"][-1]["tsa"] == "queued"
    else:
        assert result and result[0] == 503 and marker in json.dumps(result), "transaction error not observed"
    case.sql(f"DROP TRIGGER qualification_fail ON {table}; DROP FUNCTION qualification_fail()")
    case.restart()
    case.expire_lease()
    case.admit("target", [record(5), record(5)])
    return {"sqlstate": "40001", "marker": marker}


def full_storage(case: Scenario):
    # PGDATA and WAL remain on normal storage; the bounded relation tablespace
    # alone fills. This produces genuine ENOSPC without risking host storage.
    case.sql("CREATE TABLESPACE qualification_space LOCATION '/qualification'; "
             "ALTER TABLE trackone_vtl_open_record SET TABLESPACE qualification_space; "
             "ALTER TABLE trackone_vtl_open_record ALTER COLUMN record_cbor SET STORAGE EXTERNAL; CHECKPOINT")
    fill = subprocess.run(["docker", "exec", case.db.container, "sh", "-c",
                           "dd if=/dev/zero of=/qualification/filler bs=4096"], capture_output=True, text=True, timeout=30)
    assert fill.returncode != 0 and "No space left on device" in fill.stderr, "storage was not exhausted"
    evidence = run(["docker", "exec", case.db.container, "df", "-k", "/qualification"]).stdout
    (case.output / "storage-full.txt").write_text(evidence + fill.stderr)
    large = record(6)[:-1] + cbor_bytes(os.urandom(128 * 1024))
    result = case.request("target", [large])
    assert result and result[0] == 503 and "53100" in json.dumps(result), "PostgreSQL disk-full admission not observed"
    logs = run(["docker", "logs", case.db.container]).stderr
    assert "No space left on device" in logs, "PostgreSQL disk-full error not observed"
    (case.output / "disk-full-database.log").write_text(logs)
    assert "target" not in case.snapshot()["keys"], "disk-full admission partially committed"
    # Delete only this fixture's named filler inside its disposable container.
    run(["docker", "exec", case.db.container, "rm", "/qualification/filler"])
    case.restart()
    case.admit("target", [large])
    return {"filesystem": "bounded Docker tmpfs tablespace", "postgres_enospc": True, "sqlstate": "53100"}


def restore(case: Scenario, stack: ExitStack, output: Path):
    case.arm("timestamp_before_commit", segment=1)
    case.admit("target", [record(5), record(5)])
    case.reached()
    case.kill()
    # Include acknowledged open records as well as a pending leased TSA job.
    case.clear_control()
    case.start()
    case.admit("restore-open", [record(7)])
    case.kill()
    before = case.verify_state("before-restore")
    dump = subprocess.run(["docker", "exec", case.db.container, "pg_dump", "-U", "trackone",
                           "-d", case.database, "--no-owner", "--no-acl", "--no-tablespaces"],
                          capture_output=True, check=True, timeout=30).stdout
    new_db = Database(stack, output)
    new_db.sql("trackone", f"CREATE DATABASE {case.database}")
    result = subprocess.run(["docker", "exec", "-i", new_db.container, "psql", "-U", "trackone",
                             "-d", case.database, "-v", "ON_ERROR_STOP=1"], input=dump,
                            capture_output=True, timeout=30)
    assert result.returncode == 0, "fresh database restore failed"
    case.db = new_db
    case.env["TRACKONE_DATABASE_URL"] = new_db.url(case.database)
    assert case.snapshot() == before, "restore changed durable state"
    case.start()
    case.expire_lease()
    for key, records in list(case.requests.items()):
        status, _ = case.admit(key, [bytes.fromhex(r) for r in records])
        assert status == 200, "restored retry key missing"
    case.verify_state("after-restore", before)
    return {"fresh_container": new_db.container, "dump_sha256": hashlib.sha256(dump).hexdigest(),
            "pending_timestamp_present": any(s["tsa"] == "queued" for s in before["segments"]),
            "open_records_present": any(r["segment"] is None for r in before["records"])}


def exercise(case: Scenario, stack: ExitStack, output: Path):
    name = case.name
    if name.startswith("clock_"):
        case.clock(1000)
    baseline = case.seed()
    fault = {"scenario": name}
    if name in BOUNDARIES:
        crash_case(case, name)
        fault["hook"] = case.hooks[-1]
    elif name == "acknowledged_restart":
        case.admit("target", [record(5), record(5)])
        case.restart()
        assert case.admit("target", [record(5), record(5)])[0] == 200
        fault["acknowledgment_before_sigkill"] = True
    elif name == "lost_response_retry":
        lost_response(case)
        fault["dropped_success_response"] = True
    elif name.endswith("transaction_error"):
        fault.update(transaction_error(case, name.split("_")[0]))
    elif name == "full_storage":
        fault.update(full_storage(case))
    elif name.startswith("clock_"):
        if name == "clock_forward":
            case.clock(3601000)
            case.admit("target", [record(5), record(5)])
            assert any(s["reason"] == "interval" for s in case.snapshot()["segments"]), "forward interval not sealed"
        else:
            case.clock(0 if name == "clock_backward" else 1000, 2 if name == "clock_continuity" else 1)
            result = case.request("target", [record(5), record(5)])
            assert result and result[0] == 503 and "clock" in json.dumps(result), "discontinuity not rejected"
        case.kill()
        case.clock(4000000, 3)
        case.start()
        case.admit("target", [record(5), record(5)])
        fault["controlled_elapsed_clock"] = True
    elif name == "database_disconnect":
        # Terminate established gateway DB connections, producing a real socket
        # failure; psql's own connection remains alive to observe durable state.
        count = case.sql("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid();").stdout
        assert int(count.strip()) >= 2
        case.sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()")
        result = case.request("target", [record(5), record(5)])
        assert result and result[0] == 503, "lost DB connection not observed"
        case.restart()
        case.admit("target", [record(5), record(5)])
        fault["terminated_connections"] = int(count.strip())
    elif name == "database_crash":
        case.admit("target", [record(5), record(5)])
        run(["docker", "kill", "--signal", "KILL", case.db.container])
        run(["docker", "start", case.db.container])
        case.db.ready()
        case.restart()
        case.expire_lease()
        assert case.admit("target", [record(5), record(5)])[0] == 200
        fault["postgres_sigkill"] = True
    elif name == "tsa_outage":
        original = case.env["TRACKONE_TSA_URL"]
        case.kill()
        case.env["TRACKONE_TSA_URL"] = f"https://localhost:{free_port()}/tsa"
        case.start()
        case.admit("target", [record(5), record(5)])
        wait_for(lambda: int(case.sql("SELECT COALESCE(max(tsa_attempt_count),0) FROM trackone_vtl_sealed_segment WHERE tsa_status='queued'").stdout) > 0,
                 "TSA failed submission")
        wait_for(lambda: bool(case.sql("SELECT count(*) FROM trackone_vtl_sealed_segment WHERE tsa_last_error IS NOT NULL").stdout.strip() != "0"),
                 "TSA network error")
        case.kill()
        case.env["TRACKONE_TSA_URL"] = original
        case.start()
        case.expire_lease()
        assert case.admit("target", [record(5), record(5)])[0] == 200
        fault["tsa_unavailable_with_durable_retry"] = True
    elif name == "fresh_restore":
        fault.update(restore(case, stack, output))
        assert fault["pending_timestamp_present"] and fault["open_records_present"]
    else:
        raise AssertionError("unknown required scenario")
    case.verify_state("after-fault", baseline)
    # Force recovery of any acknowledged open records before export. Ordinary
    # restarts create an explicit recovery artifact even for an empty interval.
    case.kill()
    case.env.pop("TRACKONE_QUALIFICATION_CLOCK", None)
    case.clear_control()
    case.start()
    case.expire_lease()
    case.verify_state("after-final-restart", baseline)
    verification = case.export_verify()
    return {"name": name, "status": "passed", "fault_observed": fault,
            "acknowledged_uploads": len(case.acknowledged),
            "acknowledged_occurrences": sum(len(case.requests[k]) for k in case.acknowledged),
            "committed_occurrences": sum(len(case.requests[k]) for k in case.committed),
            "invariants": ["occurrence_multiplicity", "idempotency", "immutable_artifacts", "segment_chain"],
            "verification_reports": verification, "ledger_id": case.ledger}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        parser.error("output already exists; choose a fresh evidence directory")
    output.mkdir(parents=True)
    report = {"version": 1, "status": "failed", "scenarios": [],
              "required_scenarios": list(REQUIRED_SCENARIOS), "profile_uuid": None}
    try:
        report.update(commit=run(["git", "rev-parse", "HEAD"]).stdout.strip(),
                      worktree_status=run(["git", "status", "--porcelain"]).stdout.splitlines(),
                      source_sha256=source_hashes(ROOT),
                      build_features=["recovery-qualification"],
                      limits=["process crashes and PostgreSQL ENOSPC; physical media and power loss unqualified"],
                      started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        write_json(output / "report.json", report)
        require_tools()
        build_env = os.environ.copy()
        build_env["CARGO_TARGET_DIR"] = str(TARGET.parent)
        run(["cargo", "build", "--locked", "-p", "trackone-gateway-svc", "--bins",
             "--features", "recovery-qualification", "-p", "trackone-evidence"], env=build_env)
        report["tools"] = {tool: run(command).stdout.strip() for tool, command in (
            ("cargo", ["cargo", "--version"]), ("rustc", ["rustc", "--version"]),
            ("openssl", ["openssl", "version"]), ("docker", ["docker", "--version"]),
            ("python", [sys.executable, "--version"]))}
        with tempfile.TemporaryDirectory(prefix="trackone-recovery-") as temporary, ExitStack() as stack:
            work = Path(temporary)
            pki = create_pki(work)
            signer = hashlib.sha256(subprocess.check_output(
                ["openssl", "x509", "-in", pki["tsa_cert"], "-outform", "DER"])).hexdigest()
            trust = output / "trust-inputs"
            trust.mkdir()
            for key in ("https_root", "tsa_root", "tsa_crls", "tsa_cert"):
                shutil.copy2(pki[key], trust / pki[key].name)
            report["trust"] = {"policy_oid": POLICY_OID, "signer_sha256": signer}
            tsa_port = free_port()
            tsa = start_server("tsa", tsa_port, pki, output / "tsa-exchange")
            stack.callback(stop_process, tsa)
            wait_https(tsa_port, pki["https_root"], "/not-a-tsa-get")
            db = Database(stack, output)
            report["postgres"] = {"image_id": db.image["Id"], "repo_digests": db.image["RepoDigests"]}
            checker = independent_module()
            for name in REQUIRED_SCENARIOS:
                print(f"qualifying {name}", flush=True)
                case = Scenario(name, db, work, output, pki, tsa_port, signer, checker)
                try:
                    result = exercise(case, stack, output)
                    # Read the UUID from actual final artifacts, not just configuration.
                    final = json.loads((case.output / "final.json").read_text())
                    report["profile_uuid"] = assert_chain(final, lambda data: checker.CborDecoder(data).decode())
                    report["scenarios"].append(result)
                except Exception as error:
                    report["scenarios"].append({"name": name, "status": "failed", "error": str(error),
                                                "fault_observed": case.hooks, "verification_reports": []})
                    raise
                finally:
                    case.close()
                    write_json(output / "report.json", report)
            assert_complete(report)
            assert source_hashes(ROOT) == report["source_sha256"], "source changed during qualification"
            report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
        print(f"RECOVERY QUALIFICATION FAILED: {error}", file=sys.stderr)
    finally:
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        write_json(output / "report.json", report)
        (output / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(output).as_posix()}\n"
            for p in sorted(output.rglob("*")) if p.is_file() and p.name != "SHA256SUMS"))
    if report["status"] == "passed":
        print(f"recovery qualification succeeded: {output}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
