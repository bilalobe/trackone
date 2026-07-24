#!/usr/bin/env python3
"""Validate TrackOne's public JSON contracts with offline reference resolution."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urldefrag

from jsonschema import exceptions, validators
from referencing import Registry, Resource


PROVIDER = (
    "https://raw.githubusercontent.com/bilalobe/trackone/"
    "main/toolset/unified/schemas/"
)
META_PREFIX = "https://json-schema.org/"


class ContractError(RuntimeError):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read JSON {path}: {exc}") from exc


def walk_refs(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        ref = value.get("$ref")
        if isinstance(ref, str):
            yield ref
        for child in value.values():
            yield from walk_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_refs(child)


def validate_instance(
    instance_path: Path,
    schema: dict[str, Any],
    registry: Registry,
) -> None:
    instance = load_json(instance_path)
    validator_type = validators.validator_for(schema)
    validator = validator_type(schema, registry=registry)
    errors = sorted(validator.iter_errors(instance), key=lambda err: list(err.path))
    if errors:
        details = "; ".join(
            f"{'.'.join(str(item) for item in error.path) or '<root>'}: {error.message}"
            for error in errors[:8]
        )
        raise ContractError(f"{instance_path} fails schema {schema['$id']}: {details}")


def check(repo: Path) -> dict[str, int]:
    unified = repo / "toolset/unified"
    schema_dir = unified / "schemas"
    catalog_path = unified / "schema-catalog.json"
    catalog = load_json(catalog_path)
    if catalog.get("schema") != "trackone-schema-catalog-v1":
        raise ContractError("schema catalog has the wrong compatibility token")
    if catalog.get("provider") != PROVIDER:
        raise ContractError("schema catalog provider does not match the public provider")

    schema_paths = sorted(schema_dir.glob("*.schema.json"))
    schemas: dict[str, dict[str, Any]] = {}
    paths_by_id: dict[str, Path] = {}
    for path in schema_paths:
        schema = load_json(path)
        schema_id = schema.get("$id")
        if not isinstance(schema_id, str) or not schema_id:
            raise ContractError(f"{path} has no non-empty $id")
        if "example.org" in schema_id:
            raise ContractError(f"{path} still uses the placeholder example.org provider")
        if schema_id in schemas:
            raise ContractError(f"duplicate schema $id: {schema_id}")
        if schema_id.startswith("http") and schema_id != f"{PROVIDER}{path.name}":
            raise ContractError(f"{path} provider $id is not canonical: {schema_id}")
        schemas[schema_id] = schema
        paths_by_id[schema_id] = path

    catalog_entries = {
        **catalog.get("resources", {}),
        **catalog.get("urn_resources", {}),
    }
    if set(catalog_entries) != set(schemas):
        missing = sorted(set(schemas) - set(catalog_entries))
        stale = sorted(set(catalog_entries) - set(schemas))
        raise ContractError(f"schema catalog mismatch; missing={missing}, stale={stale}")
    for schema_id, relative in catalog_entries.items():
        expected = paths_by_id[schema_id].relative_to(unified).as_posix()
        if relative != expected:
            raise ContractError(
                f"schema catalog path mismatch for {schema_id}: {relative!r} != {expected!r}"
            )

    for schema_id, schema in schemas.items():
        for ref in walk_refs(schema):
            target, _fragment = urldefrag(ref)
            if not target or target == schema_id or target.startswith(META_PREFIX):
                continue
            if target not in schemas:
                raise ContractError(f"{paths_by_id[schema_id]} has dangling $ref {ref!r}")

    resources = [
        (schema_id, Resource.from_contents(schema))
        for schema_id, schema in schemas.items()
    ]
    registry = Registry().with_resources(resources)
    for schema_id, schema in schemas.items():
        validator_type = validators.validator_for(schema)
        try:
            validator_type.check_schema(schema)
            validator_type(schema, registry=registry).check_schema(schema)
        except exceptions.SchemaError as exc:
            raise ContractError(f"invalid JSON Schema {paths_by_id[schema_id]}: {exc}") from exc

    instances = [
        (
            repo / "toolset/unified/examples/anchor_subject_v1.json",
            f"{PROVIDER}anchor_subject_v1.schema.json",
        ),
        (
            repo / "toolset/unified/examples/anchor_evidence_v1.json",
            f"{PROVIDER}anchor_evidence_v1.schema.json",
        ),
        (
            repo / "toolset/unified/examples/ots_verifier_sanity_v1.json",
            f"{PROVIDER}ots_verifier_sanity_v1.schema.json",
        ),
        (
            repo / "toolset/vectors/verifiable-telemetry-canonical-cbor-v1/manifest.json",
            f"{PROVIDER}commitment_vector_manifest.schema.json",
        ),
        (
            repo / "toolset/vectors/verifiable-telemetry-canonical-cbor-v2/manifest.json",
            f"{PROVIDER}v2_vector_manifest_v2.schema.json",
        ),
        (
            repo / "toolset/vectors/verifiable-telemetry-canonical-cbor-v2/cases.json",
            f"{PROVIDER}v2_bundle_cases_v1.schema.json",
        ),
        (
            repo / "toolset/vectors/trackone-beta-negative-v1/cases.json",
            f"{PROVIDER}negative_fixture_cases_v1.schema.json",
        ),
        (
            repo / "toolset/unified/examples/scitt_evidence_bundle_statement.json",
            f"{PROVIDER}scitt_evidence_bundle_statement.schema.json",
        ),
        (
            repo / "toolset/unified/examples/scitt_verify_manifest_statement.json",
            f"{PROVIDER}scitt_verify_manifest_statement.schema.json",
        ),
    ]
    instance_count = 0
    for instance_path, schema_id in instances:
        validate_instance(instance_path, schemas[schema_id], registry)
        instance_count += 1
    for instance_path in sorted(
        (
            repo
            / "toolset/vectors/verifiable-telemetry-canonical-cbor-v2/fixtures"
        ).glob("*/segment.verify.json")
    ):
        validate_instance(
            instance_path,
            schemas[f"{PROVIDER}verify_manifest_v2.schema.json"],
            registry,
        )
        instance_count += 1
    for instance_path in sorted(
        (
            repo
            / "toolset/vectors/verifiable-telemetry-canonical-cbor-v2/fixtures"
        ).glob("*/expected-result.json")
    ):
        validate_instance(
            instance_path,
            schemas[f"{PROVIDER}verification_result_v2.schema.json"],
            registry,
        )
        instance_count += 1

    conformance_schema = schemas[f"{PROVIDER}conformance_archive_manifest_v3.schema.json"]
    conformance_example = {
        "schema": "trackone-conformance-archive-v3",
        "schema_uri": f"{PROVIDER}conformance_archive_manifest_v3.schema.json",
        "version": 3,
        "subject": {
            "kind": "commit",
            "name": "sha-0000000000000000000000000000000000000000",
            "git_commit": "0" * 40,
        },
        "software_version": "0.1.0-beta.4",
        "repository": "bilalobe/trackone",
        "carrier": {
            "oci_ref": (
                "ghcr.io/bilalobe/trackone/conformance-archive:"
                "sha-0000000000000000000000000000000000000000"
            ),
            "artifact_type": "application/vnd.trackone.conformance.archive.v3+tar",
        },
        "contents": {
            "schema_catalog": "contracts/toolset/unified/schema-catalog.json",
            "schemas": "contracts/toolset/unified/schemas",
            "cddl": "contracts/toolset/unified/cddl",
            "vectors": "vectors",
            "crates": "software/crates",
            "helm": "software/helm",
            "detached_verifier": "verifier/bin/trackone-evidence",
        },
        "claims": {
            "canonical_cbor_v1_vectors": True,
            "canonical_cbor_v2_vectors": True,
            "v2_full_conformance": True,
            "v2_durable_producer": True,
            "v2_disclosure_classes": True,
            "rfc3161_timestamp_channel": True,
            "rfc5816_signer_certificate_binding": True,
            "negative_fixture_floor": True,
            "offline_schema_resolution": True,
        },
    }
    conformance_validator = validators.validator_for(conformance_schema)(
        conformance_schema, registry=registry
    )
    conformance_errors = list(conformance_validator.iter_errors(conformance_example))
    if conformance_errors:
        raise ContractError(
            f"conformance manifest example fails: {conformance_errors[0].message}"
        )
    instance_count += 1

    rejection_schema = schemas[f"{PROVIDER}rejection_audit.schema.json"]
    rejection_records = 0
    for path in sorted(
        (repo / "toolset/vectors/trackone-beta-negative-v1/fixtures").glob(
            "*/audit/*.ndjson"
        )
    ):
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            instance = json.loads(line)
            validator_type = validators.validator_for(rejection_schema)
            errors = list(
                validator_type(rejection_schema, registry=registry).iter_errors(instance)
            )
            if errors:
                raise ContractError(
                    f"{path}:{line_number} fails rejection schema: {errors[0].message}"
                )
            rejection_records += 1

    return {
        "schemas": len(schemas),
        "instances": instance_count,
        "rejection_records": rejection_records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    args = parser.parse_args()
    try:
        result = check(args.repo.resolve())
    except Exception as exc:
        print(f"contract check failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
