#!/usr/bin/env python3
"""Build a read-only SensorThings projection from gateway fact artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

try:  # pragma: no cover - optional native acceleration
    import trackone_core

    _RUST_SENSORTHINGS = getattr(trackone_core, "sensorthings", None)
except Exception:  # pragma: no cover - native extension unavailable
    _RUST_SENSORTHINGS = None

OBSERVED_PROPERTIES: dict[str, dict[str, str]] = {
    "temp_c": {
        "key": "temperature_air",
        "label": "Ambient Air Temperature",
        "unit": "Cel",
    },
    "bioimpedance": {
        "key": "bioimpedance_magnitude",
        "label": "Bioimpedance Magnitude",
        "unit": "1",
    },
}


def _entity_id(kind: str, *components: str) -> str:
    digest = hashlib.sha256()
    digest.update(kind.encode("utf-8"))
    for component in components:
        digest.update(b"\x1f")
        digest.update(component.encode("utf-8"))
    return f"trackone:{kind}:{digest.hexdigest()}"


def load_device_table(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def load_facts(facts_dir: Path) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    for path in sorted(facts_dir.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            facts.append(data)
    return facts


def resolve_sensor_key(
    device_id: str,
    observed_property_key: str,
    *,
    device_meta: dict[str, Any] | None,
) -> str:
    if isinstance(device_meta, dict):
        sensor_keys = device_meta.get("sensor_keys")
        if isinstance(sensor_keys, dict):
            candidate = sensor_keys.get(observed_property_key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate
        sensors = device_meta.get("sensors")
        if isinstance(sensors, dict):
            for sensor_key, sensor_meta in sensors.items():
                if not isinstance(sensor_meta, dict):
                    continue
                observed = sensor_meta.get("observed_property_keys")
                if isinstance(observed, list) and observed_property_key in observed:
                    return str(sensor_key)
    return f"{device_id}:{observed_property_key}"


def project_fact(
    fact: dict[str, Any],
    *,
    site_id: str,
    device_meta: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    device_id = str(fact["device_id"])
    timestamp = str(fact["timestamp"])
    payload = fact.get("payload")
    if not isinstance(payload, dict):
        return []

    observations: list[dict[str, Any]] = []
    for payload_key, mapping in OBSERVED_PROPERTIES.items():
        if payload_key not in payload:
            continue

        observed_property_key = mapping["key"]
        sensor_key = resolve_sensor_key(
            device_id, observed_property_key, device_meta=device_meta
        )
        scalar_value = float(payload[payload_key])

        rust_projection = _project_via_rust(
            device_id=device_id,
            site_id=site_id,
            sensor_key=sensor_key,
            observed_property_key=observed_property_key,
            stream_key="raw",
            phenomenon_time_start=timestamp,
            phenomenon_time_end=timestamp,
            result_time=timestamp,
            scalar_value=scalar_value,
        )
        if rust_projection is not None:
            projection = rust_projection
        else:
            projection = _project_via_python(
                device_id=device_id,
                site_id=site_id,
                sensor_key=sensor_key,
                observed_property_key=observed_property_key,
                stream_key="raw",
                phenomenon_time_start=timestamp,
                phenomenon_time_end=timestamp,
                result_time=timestamp,
                scalar_value=scalar_value,
            )

        projection["observed_property"] = {
            "id": _entity_id("observed-property", observed_property_key),
            "key": observed_property_key,
            "label": mapping["label"],
            "unit_of_measurement": {
                "symbol": mapping["unit"],
                "name": mapping["label"],
            },
        }
        observations.append(projection)
    return observations


def _project_via_rust(
    *,
    device_id: str,
    site_id: str,
    sensor_key: str,
    observed_property_key: str,
    stream_key: str,
    phenomenon_time_start: str,
    phenomenon_time_end: str,
    result_time: str,
    scalar_value: float,
) -> dict[str, Any] | None:
    if _RUST_SENSORTHINGS is None:
        return None
    try:
        raw = _RUST_SENSORTHINGS.project_env_observation_json(
            device_id,
            site_id,
            sensor_key,
            observed_property_key,
            stream_key,
            phenomenon_time_start,
            phenomenon_time_end,
            result_time,
            scalar_result=scalar_value,
        )
        if isinstance(raw, str):
            parsed: object = json.loads(raw)
            if isinstance(parsed, dict):
                return cast(dict[str, Any], parsed)
    except Exception:
        return None
    return None


def _project_via_python(
    *,
    device_id: str,
    site_id: str,
    sensor_key: str,
    observed_property_key: str,
    stream_key: str,
    phenomenon_time_start: str,
    phenomenon_time_end: str,
    result_time: str,
    scalar_value: float,
) -> dict[str, Any]:
    thing_id = _entity_id("thing", device_id)
    sensor_id = _entity_id("sensor", device_id, sensor_key)
    observed_property_id = _entity_id("observed-property", observed_property_key)
    datastream_id = _entity_id(
        "datastream", device_id, sensor_key, observed_property_key, stream_key
    )
    observation_id = _entity_id(
        "observation",
        datastream_id,
        phenomenon_time_start,
        phenomenon_time_end,
        result_time,
    )
    return {
        "ids": {
            "thing_id": thing_id,
            "sensor_id": sensor_id,
            "observed_property_id": observed_property_id,
            "datastream_id": datastream_id,
            "observation_id": observation_id,
        },
        "thing": {
            "id": thing_id,
            "pod_id": device_id,
            "site_id": site_id,
        },
        "datastream": {
            "id": datastream_id,
            "thing_id": thing_id,
            "sensor_id": sensor_id,
            "observed_property_id": observed_property_id,
            "stream_key": stream_key,
        },
        "observation": {
            "id": observation_id,
            "datastream_id": datastream_id,
            "phenomenon_time": {
                "start_rfc3339_utc": phenomenon_time_start,
                "end_rfc3339_utc": phenomenon_time_end,
            },
            "result_time_rfc3339_utc": result_time,
            "result": scalar_value,
        },
    }


def build_bundle(
    facts: Iterable[dict[str, Any]],
    *,
    site_id: str,
    device_table: dict[str, Any] | None = None,
) -> dict[str, Any]:
    things: dict[str, dict[str, Any]] = {}
    datastreams: dict[str, dict[str, Any]] = {}
    observed_properties: dict[str, dict[str, Any]] = {}
    observations: list[dict[str, Any]] = []

    device_table = device_table or {}

    for fact in facts:
        device_id = str(fact.get("device_id", ""))
        device_num = _device_num_from_id(device_id)
        device_meta = (
            device_table.get(str(device_num)) if device_num is not None else None
        )

        for projection in project_fact(
            fact,
            site_id=site_id,
            device_meta=device_meta if isinstance(device_meta, dict) else None,
        ):
            thing = projection["thing"]
            datastream = projection["datastream"]
            observed_property = projection["observed_property"]
            observation = projection["observation"]

            things[thing["id"]] = thing
            datastreams[datastream["id"]] = datastream
            observed_properties[observed_property["id"]] = observed_property
            observations.append(observation)

    observations.sort(key=lambda item: item["id"])
    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "site_id": site_id,
        "projection_mode": "read_only_legacy_fact_json",
        "things": sorted(things.values(), key=lambda item: item["id"]),
        "datastreams": sorted(datastreams.values(), key=lambda item: item["id"]),
        "observed_properties": sorted(
            observed_properties.values(), key=lambda item: item["id"]
        ),
        "observations": observations,
    }


def write_bundle(
    *,
    facts_dir: Path,
    device_table_path: Path | None,
    site_id: str,
    out_path: Path,
) -> Path:
    bundle = build_bundle(
        load_facts(facts_dir),
        site_id=site_id,
        device_table=load_device_table(device_table_path),
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return out_path


def _device_num_from_id(device_id: str) -> int | None:
    parts = device_id.rsplit("-", 1)
    if len(parts) != 2:
        return None
    try:
        return int(parts[1], 10)
    except ValueError:
        return None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a read-only SensorThings projection artifact."
    )
    parser.add_argument("--facts", type=Path, required=True)
    parser.add_argument("--site", required=True)
    parser.add_argument("--device-table", type=Path, default=None)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    write_bundle(
        facts_dir=args.facts,
        device_table_path=args.device_table,
        site_id=args.site,
        out_path=args.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
