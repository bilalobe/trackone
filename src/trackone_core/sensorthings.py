"""Deterministic SensorThings projection helpers for canonical TrackOne facts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, cast

try:
    from ._native import sensorthings as _native_sensorthings
except ImportError:
    _native_sensorthings = None

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
    "temperature_air": {
        "key": "temperature_air",
        "label": "Ambient Air Temperature",
        "unit": "Cel",
    },
    "relative_humidity": {
        "key": "relative_humidity",
        "label": "Relative Humidity",
        "unit": "%",
    },
    "temperature_interface": {
        "key": "temperature_interface",
        "label": "Interface Temperature",
        "unit": "Cel",
    },
    "coverage_capacitance": {
        "key": "coverage_capacitance",
        "label": "Coverage Capacitance",
        "unit": "F",
    },
    "bioimpedance_magnitude": {
        "key": "bioimpedance_magnitude",
        "label": "Bioimpedance Magnitude",
        "unit": "1",
    },
    "bioimpedance_activity": {
        "key": "bioimpedance_activity",
        "label": "Bioimpedance Activity",
        "unit": "1",
    },
    "supply_voltage": {
        "key": "supply_voltage",
        "label": "Supply Voltage",
        "unit": "V",
    },
    "battery_soc": {
        "key": "battery_soc",
        "label": "Battery State of Charge",
        "unit": "%",
    },
    "flood_contact": {
        "key": "flood_contact",
        "label": "Flood Contact",
        "unit": "1",
    },
    "link_quality": {
        "key": "link_quality",
        "label": "Link Quality",
        "unit": "1",
    },
    "water_level": {
        "key": "water_level",
        "label": "Water Level",
        "unit": "m",
    },
    "water_flow_rate": {
        "key": "water_flow_rate",
        "label": "Water Flow Rate",
        "unit": "m3/s",
    },
    "water_volume": {
        "key": "water_volume",
        "label": "Water Volume",
        "unit": "m3",
    },
    "water_pressure": {
        "key": "water_pressure",
        "label": "Water Pressure",
        "unit": "Pa",
    },
    "water_temperature": {
        "key": "water_temperature",
        "label": "Water Temperature",
        "unit": "Cel",
    },
    "water_electrical_conductivity": {
        "key": "water_electrical_conductivity",
        "label": "Water Electrical Conductivity",
        "unit": "uS/cm",
    },
    "water_ph": {
        "key": "water_ph",
        "label": "Water pH",
        "unit": "pH",
    },
    "water_dissolved_oxygen": {
        "key": "water_dissolved_oxygen",
        "label": "Water Dissolved Oxygen",
        "unit": "mg/L",
    },
    "water_turbidity": {
        "key": "water_turbidity",
        "label": "Water Turbidity",
        "unit": "NTU",
    },
    "water_salinity": {
        "key": "water_salinity",
        "label": "Water Salinity",
        "unit": "ppt",
    },
    "water_total_dissolved_solids": {
        "key": "water_total_dissolved_solids",
        "label": "Water Total Dissolved Solids",
        "unit": "mg/L",
    },
    "rainfall": {
        "key": "rainfall",
        "label": "Rainfall",
        "unit": "mm",
    },
    "rain_intensity": {
        "key": "rain_intensity",
        "label": "Rain Intensity",
        "unit": "mm/h",
    },
    "wind_speed": {
        "key": "wind_speed",
        "label": "Wind Speed",
        "unit": "m/s",
    },
    "wind_direction": {
        "key": "wind_direction",
        "label": "Wind Direction",
        "unit": "deg",
    },
    "barometric_pressure": {
        "key": "barometric_pressure",
        "label": "Barometric Pressure",
        "unit": "Pa",
    },
    "solar_irradiance": {
        "key": "solar_irradiance",
        "label": "Solar Irradiance",
        "unit": "W/m2",
    },
    "soil_moisture": {
        "key": "soil_moisture",
        "label": "Soil Moisture",
        "unit": "%",
    },
    "soil_temperature": {
        "key": "soil_temperature",
        "label": "Soil Temperature",
        "unit": "Cel",
    },
    "soil_electrical_conductivity": {
        "key": "soil_electrical_conductivity",
        "label": "Soil Electrical Conductivity",
        "unit": "uS/cm",
    },
    "vibration_rms": {
        "key": "vibration_rms",
        "label": "Vibration RMS",
        "unit": "mm/s",
    },
    "vibration_peak": {
        "key": "vibration_peak",
        "label": "Vibration Peak",
        "unit": "mm/s",
    },
    "shock_acceleration": {
        "key": "shock_acceleration",
        "label": "Shock Acceleration",
        "unit": "g",
    },
    "inclination_angle": {
        "key": "inclination_angle",
        "label": "Inclination Angle",
        "unit": "deg",
    },
    "displacement": {
        "key": "displacement",
        "label": "Displacement",
        "unit": "mm",
    },
    "strain": {
        "key": "strain",
        "label": "Strain",
        "unit": "microstrain",
    },
    "crack_width": {
        "key": "crack_width",
        "label": "Crack Width",
        "unit": "mm",
    },
    "acoustic_noise": {
        "key": "acoustic_noise",
        "label": "Acoustic Noise",
        "unit": "dB",
    },
    "air_quality_pm25": {
        "key": "air_quality_pm25",
        "label": "Air Quality PM2.5",
        "unit": "ug/m3",
    },
    "air_quality_pm10": {
        "key": "air_quality_pm10",
        "label": "Air Quality PM10",
        "unit": "ug/m3",
    },
    "carbon_dioxide": {
        "key": "carbon_dioxide",
        "label": "Carbon Dioxide",
        "unit": "ppm",
    },
    "volatile_organic_compounds": {
        "key": "volatile_organic_compounds",
        "label": "Volatile Organic Compounds",
        "unit": "ppb",
    },
    "battery_voltage": {
        "key": "battery_voltage",
        "label": "Battery Voltage",
        "unit": "V",
    },
    "battery_current": {
        "key": "battery_current",
        "label": "Battery Current",
        "unit": "A",
    },
    "battery_temperature": {
        "key": "battery_temperature",
        "label": "Battery Temperature",
        "unit": "Cel",
    },
    "solar_charge_current": {
        "key": "solar_charge_current",
        "label": "Solar Charge Current",
        "unit": "A",
    },
    "enclosure_humidity": {
        "key": "enclosure_humidity",
        "label": "Enclosure Humidity",
        "unit": "%",
    },
    "enclosure_temperature": {
        "key": "enclosure_temperature",
        "label": "Enclosure Temperature",
        "unit": "Cel",
    },
    "radio_rssi": {
        "key": "radio_rssi",
        "label": "Radio RSSI",
        "unit": "dBm",
    },
    "radio_snr": {
        "key": "radio_snr",
        "label": "Radio SNR",
        "unit": "dB",
    },
}

OBSERVED_PROPERTIES_BY_KEY: dict[str, dict[str, str]] = {
    metadata["key"]: metadata for metadata in OBSERVED_PROPERTIES.values()
}

SAMPLE_TYPE_TO_PROPERTY_KEY: dict[str, str] = {
    "AmbientAirTemperature": "temperature_air",
    "AmbientRelativeHumidity": "relative_humidity",
    "InterfaceTemperature": "temperature_interface",
    "CoverageCapacitance": "coverage_capacitance",
    "BioImpedanceMagnitude": "bioimpedance_magnitude",
    "BioImpedanceActivity": "bioimpedance_activity",
    "SupplyVoltage": "supply_voltage",
    "BatterySoc": "battery_soc",
    "FloodContact": "flood_contact",
    "LinkQuality": "link_quality",
    "WaterLevel": "water_level",
    "WaterFlowRate": "water_flow_rate",
    "WaterVolume": "water_volume",
    "WaterPressure": "water_pressure",
    "WaterTemperature": "water_temperature",
    "WaterElectricalConductivity": "water_electrical_conductivity",
    "WaterPh": "water_ph",
    "WaterDissolvedOxygen": "water_dissolved_oxygen",
    "WaterTurbidity": "water_turbidity",
    "WaterSalinity": "water_salinity",
    "WaterTotalDissolvedSolids": "water_total_dissolved_solids",
    "Rainfall": "rainfall",
    "RainIntensity": "rain_intensity",
    "WindSpeed": "wind_speed",
    "WindDirection": "wind_direction",
    "BarometricPressure": "barometric_pressure",
    "SolarIrradiance": "solar_irradiance",
    "SoilMoisture": "soil_moisture",
    "SoilTemperature": "soil_temperature",
    "SoilElectricalConductivity": "soil_electrical_conductivity",
    "VibrationRms": "vibration_rms",
    "VibrationPeak": "vibration_peak",
    "ShockAcceleration": "shock_acceleration",
    "InclinationAngle": "inclination_angle",
    "Displacement": "displacement",
    "Strain": "strain",
    "CrackWidth": "crack_width",
    "AcousticNoise": "acoustic_noise",
    "AirQualityPm25": "air_quality_pm25",
    "AirQualityPm10": "air_quality_pm10",
    "CarbonDioxide": "carbon_dioxide",
    "VolatileOrganicCompounds": "volatile_organic_compounds",
    "BatteryVoltage": "battery_voltage",
    "BatteryCurrent": "battery_current",
    "BatteryTemperature": "battery_temperature",
    "SolarChargeCurrent": "solar_charge_current",
    "EnclosureHumidity": "enclosure_humidity",
    "EnclosureTemperature": "enclosure_temperature",
    "RadioRssi": "radio_rssi",
    "RadioSnr": "radio_snr",
}

SENSOR_METADATA_SCOPES = ("deployment", "provisioning")
SENSOR_IDENTITY_FIELDS = ("sensor_key", "sensor_id", "identity_pubkey", "device_id")


class ProjectionError(ValueError):
    """Raised when a SensorThings projection cannot be derived safely."""


class SensorIdentityResolutionError(ProjectionError):
    """Raised when a SensorThings Sensor identity cannot be resolved."""


def entity_id(kind: str, *components: str) -> str:
    if _native_sensorthings is not None and hasattr(_native_sensorthings, "entity_id"):
        native_id = _native_sensorthings.entity_id(kind, *components)
        if isinstance(native_id, str):
            return native_id
    digest = hashlib.sha256()
    digest.update(kind.encode("utf-8"))
    for component in components:
        digest.update(b"\x1f")
        digest.update(component.encode("utf-8"))
    return f"trackone:{kind}:{digest.hexdigest()}"


# Backwards-compatible alias; prefer the public name `entity_id`.
_entity_id = entity_id


def resolve_sensor_key(
    device_id: str,
    observed_property_key: str,
    *,
    device_meta: dict[str, Any] | None,
    sensor_channel: int | None = None,
) -> str:
    if isinstance(device_meta, dict):
        for metadata_scope in _sensor_metadata_scopes(device_meta):
            resolved = _resolve_sensor_key_from_metadata(
                metadata_scope,
                observed_property_key,
                sensor_channel=sensor_channel,
            )
            if resolved is not None:
                return resolved
    raise SensorIdentityResolutionError(
        "missing provisioning/deployment-backed sensor identity for "
        f"{device_id} observed_property={observed_property_key}"
    )


def project_fact(
    fact: dict[str, Any],
    *,
    site_id: str,
    device_meta: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    device_id = _device_id_from_fact(fact)
    result_time = _result_time_from_fact(fact)
    payload = _payload_from_fact(fact)
    if payload is None:
        return []

    kind = str(fact.get("kind", ""))
    if kind == "Env":
        env_projection = _project_env_payload(
            payload,
            device_id=device_id,
            site_id=site_id,
            device_meta=device_meta,
            result_time=result_time,
        )
        if env_projection is not None:
            return [env_projection]

    observations: list[dict[str, Any]] = []
    for payload_key, mapping in OBSERVED_PROPERTIES.items():
        if payload_key not in payload:
            continue

        observed_property_key = mapping["key"]
        sensor_key = resolve_sensor_key(
            device_id,
            observed_property_key,
            device_meta=device_meta,
        )
        scalar_value = float(payload[payload_key])

        projection = _project_via_python(
            device_id=device_id,
            site_id=site_id,
            sensor_key=sensor_key,
            observed_property_key=observed_property_key,
            stream_key="raw",
            phenomenon_time_start=result_time,
            phenomenon_time_end=result_time,
            result_time=result_time,
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


def build_bundle(
    facts: Iterable[dict[str, Any]],
    *,
    site_id: str,
    provisioning_records: dict[str, Any] | None = None,
    generated_at_utc: str | None = None,
) -> dict[str, Any]:
    things: dict[str, dict[str, Any]] = {}
    datastreams: dict[str, dict[str, Any]] = {}
    observed_properties: dict[str, dict[str, Any]] = {}
    observations: list[dict[str, Any]] = []

    provisioning_index = _index_provisioning_records(provisioning_records or {})

    for fact in facts:
        provisioning_context = _device_meta_from_table(fact, provisioning_index)
        for projection in project_fact(
            fact,
            site_id=site_id,
            device_meta=provisioning_context,
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
    bundle = {
        "generated_at_utc": generated_at_utc or datetime.now(UTC).isoformat(),
        "site_id": site_id,
        "projection_mode": "read_only_canonical_fact_json",
        "things": sorted(things.values(), key=lambda item: item["id"]),
        "datastreams": sorted(datastreams.values(), key=lambda item: item["id"]),
        "observed_properties": sorted(
            observed_properties.values(), key=lambda item: item["id"]
        ),
        "observations": observations,
    }
    try:
        json.dumps(bundle, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ProjectionError(
            "SensorThings projection bundle must contain only JSON-serializable "
            "dict/list/scalar values"
        ) from exc
    return bundle


def _project_env_payload(
    env_payload: dict[str, Any],
    *,
    device_id: str,
    site_id: str,
    device_meta: dict[str, Any] | None,
    result_time: str,
) -> dict[str, Any] | None:
    sample_type = env_payload.get("sample_type")
    if not isinstance(sample_type, str):
        return None
    sensor_channel = _sensor_channel_from_payload(env_payload)
    observed_property_meta = _observed_property_metadata(
        sample_type,
        device_meta=device_meta,
        sensor_channel=sensor_channel,
    )
    observed_property_key = observed_property_meta.get("key")
    if observed_property_key is None:
        return None

    value = env_payload.get("value")
    if isinstance(value, int | float):
        scalar_value = float(value)
        stream_key = "raw"
    else:
        mean_value = env_payload.get("mean")
        if not isinstance(mean_value, int | float):
            return None
        scalar_value = float(mean_value)
        stream_key = "summary"

    sensor_key = resolve_sensor_key(
        device_id,
        observed_property_key,
        device_meta=device_meta,
        sensor_channel=sensor_channel,
    )
    phenomenon_start = _normalize_time(
        env_payload.get("phenomenon_time_start"), fallback=result_time
    )
    phenomenon_end = _normalize_time(
        env_payload.get("phenomenon_time_end"), fallback=phenomenon_start
    )

    projection = _project_via_python(
        device_id=device_id,
        site_id=site_id,
        sensor_key=sensor_key,
        observed_property_key=observed_property_key,
        stream_key=stream_key,
        phenomenon_time_start=phenomenon_start,
        phenomenon_time_end=phenomenon_end,
        result_time=result_time,
        scalar_value=scalar_value,
    )

    projection["observed_property"] = {
        "id": _entity_id("observed-property", observed_property_key),
        "key": observed_property_key,
        "label": observed_property_meta["label"],
        "unit_of_measurement": {
            "symbol": observed_property_meta["unit"],
            "name": observed_property_meta["label"],
        },
    }
    return projection


def _observed_property_metadata(
    sample_type: str,
    *,
    device_meta: dict[str, Any] | None,
    sensor_channel: int | None,
) -> dict[str, str]:
    observed_property_key = SAMPLE_TYPE_TO_PROPERTY_KEY.get(sample_type)
    if observed_property_key is None and sample_type == "Custom":
        observed_property_key = _custom_observed_property_key(
            device_meta,
            sensor_channel=sensor_channel,
        )
    if observed_property_key is None:
        return {}

    metadata = _observed_property_metadata_from_device(
        device_meta,
        observed_property_key,
        sensor_channel=sensor_channel,
    )
    fallback = OBSERVED_PROPERTIES_BY_KEY.get(
        observed_property_key,
        {"key": observed_property_key, "label": observed_property_key, "unit": "1"},
    )
    return {
        "key": observed_property_key,
        "label": metadata.get("label") or fallback["label"],
        "unit": metadata.get("unit") or fallback["unit"],
    }


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
    native_projection = _project_via_native(
        device_id=device_id,
        site_id=site_id,
        sensor_key=sensor_key,
        observed_property_key=observed_property_key,
        stream_key=stream_key,
        phenomenon_time_start=phenomenon_time_start,
        phenomenon_time_end=phenomenon_time_end,
        result_time=result_time,
        scalar_value=scalar_value,
    )
    if native_projection is not None:
        return native_projection
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


def _project_via_native(
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
    if _native_sensorthings is None or not hasattr(
        _native_sensorthings, "project_observation"
    ):
        return None
    try:
        projection = _native_sensorthings.project_observation(
            {
                "pod_id": device_id,
                "site_id": site_id,
                "sensor_key": sensor_key,
                "observed_property_key": observed_property_key,
                "stream_key": stream_key,
                "phenomenon_time_start_rfc3339_utc": phenomenon_time_start,
                "phenomenon_time_end_rfc3339_utc": phenomenon_time_end,
                "result_time_rfc3339_utc": result_time,
                "result": scalar_value,
            }
        )
    except (RuntimeError, TypeError, ValueError) as exc:
        raise ProjectionError(
            "trackone_core native SensorThings helper failed during observation projection"
        ) from exc
    if not _is_json_object(projection):
        return None
    try:
        json.dumps(projection, allow_nan=False)
    except (TypeError, ValueError):
        return None
    return cast(dict[str, Any], projection)


def _is_json_object(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    return all(isinstance(key, str) for key in value)


def _payload_from_fact(fact: dict[str, Any]) -> dict[str, Any] | None:
    payload = fact.get("payload")
    if isinstance(payload, dict):
        if "Custom" in payload and isinstance(payload["Custom"], dict):
            return payload["Custom"]
        if "Env" in payload and isinstance(payload["Env"], dict):
            return payload["Env"]
        return payload
    return None


def _sensor_metadata_scopes(device_meta: dict[str, Any]) -> list[dict[str, Any]]:
    scopes = [device_meta]
    for key in SENSOR_METADATA_SCOPES:
        nested = device_meta.get(key)
        if isinstance(nested, dict):
            scopes.append(nested)
    return scopes


def _resolve_sensor_key_from_metadata(
    metadata: dict[str, Any],
    observed_property_key: str,
    *,
    sensor_channel: int | None,
) -> str | None:
    deployment_sensor_key = metadata.get("deployment_sensor_key")
    if isinstance(deployment_sensor_key, str) and deployment_sensor_key.strip():
        return deployment_sensor_key.strip()

    sensor_keys = metadata.get("sensor_keys")
    if isinstance(sensor_keys, dict):
        candidate = sensor_keys.get(observed_property_key)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()

    for sensor_key, sensor_meta in _iter_sensor_records(metadata.get("sensors")):
        if _sensor_record_matches(
            sensor_meta,
            sensor_key=sensor_key,
            observed_property_key=observed_property_key,
            sensor_channel=sensor_channel,
        ):
            return sensor_key

    for field_name in ("sensor_key", "sensor_id"):
        candidate = metadata.get(field_name)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()

    identity = _sensor_identity_from_metadata(metadata)
    if identity is None:
        return None
    return _derived_provisioned_sensor_key(
        identity,
        observed_property_key,
        sensor_channel=sensor_channel,
    )


def _iter_sensor_records(sensors: Any) -> Iterable[tuple[str, dict[str, Any]]]:
    if isinstance(sensors, dict):
        for sensor_key, sensor_meta in sensors.items():
            if (
                isinstance(sensor_key, str)
                and sensor_key.strip()
                and isinstance(sensor_meta, dict)
            ):
                yield sensor_key.strip(), sensor_meta
        return

    if isinstance(sensors, list):
        for sensor_meta in sensors:
            if not isinstance(sensor_meta, dict):
                continue
            sensor_key = sensor_meta.get("sensor_key") or sensor_meta.get("sensor_id")
            if isinstance(sensor_key, str) and sensor_key.strip():
                yield sensor_key.strip(), sensor_meta


def _sensor_record_matches(
    sensor_meta: dict[str, Any],
    *,
    sensor_key: str,
    observed_property_key: str,
    sensor_channel: int | None,
) -> bool:
    direct_property = sensor_meta.get("observed_property_key")
    if direct_property == observed_property_key:
        return True

    observed = sensor_meta.get("observed_property_keys")
    if isinstance(observed, list) and observed_property_key in observed:
        return True

    if sensor_channel is not None:
        for field_name in ("sensor_channel", "channel"):
            channel_value = sensor_meta.get(field_name)
            if isinstance(channel_value, int) and channel_value == sensor_channel:
                return True
        return False

    return bool(sensor_meta.get("default")) and bool(sensor_key)


def _custom_observed_property_key(
    device_meta: dict[str, Any] | None,
    *,
    sensor_channel: int | None,
) -> str | None:
    if not isinstance(device_meta, dict):
        return None
    for metadata_scope in _sensor_metadata_scopes(device_meta):
        for sensor_key, sensor_meta in _iter_sensor_records(
            metadata_scope.get("sensors")
        ):
            if sensor_channel is not None:
                channel_matches = False
                for field_name in ("sensor_channel", "channel"):
                    channel_value = sensor_meta.get(field_name)
                    if (
                        isinstance(channel_value, int)
                        and channel_value == sensor_channel
                    ):
                        channel_matches = True
                        break
                if not channel_matches:
                    continue
            elif not _sensor_record_matches(
                sensor_meta,
                sensor_key=sensor_key,
                observed_property_key="",
                sensor_channel=None,
            ):
                continue
            direct_property = sensor_meta.get("observed_property_key")
            if isinstance(direct_property, str) and direct_property.strip():
                return direct_property.strip()
            observed = sensor_meta.get("observed_property_keys")
            if isinstance(observed, list):
                for candidate in observed:
                    if isinstance(candidate, str) and candidate.strip():
                        return candidate.strip()
    return None


def _observed_property_metadata_from_device(
    device_meta: dict[str, Any] | None,
    observed_property_key: str,
    *,
    sensor_channel: int | None,
) -> dict[str, str]:
    if not isinstance(device_meta, dict):
        return {}

    for metadata_scope in _sensor_metadata_scopes(device_meta):
        observed_properties = metadata_scope.get("observed_properties")
        if isinstance(observed_properties, dict):
            candidate = observed_properties.get(observed_property_key)
            metadata = _property_metadata(candidate)
            if metadata:
                return metadata

        for sensor_key, sensor_meta in _iter_sensor_records(
            metadata_scope.get("sensors")
        ):
            if _sensor_record_matches(
                sensor_meta,
                sensor_key=sensor_key,
                observed_property_key=observed_property_key,
                sensor_channel=sensor_channel,
            ):
                metadata = _property_metadata(sensor_meta)
                if metadata:
                    return metadata

    return {}


def _property_metadata(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}

    label = value.get("observed_property_label") or value.get("label")
    unit = (
        value.get("unit_symbol")
        or value.get("unit")
        or value.get("unit_of_measurement_symbol")
    )
    result: dict[str, str] = {}
    if isinstance(label, str) and label.strip():
        result["label"] = label.strip()
    if isinstance(unit, str) and unit.strip():
        result["unit"] = unit.strip()
    return result


def _sensor_identity_from_metadata(metadata: dict[str, Any]) -> str | None:
    for field_name in ("provisioning_identity", *SENSOR_IDENTITY_FIELDS):
        candidate = metadata.get(field_name)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def _derived_provisioned_sensor_key(
    identity: str,
    observed_property_key: str,
    *,
    sensor_channel: int | None,
) -> str:
    fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    suffix = (
        f"ch{sensor_channel}"
        if isinstance(sensor_channel, int)
        else observed_property_key.replace("_", "-")
    )
    return f"prov-{fingerprint}-{suffix}"


def _device_id_from_fact(fact: dict[str, Any]) -> str:
    fact_ref = "fact"
    fc = fact.get("fc")
    ingest_time = fact.get("ingest_time")
    if isinstance(fc, int):
        fact_ref = f"fact fc={fc}"
    elif isinstance(ingest_time, int):
        fact_ref = f"fact ingest_time={ingest_time}"

    pod_id = fact.get("pod_id")
    if isinstance(pod_id, str):
        try:
            pod_value = int(pod_id, 16)
            return f"pod-{pod_value & 0xFFFF:03d}"
        except ValueError:
            raise ValueError(
                f"{fact_ref} has invalid canonical pod_id: {pod_id}"
            ) from None
    raise ValueError(f"{fact_ref} missing canonical pod_id")


def _result_time_from_fact(fact: dict[str, Any]) -> str:
    val = fact.get("ingest_time_rfc3339_utc")
    if isinstance(val, str) and val:
        return val
    ingest_time = fact.get("ingest_time")
    if isinstance(ingest_time, int):
        return (
            datetime.fromtimestamp(ingest_time, tz=UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_time(value: Any, *, fallback: str) -> str:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, int):
        return datetime.fromtimestamp(value, tz=UTC).isoformat().replace("+00:00", "Z")
    return fallback


def _sensor_channel_from_payload(payload: dict[str, Any]) -> int | None:
    value = payload.get("sensor_channel")
    return value if isinstance(value, int) else None


def _device_meta_from_table(
    fact: dict[str, Any], device_table: dict[str, Any]
) -> dict[str, Any] | None:
    device_id = _device_id_from_fact(fact)
    candidates: list[str] = [device_id]

    device_num = _device_num_from_id(device_id)
    if device_num is not None:
        candidates.insert(0, str(device_num))

    pod_id = fact.get("pod_id")
    if isinstance(pod_id, str) and pod_id:
        candidates.append(pod_id)

    for candidate in candidates:
        device_meta = device_table.get(candidate)
        if isinstance(device_meta, dict):
            return device_meta
    return None


def _projection_context_from_record(record: dict[str, Any]) -> dict[str, Any] | None:
    deployment = record.get("deployment")
    if not isinstance(deployment, dict):
        return None

    context: dict[str, Any] = {}
    deployment_sensor_key = deployment.get("deployment_sensor_key")
    if isinstance(deployment_sensor_key, str) and deployment_sensor_key.strip():
        context["deployment_sensor_key"] = deployment_sensor_key.strip()

    sensor_keys = deployment.get("sensor_keys")
    if isinstance(sensor_keys, dict):
        clean_sensor_keys = {
            str(k): str(v).strip()
            for k, v in sensor_keys.items()
            if isinstance(k, str) and isinstance(v, str) and v.strip()
        }
        if clean_sensor_keys:
            context["sensor_keys"] = clean_sensor_keys

    sensors = deployment.get("sensors")
    if isinstance(sensors, list | dict):
        context["sensors"] = sensors

    identity_pubkey = record.get("identity_pubkey")
    if isinstance(identity_pubkey, str) and identity_pubkey.strip():
        context["provisioning_identity"] = identity_pubkey.strip()

    return context if context else None


def _index_provisioning_records(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    records = bundle.get("records")
    if not isinstance(records, list):
        return indexed

    for record in records:
        if not isinstance(record, dict):
            continue
        pod_id = record.get("pod_id")
        if not isinstance(pod_id, str):
            continue
        context = _projection_context_from_record(record)
        if context is None:
            continue
        indexed[pod_id] = context
        try:
            value = int(pod_id, 16)
            indexed[str(value & 0xFFFF)] = context
            indexed[f"pod-{value & 0xFFFF:03d}"] = context
        except ValueError:
            continue
    return indexed


def _device_num_from_id(device_id: str) -> int | None:
    parts = device_id.rsplit("-", 1)
    if len(parts) != 2:
        return None
    try:
        return int(parts[1], 10)
    except ValueError:
        return None


__all__ = [
    "OBSERVED_PROPERTIES",
    "ProjectionError",
    "SAMPLE_TYPE_TO_PROPERTY_KEY",
    "SENSOR_IDENTITY_FIELDS",
    "SENSOR_METADATA_SCOPES",
    "SensorIdentityResolutionError",
    "entity_id",
    "build_bundle",
    "project_fact",
    "resolve_sensor_key",
]
