from __future__ import annotations

import importlib
import sys
from unittest.mock import MagicMock


def _clear_trackone_core_modules() -> None:
    for key in list(sys.modules):
        if key.startswith("trackone_core"):
            sys.modules.pop(key, None)


def test_build_bundle_falls_back_when_native_projection_is_mock(
    monkeypatch,
) -> None:
    native = MagicMock()
    native.__name__ = "trackone_core._native"
    native.__version__ = "0.1.0-test"
    native.__package__ = "trackone_core"
    native.sensorthings = MagicMock(name="sensorthings")

    _clear_trackone_core_modules()
    monkeypatch.setitem(sys.modules, "trackone_core._native", native)

    try:
        module = importlib.import_module("trackone_core.sensorthings")
        fact = {
            "pod_id": "0000000000000003",
            "fc": 1,
            "ingest_time": 1_772_755_501,
            "ingest_time_rfc3339_utc": "2026-03-06T00:05:01Z",
            "pod_time": None,
            "kind": "custom.raw",
            "payload": {"temp_c": 23.5},
        }
        provisioning_records = {
            "version": 1,
            "records": [
                {
                    "pod_id": "0000000000000003",
                    "identity_pubkey": "b" * 64,
                    "deployment": {
                        "sensor_keys": {
                            "temperature_air": "shtc3-ambient",
                        }
                    },
                }
            ],
        }

        bundle = module.build_bundle(
            [fact],
            site_id="an-001",
            provisioning_records=provisioning_records,
        )
    finally:
        _clear_trackone_core_modules()

    assert isinstance(bundle["things"][0], dict)
    assert bundle["things"][0]["pod_id"] == "pod-003"
    assert bundle["datastreams"][0]["sensor_id"] == module.entity_id(
        "sensor", "pod-003", "shtc3-ambient"
    )
    assert (
        bundle["observations"][0]["phenomenon_time"]["start_rfc3339_utc"]
        == "2026-03-06T00:05:01Z"
    )


def test_build_bundle_uses_native_projection_when_available(monkeypatch) -> None:
    native = MagicMock()
    native.__name__ = "trackone_core._native"
    native.__version__ = "0.1.0-test"
    native.__package__ = "trackone_core"
    native.sensorthings = MagicMock(name="sensorthings")
    native.sensorthings.entity_id.side_effect = lambda kind, *components: (
        "native:" + kind + ":" + "|".join(components)
    )
    native.sensorthings.project_observation.return_value = {
        "ids": {
            "thing_id": "native-thing",
            "sensor_id": "native-sensor",
            "observed_property_id": "native-property",
            "datastream_id": "native-datastream",
            "observation_id": "native-observation",
        },
        "thing": {
            "id": "native-thing",
            "pod_id": "pod-003",
            "site_id": "an-001",
        },
        "datastream": {
            "id": "native-datastream",
            "thing_id": "native-thing",
            "sensor_id": "native-sensor",
            "observed_property_id": "native-property",
            "stream_key": "raw",
        },
        "observation": {
            "id": "native-observation",
            "datastream_id": "native-datastream",
            "phenomenon_time": {
                "start_rfc3339_utc": "2026-03-06T00:05:01Z",
                "end_rfc3339_utc": "2026-03-06T00:05:01Z",
            },
            "result_time_rfc3339_utc": "2026-03-06T00:05:01Z",
            "result": 23.5,
        },
    }

    _clear_trackone_core_modules()
    monkeypatch.setitem(sys.modules, "trackone_core._native", native)

    try:
        module = importlib.import_module("trackone_core.sensorthings")
        fact = {
            "pod_id": "0000000000000003",
            "fc": 1,
            "ingest_time": 1_772_755_501,
            "ingest_time_rfc3339_utc": "2026-03-06T00:05:01Z",
            "pod_time": None,
            "kind": "custom.raw",
            "payload": {"temp_c": 23.5},
        }
        provisioning_records = {
            "version": 1,
            "records": [
                {
                    "pod_id": "0000000000000003",
                    "identity_pubkey": "b" * 64,
                    "deployment": {
                        "sensor_keys": {
                            "temperature_air": "shtc3-ambient",
                        }
                    },
                }
            ],
        }

        bundle = module.build_bundle(
            [fact],
            site_id="an-001",
            provisioning_records=provisioning_records,
        )
    finally:
        _clear_trackone_core_modules()

    native.sensorthings.project_observation.assert_called_once()
    assert bundle["things"][0]["id"] == "native-thing"
    assert bundle["datastreams"][0]["id"] == "native-datastream"
    assert bundle["observations"][0]["id"] == "native-observation"
