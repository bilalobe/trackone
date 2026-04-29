use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyList, PyModule, PyTuple};
use serde_json::{Map, Number, Value};
use trackone_sensorthings::{
    EnvObservationProjection, EnvObservationProjectionInput, ObservationPayload, ObservationResult,
    SensorThingsEntityKind, entity_id as native_entity_id, project_env_observation,
};

fn to_py_err<E: core::fmt::Display>(err: E) -> PyErr {
    PyValueError::new_err(err.to_string())
}

fn parse_entity_kind(kind: &str) -> Result<SensorThingsEntityKind, &'static str> {
    match kind {
        "thing" => Ok(SensorThingsEntityKind::Thing),
        "sensor" => Ok(SensorThingsEntityKind::Sensor),
        "observed-property" => Ok(SensorThingsEntityKind::ObservedProperty),
        "datastream" => Ok(SensorThingsEntityKind::Datastream),
        "observation" => Ok(SensorThingsEntityKind::Observation),
        "location" => Ok(SensorThingsEntityKind::Location),
        _ => Err("invalid SensorThings entity kind"),
    }
}

fn py_to_json_array<'py>(items: impl IntoIterator<Item = Bound<'py, PyAny>>) -> PyResult<Value> {
    items
        .into_iter()
        .map(|item| py_to_json_value(&item))
        .collect::<PyResult<Vec<_>>>()
        .map(Value::Array)
}

fn py_to_json_value(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    if value.is_none() {
        return Ok(Value::Null);
    }
    if value.cast::<PyBool>().is_ok() {
        return Ok(Value::Bool(value.extract::<bool>()?));
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        let mut out = Map::new();
        for (key, item) in dict.iter() {
            let key: String = key.extract().map_err(|_| {
                PyValueError::new_err("SensorThings structured values require string keys")
            })?;
            out.insert(key, py_to_json_value(&item)?);
        }
        return Ok(Value::Object(out));
    }
    // Handle str explicitly before any iterable check: Python strings are iterable and
    // try_iter() would otherwise convert them to arrays of single characters.
    if let Ok(s) = value.extract::<String>() {
        return Ok(Value::String(s));
    }
    // Use concrete sequence types instead of a generic try_iter() to avoid
    // accidentally treating other iterable objects (e.g. generators) as arrays.
    if let Ok(list) = value.cast::<PyList>() {
        return py_to_json_array(list.iter());
    }
    if let Ok(tuple) = value.cast::<PyTuple>() {
        return py_to_json_array(tuple.iter());
    }
    if let Ok(i) = value.extract::<i64>() {
        return Ok(Value::Number(Number::from(i)));
    }
    if let Ok(u) = value.extract::<u64>() {
        return Ok(Value::Number(Number::from(u)));
    }
    if let Ok(f) = value.extract::<f64>() {
        let number = Number::from_f64(f)
            .ok_or_else(|| PyValueError::new_err("non-finite float not allowed"))?;
        return Ok(Value::Number(number));
    }
    Err(PyValueError::new_err(
        "unsupported structured SensorThings result value",
    ))
}

fn json_to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    let json = PyModule::import(py, "json")?;
    let loads = json.getattr("loads")?;
    let serialized = serde_json::to_string(value).expect("serde_json::Value should serialize");
    Ok(loads.call1((serialized,))?.unbind())
}

fn projection_to_dict(
    py: Python<'_>,
    projection: &EnvObservationProjection,
) -> PyResult<Py<PyDict>> {
    let ids = PyDict::new(py);
    ids.set_item("thing_id", &projection.ids.thing_id)?;
    ids.set_item("sensor_id", &projection.ids.sensor_id)?;
    ids.set_item("observed_property_id", &projection.ids.observed_property_id)?;
    ids.set_item("datastream_id", &projection.ids.datastream_id)?;
    ids.set_item("observation_id", &projection.ids.observation_id)?;

    let thing = PyDict::new(py);
    thing.set_item("id", &projection.thing.id)?;
    thing.set_item("pod_id", &projection.thing.pod_id)?;
    thing.set_item("site_id", &projection.thing.site_id)?;

    let datastream = PyDict::new(py);
    datastream.set_item("id", &projection.datastream.id)?;
    datastream.set_item("thing_id", &projection.datastream.thing_id)?;
    datastream.set_item("sensor_id", &projection.datastream.sensor_id)?;
    datastream.set_item(
        "observed_property_id",
        &projection.datastream.observed_property_id,
    )?;
    datastream.set_item("stream_key", &projection.datastream.stream_key)?;

    let phenomenon_time = PyDict::new(py);
    phenomenon_time.set_item(
        "start_rfc3339_utc",
        &projection.observation.phenomenon_time.start_rfc3339_utc,
    )?;
    phenomenon_time.set_item(
        "end_rfc3339_utc",
        &projection.observation.phenomenon_time.end_rfc3339_utc,
    )?;

    let observation = PyDict::new(py);
    observation.set_item("id", &projection.observation.id)?;
    observation.set_item("datastream_id", &projection.observation.datastream_id)?;
    observation.set_item("phenomenon_time", phenomenon_time)?;
    observation.set_item(
        "result_time_rfc3339_utc",
        &projection.observation.result_time_rfc3339_utc,
    )?;
    match &projection.observation.result {
        ObservationPayload::Scalar(value) => observation.set_item("result", *value)?,
        ObservationPayload::Structured(value) => {
            observation.set_item("result", json_to_py(py, value)?)?
        }
    }

    let out = PyDict::new(py);
    out.set_item("ids", ids)?;
    out.set_item("thing", thing)?;
    out.set_item("datastream", datastream)?;
    out.set_item("observation", observation)?;
    Ok(out.unbind())
}

fn extract_required_string(input: &Bound<'_, PyDict>, key: &'static str) -> PyResult<String> {
    input
        .get_item(key)?
        .ok_or_else(|| PyValueError::new_err(format!("missing required field: {key}")))?
        .extract::<String>()
        .map_err(|_| PyValueError::new_err(format!("invalid string field: {key}")))
}

#[pyfunction]
#[pyo3(signature = (kind, *components))]
fn entity_id(kind: &str, components: &Bound<'_, PyTuple>) -> PyResult<String> {
    let kind = parse_entity_kind(kind).map_err(to_py_err)?;
    let components: Vec<String> = components
        .iter()
        .map(|component| {
            component.extract::<String>().map_err(|_| {
                PyValueError::new_err("SensorThings entity_id components must be strings")
            })
        })
        .collect::<Result<_, _>>()?;
    let component_refs: Vec<&str> = components.iter().map(String::as_str).collect();
    Ok(native_entity_id(kind, &component_refs))
}

#[pyfunction]
fn project_observation(input: &Bound<'_, PyDict>) -> PyResult<Py<PyDict>> {
    let py = input.py();
    let result_value = input
        .get_item("result")?
        .ok_or_else(|| PyValueError::new_err("missing required field: result"))?;
    let result = match result_value.extract::<f64>() {
        Ok(value) => ObservationResult::Scalar(value),
        Err(_) => ObservationResult::Structured(py_to_json_value(&result_value)?),
    };
    let input = EnvObservationProjectionInput {
        pod_id: extract_required_string(input, "pod_id")?,
        site_id: input
            .get_item("site_id")?
            .map(|value| {
                value
                    .extract::<Option<String>>()
                    .map_err(|_| PyValueError::new_err("invalid string field: site_id"))
            })
            .transpose()?
            .flatten(),
        sensor_key: extract_required_string(input, "sensor_key")?,
        observed_property_key: extract_required_string(input, "observed_property_key")?,
        stream_key: extract_required_string(input, "stream_key")?,
        phenomenon_time_start_rfc3339_utc: extract_required_string(
            input,
            "phenomenon_time_start_rfc3339_utc",
        )?,
        phenomenon_time_end_rfc3339_utc: extract_required_string(
            input,
            "phenomenon_time_end_rfc3339_utc",
        )?,
        result_time_rfc3339_utc: extract_required_string(input, "result_time_rfc3339_utc")?,
        result,
    };
    let projection = project_env_observation(&input).map_err(to_py_err)?;
    projection_to_dict(py, &projection)
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(parent.py(), "sensorthings")?;
    sub.add_function(wrap_pyfunction!(entity_id, &sub)?)?;
    sub.add_function(wrap_pyfunction!(project_observation, &sub)?)?;
    parent.add_submodule(&sub)?;
    Ok(())
}
