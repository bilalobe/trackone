use base64::{Engine as _, engine::general_purpose::STANDARD};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyList};
use serde_json::{Map, Value, json};
use trackone_core::{Fact, FactKind, FactPayload, SampleType};
use trackone_ingest::{
    self, DeviceMaterial as IngestDeviceMaterial, FixtureError, FrameHeader, FrameInput,
    RejectReason, ReplayWindow,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedFrame {
    header: FrameHeader,
    nonce: Vec<u8>,
    ct: Vec<u8>,
    tag: Vec<u8>,
}

impl ParsedFrame {
    fn as_ingest(&self) -> FrameInput<'_> {
        FrameInput {
            header: self.header,
            nonce: &self.nonce,
            ct: &self.ct,
            tag: &self.tag,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DeviceMaterial {
    salt8: Vec<u8>,
    ck_up: Vec<u8>,
}

impl DeviceMaterial {
    fn as_ingest(&self) -> IngestDeviceMaterial<'_> {
        IngestDeviceMaterial {
            salt8: &self.salt8,
            ck_up: &self.ck_up,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct DecryptedFact {
    pod_id_hex: String,
    fc: u64,
    kind: String,
    payload: Map<String, Value>,
    pod_time: Option<i64>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum PyRejectReason {
    MissingFrameFields,
    InvalidHdr,
    InvalidHdrTypes,
    InvalidFrameTypes,
    InvalidBase64,
    UnknownDevice,
    MissingSalt8,
    Ingest(RejectReason),
}

impl PyRejectReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::MissingFrameFields => "missing_frame_fields",
            Self::InvalidHdr => "invalid_hdr",
            Self::InvalidHdrTypes => "invalid_hdr_types",
            Self::InvalidFrameTypes => "invalid_frame_types",
            Self::InvalidBase64 => "invalid_base64",
            Self::UnknownDevice => "unknown_device",
            Self::MissingSalt8 => "missing_salt8",
            Self::Ingest(reason) => reason.as_str(),
        }
    }
}

impl From<RejectReason> for PyRejectReason {
    fn from(reason: RejectReason) -> Self {
        Self::Ingest(reason)
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayWindowState {
    inner: ReplayWindow,
}

#[pymethods]
impl ReplayWindowState {
    #[new]
    #[pyo3(signature = (window_size=64, highest_fc_seen=None))]
    fn new(window_size: u64, highest_fc_seen: Option<u64>) -> Self {
        Self {
            inner: ReplayWindow::new(window_size, highest_fc_seen),
        }
    }

    #[getter]
    fn window_size(&self) -> u64 {
        self.inner.window_size()
    }

    #[getter]
    fn highest_fc_seen(&self) -> Option<u64> {
        self.inner.highest_fc_seen()
    }

    fn seen_fcs(&self) -> Vec<u64> {
        self.inner.seen_fcs()
    }
}

impl ReplayWindowState {
    fn check_and_update(&mut self, fc: u64) -> Result<(), RejectReason> {
        self.inner.check_and_update(fc)
    }
}

fn get_required<'py>(
    dict: &Bound<'py, PyDict>,
    key: &str,
    missing: PyRejectReason,
) -> Result<Bound<'py, PyAny>, PyRejectReason> {
    dict.get_item(key).map_err(|_| missing)?.ok_or(missing)
}

fn extract_non_bool_u64(
    dict: &Bound<'_, PyDict>,
    key: &str,
    missing: PyRejectReason,
    invalid: PyRejectReason,
) -> Result<u64, PyRejectReason> {
    let value = get_required(dict, key, missing)?;
    if value.is_instance_of::<PyBool>() {
        return Err(invalid);
    }
    value.extract::<u64>().map_err(|_| invalid)
}

fn extract_string(
    dict: &Bound<'_, PyDict>,
    key: &str,
    missing: PyRejectReason,
    invalid: PyRejectReason,
) -> Result<String, PyRejectReason> {
    get_required(dict, key, missing)?
        .extract::<String>()
        .map_err(|_| invalid)
}

fn extract_b64(
    dict: &Bound<'_, PyDict>,
    key: &str,
    missing: PyRejectReason,
    invalid: PyRejectReason,
) -> Result<Vec<u8>, PyRejectReason> {
    let raw = extract_string(dict, key, missing, invalid)?;
    STANDARD
        .decode(raw.as_bytes())
        .map_err(|_| PyRejectReason::InvalidBase64)
}

fn extract_frame_fields(frame: &Bound<'_, PyAny>) -> Result<ParsedFrame, PyRejectReason> {
    let frame_dict = frame
        .cast::<PyDict>()
        .map_err(|_| PyRejectReason::MissingFrameFields)?;
    let hdr_obj = get_required(frame_dict, "hdr", PyRejectReason::MissingFrameFields)?;
    let hdr = hdr_obj
        .cast::<PyDict>()
        .map_err(|_| PyRejectReason::InvalidHdr)?;

    let dev_id = u16::try_from(extract_non_bool_u64(
        hdr,
        "dev_id",
        PyRejectReason::InvalidHdrTypes,
        PyRejectReason::InvalidHdrTypes,
    )?)
    .map_err(|_| PyRejectReason::InvalidHdrTypes)?;
    let msg_type = u8::try_from(extract_non_bool_u64(
        hdr,
        "msg_type",
        PyRejectReason::InvalidHdrTypes,
        PyRejectReason::InvalidHdrTypes,
    )?)
    .map_err(|_| PyRejectReason::InvalidHdrTypes)?;
    let fc = u32::try_from(extract_non_bool_u64(
        hdr,
        "fc",
        PyRejectReason::InvalidHdrTypes,
        PyRejectReason::InvalidHdrTypes,
    )?)
    .map_err(|_| PyRejectReason::InvalidHdrTypes)?;
    let flags = u8::try_from(extract_non_bool_u64(
        hdr,
        "flags",
        PyRejectReason::InvalidHdrTypes,
        PyRejectReason::InvalidHdrTypes,
    )?)
    .map_err(|_| PyRejectReason::InvalidHdrTypes)?;

    Ok(ParsedFrame {
        header: FrameHeader {
            dev_id,
            msg_type,
            fc,
            flags,
        },
        nonce: extract_b64(
            frame_dict,
            "nonce",
            PyRejectReason::MissingFrameFields,
            PyRejectReason::InvalidFrameTypes,
        )?,
        ct: extract_b64(
            frame_dict,
            "ct",
            PyRejectReason::MissingFrameFields,
            PyRejectReason::InvalidFrameTypes,
        )?,
        tag: extract_b64(
            frame_dict,
            "tag",
            PyRejectReason::MissingFrameFields,
            PyRejectReason::InvalidFrameTypes,
        )?,
    })
}

fn extract_device_material(
    device_entry: &Bound<'_, PyAny>,
) -> Result<DeviceMaterial, PyRejectReason> {
    let entry_dict = device_entry
        .cast::<PyDict>()
        .map_err(|_| PyRejectReason::UnknownDevice)?;
    Ok(DeviceMaterial {
        salt8: extract_b64(
            entry_dict,
            "salt8",
            PyRejectReason::MissingSalt8,
            PyRejectReason::InvalidBase64,
        )?,
        ck_up: extract_b64(
            entry_dict,
            "ck_up",
            PyRejectReason::UnknownDevice,
            PyRejectReason::InvalidBase64,
        )?,
    })
}

fn extract_frame_and_device(
    frame: &Bound<'_, PyAny>,
    device_entry: &Bound<'_, PyAny>,
) -> Result<(ParsedFrame, DeviceMaterial), PyRejectReason> {
    Ok((
        extract_frame_fields(frame)?,
        extract_device_material(device_entry)?,
    ))
}

fn decrypt_framed_from_py(
    frame: &Bound<'_, PyAny>,
    device_entry: &Bound<'_, PyAny>,
    ingest_profile: Option<&str>,
) -> Result<(ParsedFrame, DecryptedFact), PyRejectReason> {
    trackone_ingest::validate_ingest_profile(ingest_profile)?;
    let (frame_fields, device_material) = extract_frame_and_device(frame, device_entry)?;
    let accepted = trackone_ingest::validate_and_decrypt(
        frame_fields.as_ingest(),
        device_material.as_ingest(),
    )?;
    let fact_fields = decrypted_fact_from_core(&accepted.fact)?;
    Ok((frame_fields, fact_fields))
}

fn kind_label(kind: FactKind) -> &'static str {
    match kind {
        FactKind::Env => "Env",
        FactKind::Pipeline => "Pipeline",
        FactKind::Health => "Health",
        FactKind::Custom => "Custom",
    }
}

fn sample_type_label(sample_type: SampleType) -> &'static str {
    match sample_type {
        SampleType::AmbientAirTemperature => "AmbientAirTemperature",
        SampleType::AmbientRelativeHumidity => "AmbientRelativeHumidity",
        SampleType::InterfaceTemperature => "InterfaceTemperature",
        SampleType::CoverageCapacitance => "CoverageCapacitance",
        SampleType::BioImpedanceMagnitude => "BioImpedanceMagnitude",
        SampleType::BioImpedanceActivity => "BioImpedanceActivity",
        SampleType::SupplyVoltage => "SupplyVoltage",
        SampleType::BatterySoc => "BatterySoc",
        SampleType::FloodContact => "FloodContact",
        SampleType::LinkQuality => "LinkQuality",
        SampleType::WaterLevel => "WaterLevel",
        SampleType::WaterFlowRate => "WaterFlowRate",
        SampleType::WaterVolume => "WaterVolume",
        SampleType::WaterPressure => "WaterPressure",
        SampleType::WaterTemperature => "WaterTemperature",
        SampleType::WaterElectricalConductivity => "WaterElectricalConductivity",
        SampleType::WaterPh => "WaterPh",
        SampleType::WaterDissolvedOxygen => "WaterDissolvedOxygen",
        SampleType::WaterTurbidity => "WaterTurbidity",
        SampleType::WaterSalinity => "WaterSalinity",
        SampleType::WaterTotalDissolvedSolids => "WaterTotalDissolvedSolids",
        SampleType::Rainfall => "Rainfall",
        SampleType::RainIntensity => "RainIntensity",
        SampleType::WindSpeed => "WindSpeed",
        SampleType::WindDirection => "WindDirection",
        SampleType::BarometricPressure => "BarometricPressure",
        SampleType::SolarIrradiance => "SolarIrradiance",
        SampleType::SoilMoisture => "SoilMoisture",
        SampleType::SoilTemperature => "SoilTemperature",
        SampleType::SoilElectricalConductivity => "SoilElectricalConductivity",
        SampleType::VibrationRms => "VibrationRms",
        SampleType::VibrationPeak => "VibrationPeak",
        SampleType::ShockAcceleration => "ShockAcceleration",
        SampleType::InclinationAngle => "InclinationAngle",
        SampleType::Displacement => "Displacement",
        SampleType::Strain => "Strain",
        SampleType::CrackWidth => "CrackWidth",
        SampleType::AcousticNoise => "AcousticNoise",
        SampleType::AirQualityPm25 => "AirQualityPm25",
        SampleType::AirQualityPm10 => "AirQualityPm10",
        SampleType::CarbonDioxide => "CarbonDioxide",
        SampleType::VolatileOrganicCompounds => "VolatileOrganicCompounds",
        SampleType::BatteryVoltage => "BatteryVoltage",
        SampleType::BatteryCurrent => "BatteryCurrent",
        SampleType::BatteryTemperature => "BatteryTemperature",
        SampleType::SolarChargeCurrent => "SolarChargeCurrent",
        SampleType::EnclosureHumidity => "EnclosureHumidity",
        SampleType::EnclosureTemperature => "EnclosureTemperature",
        SampleType::RadioRssi => "RadioRssi",
        SampleType::RadioSnr => "RadioSnr",
        SampleType::Custom => "Custom",
    }
}

fn payload_map_from_fact_payload(
    payload: &FactPayload,
) -> Result<Map<String, Value>, PyRejectReason> {
    match payload {
        FactPayload::Env(env) => {
            let mut env_value = serde_json::to_value(env)
                .map_err(|_| PyRejectReason::Ingest(RejectReason::DecryptFailed))?;
            let env_obj = env_value
                .as_object_mut()
                .ok_or(PyRejectReason::Ingest(RejectReason::DecryptFailed))?;
            env_obj.insert(
                "sample_type".to_string(),
                json!(sample_type_label(env.sample_type)),
            );

            let mut out = Map::new();
            out.insert("Env".to_string(), env_value);
            Ok(out)
        }
        FactPayload::Custom(_) => {
            let value = serde_json::to_value(payload)
                .map_err(|_| PyRejectReason::Ingest(RejectReason::DecryptFailed))?;
            value
                .as_object()
                .cloned()
                .ok_or(PyRejectReason::Ingest(RejectReason::DecryptFailed))
        }
    }
}

fn decrypted_fact_from_core(fact: &Fact) -> Result<DecryptedFact, PyRejectReason> {
    Ok(DecryptedFact {
        pod_id_hex: format!("{:016x}", u64::from_be_bytes(fact.pod_id.0)),
        fc: fact.fc,
        kind: kind_label(fact.kind).to_string(),
        payload: payload_map_from_fact_payload(&fact.payload)?,
        pod_time: fact.pod_time,
    })
}

fn py_value(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(value) => Ok(PyBool::new(py, *value).to_owned().unbind().into_any()),
        Value::Number(number) if number.is_u64() => Ok(number
            .as_u64()
            .expect("u64 payload")
            .into_pyobject(py)?
            .unbind()
            .into_any()),
        Value::Number(number) if number.is_i64() => Ok(number
            .as_i64()
            .expect("i64 payload")
            .into_pyobject(py)?
            .unbind()
            .into_any()),
        Value::Number(number) => Ok(number
            .as_f64()
            .expect("f64 payload")
            .into_pyobject(py)?
            .unbind()
            .into_any()),
        Value::String(value) => Ok(value.into_pyobject(py)?.unbind().into_any()),
        Value::Array(values) => {
            let items = values
                .iter()
                .map(|item| py_value(py, item))
                .collect::<PyResult<Vec<_>>>()?;
            Ok(PyList::new(py, items)?.unbind().into_any())
        }
        Value::Object(map) => Ok(py_payload_dict(py, map.clone())?.into_any()),
    }
}

fn py_payload_dict(py: Python<'_>, payload: Map<String, Value>) -> PyResult<Py<PyDict>> {
    let payload_dict = PyDict::new(py);
    for (key, value) in payload {
        payload_dict.set_item(key, py_value(py, &value)?)?;
    }
    Ok(payload_dict.unbind())
}

fn build_fact_dict(
    py: Python<'_>,
    fact_fields: &DecryptedFact,
    ingest_time: i64,
    ingest_time_rfc3339_utc: &str,
) -> PyResult<Py<PyDict>> {
    let fact = PyDict::new(py);
    fact.set_item("pod_id", &fact_fields.pod_id_hex)?;
    fact.set_item("fc", fact_fields.fc)?;
    fact.set_item("ingest_time", ingest_time)?;
    match fact_fields.pod_time {
        Some(value) => fact.set_item("pod_time", value)?,
        None => fact.set_item("pod_time", py.None())?,
    }
    fact.set_item("kind", &fact_fields.kind)?;
    fact.set_item("payload", py_payload_dict(py, fact_fields.payload.clone())?)?;
    fact.set_item("ingest_time_rfc3339_utc", ingest_time_rfc3339_utc)?;
    Ok(fact.unbind())
}

fn map_fixture_error(error: FixtureError) -> PyErr {
    match error {
        FixtureError::Reject(reason) => PyValueError::new_err(reason.as_str()),
        FixtureError::EncodeFailed => PyRuntimeError::new_err("failed to encode postcard fact"),
        FixtureError::EncryptFailed => PyRuntimeError::new_err("failed to encrypt framed fixture"),
    }
}

type AdmitFramedFactResult = PyResult<(Option<Py<PyDict>>, Option<String>, Option<String>)>;

#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pyfunction]
#[pyo3(signature = (dev_id, fc, device_entry, *, msg_type=1, flags=0, pod_time=None))]
fn emit_rust_postcard_framed_fixture(
    py: Python<'_>,
    dev_id: u16,
    fc: u32,
    device_entry: &Bound<'_, PyAny>,
    msg_type: u8,
    flags: u8,
    pod_time: Option<i64>,
) -> PyResult<Py<PyDict>> {
    let device_material = extract_device_material(device_entry)
        .map_err(|reason| PyValueError::new_err(reason.as_str()))?;
    let fixture = trackone_ingest::emit_fixture(
        dev_id,
        fc,
        device_material.as_ingest(),
        msg_type,
        flags,
        pod_time,
    )
    .map_err(map_fixture_error)?;

    let hdr = PyDict::new(py);
    hdr.set_item("dev_id", fixture.dev_id)?;
    hdr.set_item("msg_type", fixture.msg_type)?;
    hdr.set_item("fc", fixture.fc)?;
    hdr.set_item("flags", fixture.flags)?;

    let frame = PyDict::new(py);
    frame.set_item("hdr", hdr)?;
    frame.set_item("nonce", STANDARD.encode(fixture.nonce))?;
    frame.set_item("ct", STANDARD.encode(fixture.ct))?;
    frame.set_item("tag", STANDARD.encode(fixture.tag))?;
    Ok(frame.unbind())
}

#[pyfunction]
#[pyo3(signature = (frame, device_entry, *, ingest_profile=None))]
fn validate_and_decrypt_framed(
    py: Python<'_>,
    frame: &Bound<'_, PyAny>,
    device_entry: &Bound<'_, PyAny>,
    ingest_profile: Option<String>,
) -> PyResult<(Option<Py<PyDict>>, Option<String>)> {
    let (_, fact_fields) =
        match decrypt_framed_from_py(frame, device_entry, ingest_profile.as_deref()) {
            Ok(value) => value,
            Err(reason) => return Ok((None, Some(reason.as_str().to_string()))),
        };

    Ok((Some(py_payload_dict(py, fact_fields.payload)?), None))
}

#[pyfunction]
#[pyo3(signature = (frame, device_entry, state, *, ingest_time, ingest_time_rfc3339_utc, pod_time=None, ingest_profile=None))]
fn admit_framed_fact(
    frame: &Bound<'_, PyAny>,
    device_entry: &Bound<'_, PyAny>,
    mut state: PyRefMut<'_, ReplayWindowState>,
    ingest_time: i64,
    ingest_time_rfc3339_utc: &str,
    pod_time: Option<i64>,
    ingest_profile: Option<String>,
) -> AdmitFramedFactResult {
    let py = frame.py();
    let (frame_fields, mut fact_fields) =
        match decrypt_framed_from_py(frame, device_entry, ingest_profile.as_deref()) {
            Ok(value) => value,
            Err(reason) => {
                return Ok((
                    None,
                    Some(reason.as_str().to_string()),
                    Some("decrypt".to_string()),
                ));
            }
        };

    if let Err(reason) = state.check_and_update(u64::from(frame_fields.header.fc)) {
        return Ok((
            None,
            Some(reason.as_str().to_string()),
            Some("replay".to_string()),
        ));
    }

    if fact_fields.pod_time.is_none() {
        fact_fields.pod_time = pod_time;
    }

    Ok((
        Some(build_fact_dict(
            py,
            &fact_fields,
            ingest_time,
            ingest_time_rfc3339_utc,
        )?),
        None,
        None,
    ))
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(parent.py(), "crypto")?;
    sub.add_class::<ReplayWindowState>()?;
    sub.add_function(wrap_pyfunction!(version, &sub)?)?;
    sub.add_function(wrap_pyfunction!(emit_rust_postcard_framed_fixture, &sub)?)?;
    sub.add_function(wrap_pyfunction!(validate_and_decrypt_framed, &sub)?)?;
    sub.add_function(wrap_pyfunction!(admit_framed_fact, &sub)?)?;
    parent.add_submodule(&sub)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_state_accepts_and_prunes() {
        let mut state = ReplayWindowState::new(3, Some(1));

        state.check_and_update(2).expect("fc=2 should be accepted");
        state.check_and_update(3).expect("fc=3 should be accepted");
        state.check_and_update(4).expect("fc=4 should be accepted");
        state.check_and_update(5).expect("fc=5 should be accepted");

        assert_eq!(state.highest_fc_seen(), Some(5));
        assert_eq!(state.seen_fcs(), vec![2, 3, 4, 5]);
    }

    #[test]
    fn replay_window_state_rejects_duplicates_and_out_of_window() {
        let mut state = ReplayWindowState::new(4, Some(10));

        state
            .check_and_update(10)
            .expect("first session observation");

        let duplicate = state.check_and_update(10).unwrap_err();
        assert_eq!(duplicate, RejectReason::Duplicate);

        let too_old = state.check_and_update(5).unwrap_err();
        assert_eq!(too_old, RejectReason::OutOfWindow);

        let too_new = state.check_and_update(20).unwrap_err();
        assert_eq!(too_new, RejectReason::OutOfWindow);
    }

    #[test]
    fn labels_water_level_sample_type() {
        assert_eq!(sample_type_label(SampleType::WaterLevel), "WaterLevel");
    }
}
