//! PyO3-only wrappers around the reusable trackone-ots library.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::path::Path;
use std::time::Duration;

#[pyclass(eq, eq_int, skip_from_py_object)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OtsStatus {
    Verified,
    Pending,
    Failed,
    Missing,
    Skipped,
}

impl OtsStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Pending => "pending",
            Self::Failed => "failed",
            Self::Missing => "missing",
            Self::Skipped => "skipped",
        }
    }
}

impl From<trackone_ots::OtsStatus> for OtsStatus {
    fn from(status: trackone_ots::OtsStatus) -> Self {
        match status {
            trackone_ots::OtsStatus::Verified => Self::Verified,
            trackone_ots::OtsStatus::Pending => Self::Pending,
            trackone_ots::OtsStatus::Failed => Self::Failed,
            trackone_ots::OtsStatus::Missing => Self::Missing,
            trackone_ots::OtsStatus::Skipped => Self::Skipped,
        }
    }
}

#[pymethods]
impl OtsStatus {
    #[getter]
    fn value(&self) -> &'static str {
        self.as_str()
    }

    fn __str__(&self) -> &'static str {
        self.as_str()
    }

    fn __repr__(&self) -> String {
        format!("OtsStatus('{}')", self.as_str())
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone, Debug)]
struct OtsVerifyResult {
    ok: bool,
    status: OtsStatus,
    reason: String,
    bitcoin_attestation_heights: Vec<u64>,
}

impl From<trackone_ots::OtsVerifyResult> for OtsVerifyResult {
    fn from(result: trackone_ots::OtsVerifyResult) -> Self {
        Self {
            ok: result.ok,
            status: result.status.into(),
            reason: result.reason,
            bitcoin_attestation_heights: result.bitcoin_attestation_heights,
        }
    }
}

#[pymethods]
impl OtsVerifyResult {
    #[getter]
    fn ok(&self) -> bool {
        self.ok
    }

    #[getter]
    fn status(&self) -> OtsStatus {
        self.status
    }

    #[getter]
    fn status_name(&self) -> &'static str {
        self.status.as_str()
    }

    #[getter]
    fn reason(&self) -> String {
        self.reason.clone()
    }

    #[getter]
    fn bitcoin_attestation_heights(&self) -> Vec<u64> {
        self.bitcoin_attestation_heights.clone()
    }

    fn __bool__(&self) -> bool {
        self.ok
    }

    fn __repr__(&self) -> String {
        format!(
            "OtsVerifyResult(ok={}, status='{}', reason='{}')",
            self.ok,
            self.status.as_str(),
            self.reason
        )
    }
}

fn timeout_from_secs(timeout_secs: Option<f64>) -> Option<Duration> {
    timeout_secs.and_then(|value| {
        (value.is_finite() && value > 0.0 && value <= Duration::MAX.as_secs_f64())
            .then(|| Duration::from_secs_f64(value))
    })
}

#[pyfunction]
fn hash_for_ots<'py>(py: Python<'py>, artifact: &Bound<'py, PyBytes>) -> Bound<'py, PyBytes> {
    let digest = trackone_ots::hash_for_ots_native(artifact.as_bytes());
    PyBytes::new(py, &digest)
}

#[pyfunction(signature = (ots_path, allow_placeholder = true, expected_artifact_sha = None, ots_binary = None, timeout_secs = None))]
fn verify_ots_proof(
    ots_path: String,
    allow_placeholder: bool,
    expected_artifact_sha: Option<String>,
    ots_binary: Option<String>,
    timeout_secs: Option<f64>,
) -> OtsVerifyResult {
    trackone_ots::verify_ots_proof_native(
        Path::new(&ots_path),
        allow_placeholder,
        expected_artifact_sha.as_deref(),
        ots_binary.as_deref().map(Path::new),
        timeout_from_secs(timeout_secs),
    )
    .into()
}

#[pyfunction(signature = (ots_path, expected_artifact_sha = None))]
fn describe_ots_proof(
    ots_path: String,
    expected_artifact_sha: Option<String>,
) -> PyResult<Vec<String>> {
    trackone_ots::describe_ots_proof_native(Path::new(&ots_path), expected_artifact_sha.as_deref())
        .map_err(PyValueError::new_err)
}

#[pyfunction]
fn validate_meta_sidecar(
    meta_path: String,
    repo_root: String,
    expected_artifact_path: String,
    expected_ots_path: String,
) -> OtsVerifyResult {
    trackone_ots::validate_meta_sidecar_native(
        Path::new(&meta_path),
        Path::new(&repo_root),
        Path::new(&expected_artifact_path),
        Path::new(&expected_ots_path),
    )
    .into()
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(parent.py(), "ots")?;
    sub.add_class::<OtsStatus>()?;
    sub.add_class::<OtsVerifyResult>()?;
    sub.add_function(wrap_pyfunction!(hash_for_ots, &sub)?)?;
    sub.add_function(wrap_pyfunction!(verify_ots_proof, &sub)?)?;
    sub.add_function(wrap_pyfunction!(describe_ots_proof, &sub)?)?;
    sub.add_function(wrap_pyfunction!(validate_meta_sidecar, &sub)?)?;
    parent.add_submodule(&sub)?;
    Ok(())
}
