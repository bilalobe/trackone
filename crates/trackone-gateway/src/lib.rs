#![cfg_attr(not(debug_assertions), deny(warnings))]

#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::types::{PyAny, PyBytes};

#[cfg(feature = "python")]
mod crypto;
#[cfg(feature = "python")]
mod ledger;
#[cfg(feature = "python")]
mod merkle;
#[cfg(any(feature = "python", test))]
mod ots;
#[cfg(feature = "python")]
mod radio;
pub mod sensorthings;

#[cfg(feature = "python")]
fn extract_frames(py_frames: &Bound<'_, PyAny>) -> PyResult<Vec<Vec<u8>>> {
    let capacity = py_frames.len().unwrap_or(0);
    let mut frames: Vec<Vec<u8>> = Vec::with_capacity(capacity);
    for item in py_frames.try_iter()? {
        let obj: Bound<'_, PyAny> = item?;
        let b = obj.cast_into::<PyBytes>()?;
        frames.push(b.as_bytes().to_vec());
    }
    Ok(frames)
}

/// A simple batch of raw frames plus a Merkle root.
#[cfg(feature = "python")]
#[pyclass]
pub struct GatewayBatch {
    /// Raw frames as provided by Python.
    frames: Vec<Vec<u8>>,
    /// Merkle root over `frames`.
    merkle_root: [u8; 32],
}

#[cfg(feature = "python")]
#[pymethods]
impl GatewayBatch {
    /// Return the frames as a list of Python bytes objects.
    pub fn frames(&self, py: Python<'_>) -> Vec<Py<PyBytes>> {
        self.frames
            .iter()
            .map(|frame| PyBytes::new(py, frame).unbind())
            .collect()
    }

    /// Return the Merkle root as bytes.
    pub fn merkle_root(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.merkle_root).unbind()
    }

    /// Number of frames in this batch.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

/// High-level gateway helper exposed to Python.
#[cfg(feature = "python")]
#[pyclass]
pub struct Gateway;

#[cfg(feature = "python")]
impl Default for Gateway {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "python")]
#[pymethods]
impl Gateway {
    /// Construct a new Gateway instance.
    #[new]
    pub fn new() -> Self {
        Gateway
    }

    /// Compute a Merkle root over a sequence of frames (bytes).
    pub fn compute_merkle_root<'py>(
        &self,
        py: Python<'py>,
        py_frames: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let frames = extract_frames(py_frames)?;
        let root = trackone_ledger::merkle::merkle_root_from_leaves(&frames).root;
        Ok(PyBytes::new(py, &root))
    }

    /// Create a batch from frames and attach a Merkle root.
    pub fn make_batch(&self, py_frames: &Bound<'_, PyAny>) -> PyResult<GatewayBatch> {
        let frames = extract_frames(py_frames)?;
        let root = trackone_ledger::merkle::merkle_root_from_leaves(&frames).root;
        Ok(GatewayBatch {
            frames,
            merkle_root: root,
        })
    }

    /// Send a single frame using the provided radio implementation.
    ///
    /// The `radio` object must implement `send_frame(self, data: bytes)` on the Python side.
    fn send_frame(&self, radio: &radio::PyRadio, frame: &Bound<'_, PyBytes>) -> PyResult<()> {
        radio.send_frame(frame)
    }
}

#[cfg(feature = "python")]
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register high-level classes
    m.add_class::<Gateway>()?;
    m.add_class::<GatewayBatch>()?;
    m.add_class::<radio::PyRadio>()?;

    // Re-export submodules into the Python extension module namespace
    crypto::register(m)?;
    ledger::register(m)?;
    merkle::register(m)?;
    ots::register(m)?;
    sensorthings::python::register(m)?;

    m.add(
        "DEFAULT_COMMITMENT_PROFILE_ID",
        trackone_constants::COMMITMENT_PROFILE_ID_CANONICAL_CBOR_V1,
    )?;
    m.add(
        "DISCLOSURE_CLASS_A",
        trackone_constants::DISCLOSURE_CLASS_PUBLIC_RECOMPUTE,
    )?;
    m.add(
        "DISCLOSURE_CLASS_B",
        trackone_constants::DISCLOSURE_CLASS_PARTNER_AUDIT,
    )?;
    m.add(
        "DISCLOSURE_CLASS_C",
        trackone_constants::DISCLOSURE_CLASS_ANCHOR_ONLY,
    )?;
    m.add(
        "DISCLOSURE_CLASS_A_LABEL",
        trackone_constants::DISCLOSURE_CLASS_PUBLIC_RECOMPUTE_LABEL,
    )?;
    m.add(
        "DISCLOSURE_CLASS_B_LABEL",
        trackone_constants::DISCLOSURE_CLASS_PARTNER_AUDIT_LABEL,
    )?;
    m.add(
        "DISCLOSURE_CLASS_C_LABEL",
        trackone_constants::DISCLOSURE_CLASS_ANCHOR_ONLY_LABEL,
    )?;
    m.add(
        "INGEST_PROFILE_RUST_POSTCARD_V1",
        trackone_constants::INGEST_PROFILE_RUST_POSTCARD_V1,
    )?;
    m.add(
        "FRAMED_FACT_MSG_TYPE",
        trackone_constants::FRAMED_FACT_MSG_TYPE,
    )?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
