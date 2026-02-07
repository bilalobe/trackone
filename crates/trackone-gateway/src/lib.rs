#![cfg_attr(not(debug_assertions), deny(warnings))]

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};

mod crypto;
mod ledger;
mod merkle;
mod ots;
mod radio;

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
#[pyclass]
pub struct GatewayBatch {
    /// Raw frames as provided by Python.
    frames: Vec<Vec<u8>>,
    /// Merkle root over `frames`.
    merkle_root: [u8; 32],
}

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
#[pyclass]
pub struct Gateway;

impl Default for Gateway {
    fn default() -> Self {
        Self::new()
    }
}

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

#[pymodule]
fn trackone_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register high-level classes
    m.add_class::<Gateway>()?;
    m.add_class::<GatewayBatch>()?;
    m.add_class::<radio::PyRadio>()?;

    // Re-export submodules into the Python extension module namespace
    crypto::register(m)?;
    ledger::register(m)?;
    merkle::register(m)?;
    ots::register(m)?;

    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
