#![cfg_attr(not(debug_assertions), deny(warnings))]

use pyo3::prelude::*;

mod crypto;
mod merkle;
mod ots;

#[pymodule]
fn trackone_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Re-export submodules into the Python extension module namespace
    crypto::register(m)?;
    merkle::register(m)?;
    ots::register(m)?;

    m.add("__version__", "0.0.1")?;
    Ok(())
}
