use pyo3::prelude::*;

#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    // In PyO3 0.27, create submodule directly via add_submodule with PyModule::new
    let sub = PyModule::new(parent.py(), "crypto")?;
    sub.add_function(wrap_pyfunction!(version, &sub)?)?;
    parent.add_submodule(&sub)?;
    Ok(())
}
