use pyo3::prelude::*;

#[pyfunction]
fn version() -> &'static str {
    "0.0.1"
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new_bound(parent.py(), "crypto")?;
    sub.add_function(wrap_pyfunction!(version, &sub)?)?;
    parent.add_submodule(&sub)?;
    Ok(())
}
