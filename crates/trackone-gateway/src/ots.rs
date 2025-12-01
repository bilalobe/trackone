use pyo3::prelude::*;

#[pyfunction]
fn placeholder_ots() -> &'static str {
    "ots-not-implemented"
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new_bound(parent.py(), "ots")?;
    sub.add_function(wrap_pyfunction!(placeholder_ots, &sub)?)?;
    parent.add_submodule(&sub)?;
    Ok(())
}
