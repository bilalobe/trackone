use pyo3::prelude::*;

#[pyfunction]
fn placeholder_root() -> &'static str {
    "merkle-root-not-implemented"
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new_bound(parent.py(), "merkle")?;
    sub.add_function(wrap_pyfunction!(placeholder_root, &sub)?)?;
    parent.add_submodule(&sub)?;
    Ok(())
}
