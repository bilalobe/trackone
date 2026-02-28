use pyo3::prelude::*;
use pyo3::types::PyBytes;
use trackone_ledger::hex_lower;

#[pyfunction]
fn merkle_root_bytes<'py>(
    py: Python<'py>,
    leaves: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    let leaves = crate::extract_frames(leaves)?;
    let root = trackone_ledger::merkle::merkle_root_from_leaves(&leaves).root;
    Ok(PyBytes::new(py, &root))
}

#[pyfunction]
fn merkle_root_hex(leaves: &Bound<'_, PyAny>) -> PyResult<String> {
    let leaves = crate::extract_frames(leaves)?;
    let root = trackone_ledger::merkle::merkle_root_from_leaves(&leaves).root;
    Ok(hex_lower(&root))
}

#[pyfunction]
fn merkle_root_hex_and_leaf_hashes(leaves: &Bound<'_, PyAny>) -> PyResult<(String, Vec<String>)> {
    let leaves = crate::extract_frames(leaves)?;
    let result = trackone_ledger::merkle::merkle_root_from_leaves(&leaves);
    Ok((result.root_hex(), result.leaf_hashes_hex()))
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(parent.py(), "merkle")?;
    sub.add_function(wrap_pyfunction!(merkle_root_bytes, &sub)?)?;
    sub.add_function(wrap_pyfunction!(merkle_root_hex, &sub)?)?;
    sub.add_function(wrap_pyfunction!(merkle_root_hex_and_leaf_hashes, &sub)?)?;
    parent.add_submodule(&sub)?;
    Ok(())
}
