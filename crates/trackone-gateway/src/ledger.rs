use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

fn to_py_err<E: core::fmt::Display>(err: E) -> PyErr {
    PyValueError::new_err(err.to_string())
}

/// Canonicalize JSON bytes (ADR-003): sorted keys, UTF-8, minified.
#[pyfunction]
fn canonicalize_json_bytes<'py>(
    py: Python<'py>,
    input: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let out = trackone_ledger::canonical_json::canonicalize_json_bytes(input.as_bytes())
        .map_err(to_py_err)?;
    Ok(PyBytes::new(py, &out))
}

/// Canonicalize JSON bytes into deterministic CBOR commitment bytes (ADR-039).
#[pyfunction]
fn canonicalize_json_to_cbor_bytes<'py>(
    py: Python<'py>,
    input: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let out = trackone_ledger::canonical_cbor::canonicalize_json_bytes_to_cbor(input.as_bytes())
        .map_err(to_py_err)?;
    Ok(PyBytes::new(py, &out))
}

#[pyfunction]
fn sha256_hex(input: &Bound<'_, PyBytes>) -> PyResult<String> {
    Ok(trackone_ledger::sha256_hex(input.as_bytes()))
}

#[pyfunction]
fn normalize_hex64(value: String) -> PyResult<String> {
    trackone_ledger::normalize_hex64(&value).map_err(to_py_err)
}

/// Build a v1 block header and day record, returning canonical JSON bytes.
///
/// Returns `(block_header_json_bytes, day_bin_bytes)`.
#[pyfunction]
fn build_day_v1_single_batch<'py>(
    py: Python<'py>,
    site_id: String,
    date: String,
    prev_day_root: String,
    batch_id: String,
    canonical_leaves: &Bound<'py, PyAny>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let leaves = crate::extract_frames(canonical_leaves)?;

    let header = trackone_ledger::types::block_header_v1_from_canonical_leaves(
        site_id.clone(),
        date.clone(),
        batch_id,
        &leaves,
    );
    let header_bytes = header.canonical_json_bytes().map_err(to_py_err)?;
    let day_record =
        trackone_ledger::types::day_record_v1_single_batch(site_id, date, prev_day_root, header);
    let day_bytes = day_record.canonical_json_bytes().map_err(to_py_err)?;

    Ok((
        PyBytes::new(py, &header_bytes),
        PyBytes::new(py, &day_bytes),
    ))
}

/// Build a v1 block header and day record, returning
/// `(block_header_json_bytes, day_cbor_bytes, day_json_projection_bytes)`.
#[pyfunction]
fn build_day_v1_single_batch_cbor<'py>(
    py: Python<'py>,
    site_id: String,
    date: String,
    prev_day_root: String,
    batch_id: String,
    canonical_leaves: &Bound<'py, PyAny>,
) -> PyResult<(
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
)> {
    let leaves = crate::extract_frames(canonical_leaves)?;

    let header = trackone_ledger::types::block_header_v1_from_canonical_leaves(
        site_id.clone(),
        date.clone(),
        batch_id,
        &leaves,
    );
    let header_bytes = header.canonical_json_bytes().map_err(to_py_err)?;
    let day_record =
        trackone_ledger::types::day_record_v1_single_batch(site_id, date, prev_day_root, header);
    let day_cbor_bytes = day_record.canonical_cbor_bytes().map_err(to_py_err)?;
    let day_json_bytes = day_record.canonical_json_bytes().map_err(to_py_err)?;

    Ok((
        PyBytes::new(py, &header_bytes),
        PyBytes::new(py, &day_cbor_bytes),
        PyBytes::new(py, &day_json_bytes),
    ))
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(parent.py(), "ledger")?;
    sub.add_function(wrap_pyfunction!(canonicalize_json_bytes, &sub)?)?;
    sub.add_function(wrap_pyfunction!(canonicalize_json_to_cbor_bytes, &sub)?)?;
    sub.add_function(wrap_pyfunction!(sha256_hex, &sub)?)?;
    sub.add_function(wrap_pyfunction!(normalize_hex64, &sub)?)?;
    sub.add_function(wrap_pyfunction!(build_day_v1_single_batch, &sub)?)?;
    sub.add_function(wrap_pyfunction!(build_day_v1_single_batch_cbor, &sub)?)?;
    parent.add_submodule(&sub)?;
    Ok(())
}
