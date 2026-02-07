use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Python-implemented radio adapter.
///
/// This is a thin wrapper around an arbitrary Python object that
/// provides `send_frame(self, data: bytes)` and optionally
/// `receive_frame(self) -> Optional[bytes]`.
#[pyclass]
pub struct PyRadio {
    inner: Py<PyAny>,
}

#[pymethods]
impl PyRadio {
    /// Wrap a Python-side radio implementation.
    ///
    /// Example (Python):
    ///
    /// ```python
    /// class MyRadio:
    ///     def send_frame(self, data: bytes) -> None:
    ///         ...
    ///
    /// r = PyRadio(MyRadio())
    /// ```
    #[new]
    pub fn new(obj: Py<PyAny>) -> Self {
        PyRadio { inner: obj }
    }

    /// Call `send_frame(data)` on the underlying Python object.
    pub fn send_frame(&self, frame: &Bound<'_, PyBytes>) -> PyResult<()> {
        let py = frame.py();
        let inner = self.inner.bind(py);
        inner.call_method("send_frame", (frame,), None)?;
        Ok(())
    }

    /// Call `receive_frame()` on the underlying Python object, if implemented.
    ///
    /// Returns `None` if no frame is available or the method is missing.
    pub fn receive_frame<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let inner = self.inner.bind(py);
        let result = inner.getattr("receive_frame").ok();
        if let Some(method) = result {
            let any = method.call0()?;
            if any.is_none() {
                Ok(None)
            } else {
                Ok(Some(any.cast_into::<PyBytes>()?))
            }
        } else {
            Ok(None)
        }
    }
}
