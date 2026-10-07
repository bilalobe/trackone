//! Context for failures at application boundaries, retaining the original cause.

use std::{error::Error, fmt};

#[derive(thiserror::Error)]
#[error("{context}: {source}")]
pub struct RuntimeError {
    context: String,
    #[source]
    source: Box<dyn Error>,
}

// Result-returning main uses Debug to report errors. Keep that output readable.
impl fmt::Debug for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

pub trait ResultContext<T> {
    fn context(self, context: impl Into<String>) -> Result<T, RuntimeError>;
}

impl<T, E: Into<Box<dyn Error>>> ResultContext<T> for Result<T, E> {
    fn context(self, context: impl Into<String>) -> Result<T, RuntimeError> {
        self.map_err(|source| RuntimeError {
            context: context.into(),
            source: source.into(),
        })
    }
}
