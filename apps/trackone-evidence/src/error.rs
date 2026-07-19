//! Shared evidence application error type.

#[derive(Debug)]
pub enum EvidenceError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Ledger(trackone_ledger::Error),
    Invalid(String),
    VerificationFailed(String),
    Git(String),
}

impl core::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::Json(err) => write!(f, "json error: {err}"),
            Self::Ledger(err) => write!(f, "ledger error: {err}"),
            Self::Invalid(msg) | Self::VerificationFailed(msg) | Self::Git(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for EvidenceError {}

impl From<std::io::Error> for EvidenceError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for EvidenceError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

impl From<trackone_ledger::Error> for EvidenceError {
    fn from(err: trackone_ledger::Error) -> Self {
        Self::Ledger(err)
    }
}

pub type Result<T> = core::result::Result<T, EvidenceError>;
