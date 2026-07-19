//! Supported verification and evidence-export application library.

mod bundle;
mod error;
mod export;
mod git_ops;
mod manifest;
mod policy;
mod verify;

pub mod v2;

pub use error::{EvidenceError, Result};
pub use export::export_bundle;
pub use manifest::{ArtifactRef, VerificationBundle, VerifyManifest};
pub use policy::*;
pub use verify::{local_verification_failure, verify_bundle};
