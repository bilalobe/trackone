/// Canonical maximum serialized length for a `Fact` in bytes.
///
/// This is a workspace-level policy knob. Consumers should not hardcode
/// their own value; import it from `trackone_constants::MAX_FACT_LEN` (re-exported)
/// or directly from this crate if needed.
pub const MAX_FACT_LEN: usize = 256;

/// AEAD nonce length in bytes (XChaCha20-Poly1305).
pub const AEAD_NONCE_LEN: usize = 24;

/// AEAD authentication tag length in bytes (Poly1305).
pub const AEAD_TAG_LEN: usize = 16;

/// Default timeout for invoking `ots verify` in gateway-side validation.
pub const OTS_VERIFY_TIMEOUT_SECS: u64 = 30;
