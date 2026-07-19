//! Framed nonce construction and prefix validation.

use trackone_core::AEAD_NONCE_LEN;

/// Error returned when the nonce prefix does not match the framed header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramedNonceError {
    NonceLength,
    Salt8Length,
    SaltMismatch,
    FrameCounterMismatch,
}

/// Build a gateway-admissible XChaCha20-Poly1305 framed nonce.
///
/// Layout: `salt8 || fc32_as_u64_be || tail8`.
pub fn framed_nonce(salt8: [u8; 8], fc: u32, tail8: [u8; 8]) -> [u8; AEAD_NONCE_LEN] {
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce[..8].copy_from_slice(&salt8);
    nonce[8..16].copy_from_slice(&u64::from(fc).to_be_bytes());
    nonce[16..24].copy_from_slice(&tail8);
    nonce
}

/// Validate the gateway-admission nonce prefix against device salt and frame
/// header counter.
pub fn validate_nonce_prefix(nonce: &[u8], salt8: &[u8], fc: u32) -> Result<(), FramedNonceError> {
    if nonce.len() != AEAD_NONCE_LEN {
        return Err(FramedNonceError::NonceLength);
    }
    if salt8.len() != 8 {
        return Err(FramedNonceError::Salt8Length);
    }
    if nonce[..8] != salt8[..] {
        return Err(FramedNonceError::SaltMismatch);
    }
    let counter = u64::from_be_bytes(nonce[8..16].try_into().expect("nonce slice length"));
    if counter != u64::from(fc) {
        return Err(FramedNonceError::FrameCounterMismatch);
    }
    Ok(())
}
