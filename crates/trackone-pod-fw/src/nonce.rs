//! Nonce generation helpers for pod firmware.
//!
//! TrackOne uses a 24-byte nonce size (XChaCha20-Poly1305). The core crate
//! (`trackone-core`) enforces nonce *uniqueness* at the call-site by requiring
//! the nonce to be supplied explicitly when encrypting facts.
//!
//! This module provides a simple, `no_std`-friendly counter-based nonce
//! generator suitable for embedded pods (ADR-018).

use trackone_core::{PodId, AEAD_NONCE_LEN};

/// A 24-byte nonce generator.
pub trait Nonce24 {
    fn next_nonce(&mut self) -> [u8; AEAD_NONCE_LEN];
}

/// Counter-based 24-byte nonce generator.
///
/// Layout: `[prefix:16] || [counter_be:8]`.
///
/// The caller must ensure the `(prefix, counter)` pair never repeats for the
/// lifetime of a given AEAD key.
#[derive(Clone, Copy, Debug)]
pub struct CounterNonce24 {
    prefix: [u8; 16],
    counter: u64,
}

impl CounterNonce24 {
    pub const fn new(prefix: [u8; 16], initial_counter: u64) -> Self {
        Self {
            prefix,
            counter: initial_counter,
        }
    }

    /// Convenience helper: derive a 16-byte prefix from a `PodId` and an 8-byte boot salt.
    ///
    /// A recommended strategy is to store a persistent counter in NVM and to
    /// generate a fresh `boot_salt` at boot from an OS-backed CSPRNG or a
    /// hardware RNG (if available).
    pub fn from_pod_id(pod_id: PodId, boot_salt: [u8; 8], initial_counter: u64) -> Self {
        let mut prefix = [0u8; 16];
        prefix[0..8].copy_from_slice(&pod_id.0);
        prefix[8..16].copy_from_slice(&boot_salt);
        Self::new(prefix, initial_counter)
    }

    pub const fn counter(&self) -> u64 {
        self.counter
    }
}

impl Nonce24 for CounterNonce24 {
    fn next_nonce(&mut self) -> [u8; AEAD_NONCE_LEN] {
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        nonce[0..16].copy_from_slice(&self.prefix);
        nonce[16..24].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        nonce
    }
}
