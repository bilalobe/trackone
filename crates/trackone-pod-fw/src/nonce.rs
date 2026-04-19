//! Nonce generation helpers for pod firmware.
//!
//! TrackOne uses a 24-byte nonce size (XChaCha20-Poly1305). The core crate
//! (`trackone-core`) enforces nonce *uniqueness* at the call-site by requiring
//! the nonce to be supplied explicitly when encrypting facts.
//!
//! This module provides a simple, `no_std`-friendly counter-based nonce
//! generator suitable for embedded pods (ADR-018).

use trackone_core::{AEAD_NONCE_LEN, FrameCounter};
use trackone_ingest::framed_nonce;

/// A 24-byte nonce source for an already-selected frame counter.
pub trait Nonce24 {
    fn nonce_for_frame(&mut self, fc: FrameCounter) -> [u8; AEAD_NONCE_LEN];
}

/// Frame-counter-bound 24-byte nonce generator.
///
/// Layout: `[salt8:8] || [fc32_as_u64_be:8] || [tail8:8]`.
///
/// The middle field is derived from the frame/fact counter supplied by the pod
/// state machine. This keeps one counter authority: `Pod::next_fc`.
#[derive(Clone, Copy, Debug)]
pub struct CounterNonce24 {
    salt8: [u8; 8],
    tail8: [u8; 8],
}

impl CounterNonce24 {
    pub const fn new(salt8: [u8; 8], tail8: [u8; 8]) -> Self {
        Self { salt8, tail8 }
    }

    /// Convenience helper for provisioned TrackOne devices.
    ///
    /// `provisioned_salt8` must be the stable per-device salt stored in the
    /// gateway device table. Generate `boot_tail8` freshly at boot when the
    /// platform has an OS-backed CSPRNG or hardware RNG; otherwise use stable
    /// producer-specific tail material and a persistent monotonic counter.
    pub const fn from_provisioned_salt(provisioned_salt8: [u8; 8], boot_tail8: [u8; 8]) -> Self {
        Self::new(provisioned_salt8, boot_tail8)
    }
}

impl Nonce24 for CounterNonce24 {
    fn nonce_for_frame(&mut self, fc: FrameCounter) -> [u8; AEAD_NONCE_LEN] {
        let fc32 = u32::try_from(fc)
            .expect("CounterNonce24 requires frame counters that fit the v1 u32 frame header");
        framed_nonce(self.salt8, fc32, self.tail8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_is_bound_to_supplied_frame_counter() {
        let mut nonce_gen = CounterNonce24::new([0u8; 8], [0u8; 8]);
        let nonce1 = nonce_gen.nonce_for_frame(7);
        let nonce2 = nonce_gen.nonce_for_frame(8);
        assert_ne!(nonce1, nonce2);
        assert_eq!(&nonce1[..8], &[0u8; 8]);
        assert_eq!(&nonce1[16..24], &[0u8; 8]);
        assert_eq!(
            u64::from_be_bytes(nonce1[8..16].try_into().expect("counter bytes")),
            7
        );
        assert_eq!(
            u64::from_be_bytes(nonce2[8..16].try_into().expect("counter bytes")),
            8
        );
    }

    #[test]
    fn provisioned_salt_constructor_keeps_validated_prefix_stable() {
        let provisioned_salt8 = [0x42u8; 8];
        let boot_tail8 = [0x99u8; 8];
        let mut nonce_gen = CounterNonce24::from_provisioned_salt(provisioned_salt8, boot_tail8);
        let nonce = nonce_gen.nonce_for_frame(7);

        assert_eq!(&nonce[..8], &provisioned_salt8);
        assert_eq!(
            u64::from_be_bytes(nonce[8..16].try_into().expect("counter bytes")),
            7
        );
        assert_eq!(&nonce[16..24], &boot_tail8);
    }

    #[test]
    #[should_panic(expected = "fit the v1 u32 frame header")]
    fn nonce_panics_when_frame_counter_exceeds_v1_header() {
        let mut nonce_gen = CounterNonce24::new([0u8; 8], [0u8; 8]);
        nonce_gen.nonce_for_frame(u64::from(u32::MAX) + 1);
    }
}
