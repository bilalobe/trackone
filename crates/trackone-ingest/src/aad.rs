//! Framed associated-data construction and fact/header binding.

use trackone_core::{Fact, PodId};

/// Error returned when a postcard `Fact` conflicts with its frame header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramedFactBindingError {
    PodIdMismatch,
    FrameCounterMismatch,
}

/// Derive the legacy 16-bit frame `dev_id` from the canonical 8-byte `PodId`.
pub fn legacy_dev_id_from_pod_id(pod_id: PodId) -> u16 {
    u16::from_be_bytes([pod_id.0[6], pod_id.0[7]])
}

/// Construct AEAD associated data for framed material.
pub fn framed_aad(dev_id: u16, msg_type: u8, flags: u8) -> [u8; 4] {
    let [hi, lo] = dev_id.to_be_bytes();
    [hi, lo, msg_type, flags]
}

/// Construct AEAD associated data from a canonical `PodId`.
pub fn framed_aad_for_pod(pod_id: PodId, msg_type: u8, flags: u8) -> [u8; 4] {
    framed_aad(legacy_dev_id_from_pod_id(pod_id), msg_type, flags)
}

/// Validate that a decoded postcard fact belongs to the enclosing frame.
pub fn validate_fact_binding(
    fact: &Fact,
    dev_id: u16,
    fc: u32,
) -> Result<(), FramedFactBindingError> {
    if legacy_dev_id_from_pod_id(fact.pod_id) != dev_id {
        return Err(FramedFactBindingError::PodIdMismatch);
    }
    if fact.fc != u64::from(fc) {
        return Err(FramedFactBindingError::FrameCounterMismatch);
    }
    Ok(())
}
