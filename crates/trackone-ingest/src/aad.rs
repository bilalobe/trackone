//! Framed associated-data construction and fact/header binding.

use trackone_core::{Fact, FrameCounter, PodId};

/// Error returned when a postcard `Fact` conflicts with its frame header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramedFactBindingError {
    PodIdMismatch,
    FrameCounterMismatch,
}

/// Derive the legacy 16-bit frame routing identifier from a canonical `PodId`.
///
/// # Security
///
/// This value is collision-prone and must never be used as an authorization
/// identity. Bind admitted data to the complete provisioned `PodId`.
pub fn legacy_dev_id_from_pod_id(pod_id: PodId) -> u16 {
    u16::from_be_bytes([pod_id.0[6], pod_id.0[7]])
}

/// Construct AEAD associated data for framed material.
pub fn framed_aad(dev_id: u16, msg_type: u8, flags: u8) -> [u8; 4] {
    let [hi, lo] = dev_id.to_be_bytes();
    [hi, lo, msg_type, flags]
}

/// Construct legacy AEAD associated data from a canonical `PodId`.
///
/// This includes only the `PodId` routing suffix. Callers must separately bind
/// decrypted data to the complete provisioned identity.
pub fn framed_aad_for_pod(pod_id: PodId, msg_type: u8, flags: u8) -> [u8; 4] {
    framed_aad(legacy_dev_id_from_pod_id(pod_id), msg_type, flags)
}

/// Validate that a decoded fact belongs to the provisioned device and frame.
///
/// The full `expected_pod_id` is authoritative. Matching only the legacy
/// 16-bit `dev_id` suffix is not an identity check.
///
/// # Example
///
/// ```
/// use trackone_core::{Fact, FactKind, FactPayload, PodId};
/// use trackone_ingest::{
///     FramedFactBindingError, legacy_dev_id_from_pod_id, validate_fact_binding,
/// };
///
/// let expected = PodId::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x12, 0x34]);
/// let mut fact = Fact {
///     pod_id: expected,
///     fc: 7,
///     ingest_time: 0,
///     pod_time: None,
///     kind: FactKind::Custom,
///     payload: FactPayload::Custom(Default::default()),
/// };
/// assert_eq!(validate_fact_binding(&fact, expected, 7), Ok(()));
///
/// // The forged identity has the same legacy suffix but is still rejected.
/// fact.pod_id = PodId::from([0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x12, 0x34]);
/// assert_eq!(
///     legacy_dev_id_from_pod_id(fact.pod_id),
///     legacy_dev_id_from_pod_id(expected),
/// );
/// assert_eq!(
///     validate_fact_binding(&fact, expected, 7),
///     Err(FramedFactBindingError::PodIdMismatch),
/// );
/// ```
pub fn validate_fact_binding(
    fact: &Fact,
    expected_pod_id: PodId,
    expected_fc: FrameCounter,
) -> Result<(), FramedFactBindingError> {
    if fact.pod_id != expected_pod_id {
        return Err(FramedFactBindingError::PodIdMismatch);
    }
    if fact.fc != expected_fc {
        return Err(FramedFactBindingError::FrameCounterMismatch);
    }
    Ok(())
}
