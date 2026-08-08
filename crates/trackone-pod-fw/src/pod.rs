//! Pod-side helpers for constructing and encrypting facts.
//!
//! This module is intentionally small and `no_std`-friendly. Hardware-specific
//! concerns (HAL, sensors, radio) live outside this crate.

use trackone_core::crypto::AeadEncrypt;
use trackone_core::{Error, Fact, FactPayload, PodId};
use trackone_ingest::{EncryptedFrame, encrypt_fact, make_fact};

use crate::nonce::{Nonce24, NonceError};

/// Pod emission failures that callers must handle without reusing a counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PodError {
    Core(Error),
    Nonce(NonceError),
    FrameCounterRegression,
    FrameCounterExhausted,
    FactPodIdMismatch,
    FactFrameCounterMismatch,
}

impl From<Error> for PodError {
    fn from(error: Error) -> Self {
        Self::Core(error)
    }
}

impl From<NonceError> for PodError {
    fn from(error: NonceError) -> Self {
        Self::Nonce(error)
    }
}

pub type PodResult<T> = Result<T, PodError>;

/// Minimal pod state machine for emitting encrypted frames.
pub struct Pod<C, G, const N: usize> {
    pod_id: PodId,
    next_fc: Option<u32>,
    cipher: C,
    nonce_gen: G,
}

impl<C, G, const N: usize> Pod<C, G, N>
where
    C: AeadEncrypt<Error = Error>,
    G: Nonce24,
{
    pub fn new(pod_id: PodId, cipher: C, nonce_gen: G) -> Self {
        Self {
            pod_id,
            next_fc: Some(0),
            cipher,
            nonce_gen,
        }
    }

    pub fn pod_id(&self) -> PodId {
        self.pod_id
    }

    pub fn next_frame_counter(&self) -> Option<u32> {
        self.next_fc
    }

    /// Restore durable counter state without permitting rollback or reuse.
    pub fn restore_next_frame_counter(&mut self, next_fc: Option<u32>) -> PodResult<()> {
        match (self.next_fc, next_fc) {
            (None, None) => return Ok(()),
            (None, Some(_)) => return Err(PodError::FrameCounterExhausted),
            (Some(_), None) => {}
            (Some(current), Some(restored)) if restored < current => {
                return Err(PodError::FrameCounterRegression);
            }
            (Some(_), Some(_)) => {}
        }
        self.next_fc = next_fc;
        Ok(())
    }

    /// Build a `Fact` with the next frame counter and encrypt it into an `EncryptedFrame<N>`.
    pub fn emit_payload(&mut self, payload: FactPayload) -> PodResult<EncryptedFrame<N>> {
        let fc = self.next_fc.ok_or(PodError::FrameCounterExhausted)?;
        let fact = make_fact(self.pod_id, u64::from(fc), payload)?;
        self.emit_fact(&fact)
    }

    /// Validate and encrypt an already-constructed `Fact`.
    ///
    /// The fact must use this pod's identity and exact next v1 counter. Counter
    /// state advances only after encryption succeeds; after `u32::MAX` it
    /// becomes permanently exhausted.
    pub fn emit_fact(&mut self, fact: &Fact) -> PodResult<EncryptedFrame<N>> {
        let next_fc = self.next_fc.ok_or(PodError::FrameCounterExhausted)?;
        if fact.pod_id != self.pod_id {
            return Err(PodError::FactPodIdMismatch);
        }
        if fact.fc != u64::from(next_fc) {
            return Err(PodError::FactFrameCounterMismatch);
        }
        fact.validate()
            .map_err(Error::InvalidFact)
            .map_err(PodError::Core)?;

        let nonce = self.nonce_gen.nonce_for_frame(fact.fc)?;
        let frame = encrypt_fact::<N, _>(&self.cipher, nonce, fact)?;
        self.next_fc = next_fc.checked_add(1);
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonce::CounterNonce24;
    use trackone_core::crypto::dummy::DummyAead;
    use trackone_core::{EnvFact, SampleType};

    #[test]
    fn pod_emits_decryptable_frames() {
        static KEY: &[u8] = b"pod-fw-test-key";
        let cipher = DummyAead::new(KEY);

        let nonce_gen = CounterNonce24::from_provisioned_salt([0x42u8; 8], [0x99u8; 8]);
        let mut pod: Pod<_, _, 512> = Pod::new(PodId::from(7u32), cipher, nonce_gen);

        let payload = FactPayload::Env(
            EnvFact::instant(SampleType::AmbientAirTemperature, 1_700_000_000, 21.5).unwrap(),
        );

        let frame = pod.emit_payload(payload.clone()).expect("emit frame");
        assert_eq!(frame.pod_id, PodId::from(7u32));
        assert_eq!(frame.fc, 0);

        let cipher2 = DummyAead::new(KEY);
        let decoded = trackone_ingest::decrypt_fact::<512, _>(&cipher2, &frame, pod.pod_id())
            .expect("decrypt");
        assert_eq!(decoded.pod_id, PodId::from(7u32));
        assert_eq!(decoded.fc, 0);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn pod_frame_counter_increments_after_success() {
        static KEY: &[u8] = b"pod-fw-test-key";
        let cipher = DummyAead::new(KEY);
        let nonce_gen = CounterNonce24::from_provisioned_salt([0x42u8; 8], [0x99u8; 8]);
        let mut pod: Pod<_, _, 512> = Pod::new(PodId::from(7u32), cipher, nonce_gen);

        let payload = FactPayload::Env(
            EnvFact::instant(SampleType::AmbientAirTemperature, 1_700_000_000, 21.5).unwrap(),
        );

        // Frame counter should be 0 initially
        assert_eq!(pod.next_frame_counter(), Some(0));

        // Emit first frame
        let frame1 = pod.emit_payload(payload.clone()).expect("emit frame 1");
        assert_eq!(frame1.fc, 0);
        assert_eq!(pod.next_frame_counter(), Some(1));

        // Emit second frame
        let frame2 = pod.emit_payload(payload.clone()).expect("emit frame 2");
        assert_eq!(frame2.fc, 1);
        assert_eq!(pod.next_frame_counter(), Some(2));
    }

    #[test]
    fn pod_nonce_tracks_frame_counter_after_manual_resync() {
        static KEY: &[u8] = b"pod-fw-test-key";
        let cipher = DummyAead::new(KEY);
        let nonce_gen = CounterNonce24::from_provisioned_salt([0x42u8; 8], [0x99u8; 8]);
        let mut pod: Pod<_, _, 512> = Pod::new(PodId::from(7u32), cipher, nonce_gen);
        pod.restore_next_frame_counter(Some(42)).unwrap();

        let payload = FactPayload::Env(
            EnvFact::instant(SampleType::AmbientAirTemperature, 1_700_000_000, 21.5).unwrap(),
        );

        let frame = pod.emit_payload(payload).expect("emit frame");
        assert_eq!(frame.fc, 42);
        assert_eq!(
            u64::from_be_bytes(frame.nonce[8..16].try_into().expect("counter bytes")),
            42
        );
    }

    #[test]
    fn pod_restore_rejects_counter_regression() {
        let cipher = DummyAead::new(b"pod-fw-test-key");
        let nonce_gen = CounterNonce24::from_provisioned_salt([0x42; 8], [0x99; 8]);
        let mut pod: Pod<_, _, 512> = Pod::new(PodId::from(7u32), cipher, nonce_gen);

        pod.restore_next_frame_counter(Some(42)).unwrap();
        assert_eq!(
            pod.restore_next_frame_counter(Some(41)),
            Err(PodError::FrameCounterRegression)
        );
        assert_eq!(pod.next_frame_counter(), Some(42));
    }

    #[test]
    fn pod_exhausts_v1_counter_without_wrapping() {
        let cipher = DummyAead::new(b"pod-fw-test-key");
        let nonce_gen = CounterNonce24::from_provisioned_salt([0x42; 8], [0x99; 8]);
        let mut pod: Pod<_, _, 512> = Pod::new(PodId::from(7u32), cipher, nonce_gen);
        pod.restore_next_frame_counter(Some(u32::MAX)).unwrap();
        let payload = FactPayload::Env(
            EnvFact::instant(SampleType::AmbientAirTemperature, 1_700_000_000, 21.5).unwrap(),
        );

        let frame = pod.emit_payload(payload.clone()).unwrap();
        assert_eq!(frame.fc, u64::from(u32::MAX));
        assert_eq!(pod.next_frame_counter(), None);
        assert_eq!(
            pod.emit_payload(payload),
            Err(PodError::FrameCounterExhausted)
        );
        assert_eq!(
            pod.restore_next_frame_counter(Some(0)),
            Err(PodError::FrameCounterExhausted)
        );
    }

    #[test]
    fn pod_can_restore_durable_exhaustion_without_reopening_counter_zero() {
        let cipher = DummyAead::new(b"pod-fw-test-key");
        let nonce_gen = CounterNonce24::from_provisioned_salt([0x42; 8], [0x99; 8]);
        let mut pod: Pod<_, _, 512> = Pod::new(PodId::from(7u32), cipher, nonce_gen);

        pod.restore_next_frame_counter(None).unwrap();
        assert_eq!(pod.next_frame_counter(), None);
        assert_eq!(
            pod.restore_next_frame_counter(Some(0)),
            Err(PodError::FrameCounterExhausted)
        );
    }

    #[test]
    fn emit_fact_rejects_foreign_state_without_advancing() {
        let cipher = DummyAead::new(b"pod-fw-test-key");
        let nonce_gen = CounterNonce24::from_provisioned_salt([0x42; 8], [0x99; 8]);
        let mut pod: Pod<_, _, 512> = Pod::new(PodId::from(7u32), cipher, nonce_gen);
        let fact = make_fact(
            PodId::from(8u32),
            0,
            FactPayload::Env(
                EnvFact::instant(SampleType::AmbientAirTemperature, 1_700_000_000, 21.5).unwrap(),
            ),
        )
        .unwrap();

        assert_eq!(pod.emit_fact(&fact), Err(PodError::FactPodIdMismatch));
        assert_eq!(pod.next_frame_counter(), Some(0));
    }
}
