//! Pod-side helpers for constructing and encrypting facts.
//!
//! This module is intentionally small and `no_std`-friendly. Hardware-specific
//! concerns (HAL, sensors, radio) live outside this crate.

use trackone_core::crypto::AeadEncrypt;
use trackone_core::frame;
use trackone_core::{CoreResult, EncryptedFrame, Error, Fact, FactPayload, FrameCounter, PodId};

use crate::nonce::Nonce24;

/// Minimal pod state machine for emitting encrypted frames.
pub struct Pod<C, G, const N: usize> {
    pod_id: PodId,
    next_fc: FrameCounter,
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
            next_fc: 0,
            cipher,
            nonce_gen,
        }
    }

    pub fn pod_id(&self) -> PodId {
        self.pod_id
    }

    pub fn next_frame_counter(&self) -> FrameCounter {
        self.next_fc
    }

    pub fn set_next_frame_counter(&mut self, fc: FrameCounter) {
        self.next_fc = fc;
    }

    /// Build a `Fact` with the next frame counter and encrypt it into an `EncryptedFrame<N>`.
    pub fn emit_payload(&mut self, payload: FactPayload) -> CoreResult<EncryptedFrame<N>> {
        let fc = self.next_fc;
        let fact = frame::make_fact(self.pod_id, fc, payload);
        match self.emit_fact(&fact) {
            Ok(frame) => {
                // Only advance the frame counter after successful encryption.
                self.next_fc = self.next_fc.wrapping_add(1);
                Ok(frame)
            }
            Err(e) => Err(e),
        }
    }

    /// Encrypt an already-constructed `Fact` into an `EncryptedFrame<N>`.
    pub fn emit_fact(&mut self, fact: &Fact) -> CoreResult<EncryptedFrame<N>> {
        let nonce = self.nonce_gen.next_nonce();
        frame::encrypt_fact::<N, _>(&self.cipher, nonce, fact)
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

        let nonce_gen = CounterNonce24::from_pod_id(PodId::from(7u32), [0x42u8; 8], 0);
        let mut pod: Pod<_, _, 512> = Pod::new(PodId::from(7u32), cipher, nonce_gen);

        let payload = FactPayload::Env(EnvFact::instant(
            SampleType::AmbientAirTemperature,
            1_700_000_000,
            21.5,
        ));

        let frame = pod.emit_payload(payload.clone()).expect("emit frame");
        assert_eq!(frame.pod_id, PodId::from(7u32));
        assert_eq!(frame.fc, 0);

        let cipher2 = DummyAead::new(KEY);
        let decoded = frame::decrypt_fact::<512, _>(&cipher2, &frame).expect("decrypt");
        assert_eq!(decoded.pod_id, PodId::from(7u32));
        assert_eq!(decoded.fc, 0);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn pod_frame_counter_increments_after_success() {
        static KEY: &[u8] = b"pod-fw-test-key";
        let cipher = DummyAead::new(KEY);
        let nonce_gen = CounterNonce24::from_pod_id(PodId::from(7u32), [0x42u8; 8], 0);
        let mut pod: Pod<_, _, 512> = Pod::new(PodId::from(7u32), cipher, nonce_gen);

        let payload = FactPayload::Env(EnvFact::instant(
            SampleType::AmbientAirTemperature,
            1_700_000_000,
            21.5,
        ));

        // Frame counter should be 0 initially
        assert_eq!(pod.next_frame_counter(), 0);

        // Emit first frame
        let frame1 = pod.emit_payload(payload.clone()).expect("emit frame 1");
        assert_eq!(frame1.fc, 0);
        assert_eq!(pod.next_frame_counter(), 1);

        // Emit second frame
        let frame2 = pod.emit_payload(payload.clone()).expect("emit frame 2");
        assert_eq!(frame2.fc, 1);
        assert_eq!(pod.next_frame_counter(), 2);
    }
}
