//! Rust-native framed telemetry emission and gateway admission.
//!
//! This crate owns the framed plaintext wire contract used between pods and
//! gateways: profile identifiers, nonce/AAD construction, bounded encrypted
//! frame envelopes, fixture emission, and gateway-side framed admission.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(debug_assertions), deny(warnings))]

use core::fmt;

use heapless::Vec as HVec;
use serde::{Deserialize, Serialize};
use trackone_core::crypto::{AeadDecrypt, AeadEncrypt};
use trackone_core::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, CoreResult, Error, Fact, FactKind, FactPayload, FrameCounter,
    MAX_FACT_LEN, PodId,
};

#[cfg(feature = "xchacha")]
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
#[cfg(feature = "std")]
use std::collections::BTreeSet;
#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(feature = "xchacha")]
use trackone_core::{EnvFact, SampleType};

/// Current Rust-native framed plaintext profile identifier.
pub const INGEST_PROFILE_RUST_POSTCARD_V1: &str =
    trackone_constants::INGEST_PROFILE_RUST_POSTCARD_V1;

/// Message type used by the current Rust-native framed fact path.
pub const FRAMED_FACT_MSG_TYPE: u8 = trackone_constants::FRAMED_FACT_MSG_TYPE;

/// Gateway admission policy for ciphertext bytes, excluding the AEAD tag.
pub const MAX_FRAME_CIPHERTEXT_BYTES: usize = 256;

/// AEAD-wrapped fact as seen on the framed wire path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptedFrame<const N: usize> {
    pub pod_id: PodId,
    pub fc: FrameCounter,
    pub nonce: [u8; AEAD_NONCE_LEN],
    pub ciphertext: HVec<u8, N>,
}

/// Error returned when the nonce prefix does not match the framed header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramedNonceError {
    NonceLength,
    Salt8Length,
    SaltMismatch,
    FrameCounterMismatch,
}

/// Error returned when a postcard `Fact` conflicts with its frame header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramedFactBindingError {
    PodIdMismatch,
    FrameCounterMismatch,
}

/// Rejection reasons produced by framed admission and replay checks.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RejectReason {
    Salt8Length,
    CkUpLength,
    NonceLength,
    TagLength,
    EmptyCiphertext,
    CiphertextTooLarge,
    NonceSaltMismatch,
    NonceFcMismatch,
    UnsupportedFlags,
    DecryptFailed,
    InvalidIngestProfile,
    PostcardPodIdMismatch,
    PostcardFcMismatch,
    Duplicate,
    OutOfWindow,
}

impl RejectReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Salt8Length => "salt8_length",
            Self::CkUpLength => "ck_up_length",
            Self::NonceLength => "nonce_length",
            Self::TagLength => "tag_length",
            Self::EmptyCiphertext => "empty_ciphertext",
            Self::CiphertextTooLarge => "ciphertext_too_large",
            Self::NonceSaltMismatch => "nonce_salt_mismatch",
            Self::NonceFcMismatch => "nonce_fc_mismatch",
            Self::UnsupportedFlags => "unsupported_flags",
            Self::DecryptFailed => "decrypt_failed",
            Self::InvalidIngestProfile => "invalid_ingest_profile",
            Self::PostcardPodIdMismatch => "postcard_pod_id_mismatch",
            Self::PostcardFcMismatch => "postcard_fc_mismatch",
            Self::Duplicate => "duplicate",
            Self::OutOfWindow => "out_of_window",
        }
    }
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Framed header fields that participate in admission.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub dev_id: u16,
    pub msg_type: u8,
    pub fc: u32,
    pub flags: u8,
}

/// Borrowed framed input as received by a gateway.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FrameInput<'a> {
    pub header: FrameHeader,
    pub nonce: &'a [u8],
    pub ct: &'a [u8],
    pub tag: &'a [u8],
}

/// Borrowed provisioned material for one admitted device.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DeviceMaterial<'a> {
    pub salt8: &'a [u8],
    pub ck_up: &'a [u8],
}

/// A framed input accepted into the Rust-native postcard fact plane.
#[derive(Clone, Debug, PartialEq)]
pub struct AcceptedFrame {
    pub header: FrameHeader,
    pub fact: Fact,
}

/// Error returned while generating deterministic framed fixtures.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FixtureError {
    Reject(RejectReason),
    EncodeFailed,
    EncryptFailed,
}

/// Accept omitted profile for backward-compatible callers, or the explicit
/// Rust postcard profile. Any other profile name is unsupported.
pub fn is_supported_ingest_profile(raw: Option<&str>) -> bool {
    matches!(raw, None | Some(INGEST_PROFILE_RUST_POSTCARD_V1))
}

pub fn validate_ingest_profile(raw: Option<&str>) -> Result<(), RejectReason> {
    if is_supported_ingest_profile(raw) {
        Ok(())
    } else {
        Err(RejectReason::InvalidIngestProfile)
    }
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

/// Encode a canonical `Fact` under the Rust postcard framed plaintext profile.
pub fn encode_fact_postcard<'a>(fact: &Fact, out: &'a mut [u8]) -> CoreResult<&'a [u8]> {
    postcard::to_slice(fact, out)
        .map(|used| &*used)
        .map_err(|_| Error::SerializeError)
}

/// Encode a canonical `Fact` into a fixed-size scratch buffer.
pub fn encode_fact_postcard_buf(fact: &Fact) -> CoreResult<([u8; MAX_FACT_LEN], usize)> {
    let mut out = [0u8; MAX_FACT_LEN];
    let used = encode_fact_postcard(fact, &mut out)?.len();
    Ok((out, used))
}

/// Decode a canonical `Fact` under the Rust postcard framed plaintext profile.
pub fn decode_fact_postcard(bytes: &[u8]) -> CoreResult<Fact> {
    postcard::from_bytes(bytes).map_err(|_| Error::DeserializeError)
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

/// Helper to construct a `Fact`.
pub fn make_fact(pod_id: PodId, fc: FrameCounter, payload: FactPayload) -> Fact {
    let kind = match &payload {
        FactPayload::Env(_) => FactKind::Env,
        FactPayload::Custom(_) => FactKind::Custom,
    };

    Fact {
        pod_id,
        fc,
        ingest_time: 0,
        pod_time: None,
        kind,
        payload,
    }
}

/// Serialize + encrypt a `Fact` into an `EncryptedFrame`.
pub fn encrypt_fact<const N: usize, C>(
    cipher: &C,
    nonce: [u8; AEAD_NONCE_LEN],
    fact: &Fact,
) -> CoreResult<EncryptedFrame<N>>
where
    C: AeadEncrypt<Error = Error>,
{
    let mut serialized = [0u8; MAX_FACT_LEN];
    let used = encode_fact_postcard(fact, &mut serialized)?;
    let aad = framed_aad_for_pod(fact.pod_id, 1, 0); // msg_type 1 = fact frame

    let mut ciphertext_buf = [0u8; N];
    if ciphertext_buf.len() < used.len() + AEAD_TAG_LEN {
        return Err(Error::CiphertextTooLarge);
    }

    let ct_len = cipher
        .encrypt(&nonce, &aad, used, &mut ciphertext_buf)
        .map_err(|_| Error::CryptoError)?;

    let mut ciphertext = HVec::<u8, N>::new();
    ciphertext
        .extend_from_slice(&ciphertext_buf[..ct_len])
        .map_err(|_| Error::CiphertextTooLarge)?;

    Ok(EncryptedFrame {
        pod_id: fact.pod_id,
        fc: fact.fc,
        nonce,
        ciphertext,
    })
}

/// Decrypt + deserialize an `EncryptedFrame` back into a `Fact`.
pub fn decrypt_fact<const N: usize, C>(cipher: &C, frame: &EncryptedFrame<N>) -> CoreResult<Fact>
where
    C: AeadDecrypt<Error = Error>,
{
    let aad = framed_aad_for_pod(frame.pod_id, 1, 0); // msg_type 1 = fact frame
    let mut plaintext_buf = [0u8; MAX_FACT_LEN];

    if plaintext_buf.len() < frame.ciphertext.len() {
        return Err(Error::DeserializeError);
    }

    let pt_len = cipher
        .decrypt(
            &frame.nonce,
            &aad,
            frame.ciphertext.as_slice(),
            &mut plaintext_buf,
        )
        .map_err(|_| Error::CryptoError)?;

    decode_fact_postcard(&plaintext_buf[..pt_len])
}

#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayWindow {
    window_size: u64,
    highest_fc_seen: Option<u64>,
    seen: BTreeSet<u64>,
}

#[cfg(feature = "std")]
impl ReplayWindow {
    pub fn new(window_size: u64, highest_fc_seen: Option<u64>) -> Self {
        Self {
            window_size,
            highest_fc_seen,
            seen: BTreeSet::new(),
        }
    }

    pub fn window_size(&self) -> u64 {
        self.window_size
    }

    pub fn highest_fc_seen(&self) -> Option<u64> {
        self.highest_fc_seen
    }

    pub fn seen_fcs(&self) -> Vec<u64> {
        self.seen.iter().copied().collect()
    }

    pub fn check_and_update(&mut self, fc: u64) -> Result<(), RejectReason> {
        let Some(highest) = self.highest_fc_seen else {
            self.highest_fc_seen = Some(fc);
            self.seen.insert(fc);
            return Ok(());
        };

        if self.seen.contains(&fc) {
            return Err(RejectReason::Duplicate);
        }

        if fc < highest && (highest - fc) > self.window_size {
            return Err(RejectReason::OutOfWindow);
        }

        if fc > highest && (fc - highest) > self.window_size {
            return Err(RejectReason::OutOfWindow);
        }

        if fc > highest {
            self.highest_fc_seen = Some(fc);
            let lower_bound = fc.saturating_sub(self.window_size);
            self.seen.retain(|seen_fc| *seen_fc >= lower_bound);
        }

        self.seen.insert(fc);
        Ok(())
    }
}

#[cfg(feature = "xchacha")]
/// Framed fixture material emitted by the Rust postcard profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramedFixture {
    pub dev_id: u16,
    pub msg_type: u8,
    pub fc: u32,
    pub flags: u8,
    pub nonce: [u8; AEAD_NONCE_LEN],
    pub ct: Vec<u8>,
    pub tag: Vec<u8>,
}

#[cfg(feature = "xchacha")]
pub fn validate_and_decrypt(
    frame: FrameInput<'_>,
    device: DeviceMaterial<'_>,
) -> Result<AcceptedFrame, RejectReason> {
    if frame.tag.len() != AEAD_TAG_LEN {
        return Err(RejectReason::TagLength);
    }
    if device.ck_up.len() != 32 {
        return Err(RejectReason::CkUpLength);
    }
    if frame.ct.is_empty() {
        return Err(RejectReason::EmptyCiphertext);
    }
    if frame.ct.len() > MAX_FRAME_CIPHERTEXT_BYTES {
        return Err(RejectReason::CiphertextTooLarge);
    }
    if frame.header.flags != 0 {
        return Err(RejectReason::UnsupportedFlags);
    }
    validate_nonce_prefix(frame.nonce, device.salt8, frame.header.fc)
        .map_err(map_framed_nonce_error)?;

    let aad = framed_aad(
        frame.header.dev_id,
        frame.header.msg_type,
        frame.header.flags,
    );
    let mut combined = Vec::with_capacity(frame.ct.len() + frame.tag.len());
    combined.extend_from_slice(frame.ct);
    combined.extend_from_slice(frame.tag);

    let cipher =
        XChaCha20Poly1305::new_from_slice(device.ck_up).map_err(|_| RejectReason::CkUpLength)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(frame.nonce),
            Payload {
                msg: combined.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| RejectReason::DecryptFailed)?;

    let fact = decode_fact_postcard(&plaintext).map_err(|_| RejectReason::DecryptFailed)?;
    validate_fact_binding(&fact, frame.header.dev_id, frame.header.fc).map_err(|reason| {
        match reason {
            FramedFactBindingError::PodIdMismatch => RejectReason::PostcardPodIdMismatch,
            FramedFactBindingError::FrameCounterMismatch => RejectReason::PostcardFcMismatch,
        }
    })?;

    Ok(AcceptedFrame {
        header: frame.header,
        fact,
    })
}

#[cfg(feature = "xchacha")]
pub fn emit_fixture(
    dev_id: u16,
    fc: u32,
    device: DeviceMaterial<'_>,
    msg_type: u8,
    flags: u8,
    pod_time: Option<i64>,
) -> Result<FramedFixture, FixtureError> {
    if device.salt8.len() != 8 {
        return Err(FixtureError::Reject(RejectReason::Salt8Length));
    }
    if device.ck_up.len() != 32 {
        return Err(FixtureError::Reject(RejectReason::CkUpLength));
    }
    if flags != 0 {
        return Err(FixtureError::Reject(RejectReason::UnsupportedFlags));
    }

    let observed_at = pod_time.unwrap_or(1_700_000_000 + i64::from(fc));
    let fact = Fact {
        pod_id: PodId::from(u32::from(dev_id)),
        fc: u64::from(fc),
        ingest_time: 0,
        pod_time: Some(observed_at),
        kind: FactKind::Env,
        payload: FactPayload::Env(EnvFact::instant(
            SampleType::AmbientAirTemperature,
            observed_at,
            20.0,
        )),
    };

    let mut plaintext = [0u8; MAX_FACT_LEN];
    let used = encode_fact_postcard(&fact, &mut plaintext)
        .map_err(|_| FixtureError::EncodeFailed)?
        .len();

    let salt8: [u8; 8] = device.salt8.try_into().expect("checked salt8 length");
    let tail = ((u64::from(dev_id) << 48) | u64::from(fc)).to_be_bytes();
    let nonce = framed_nonce(salt8, fc, tail);
    let aad = framed_aad(dev_id, msg_type, flags);
    let cipher = XChaCha20Poly1305::new_from_slice(device.ck_up)
        .map_err(|_| FixtureError::Reject(RejectReason::CkUpLength))?;
    let combined = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext[..used],
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| FixtureError::EncryptFailed)?;
    let split_at = combined.len().saturating_sub(AEAD_TAG_LEN);
    let (ct, tag) = combined.split_at(split_at);

    Ok(FramedFixture {
        dev_id,
        msg_type,
        fc,
        flags,
        nonce,
        ct: ct.to_vec(),
        tag: tag.to_vec(),
    })
}

#[cfg(feature = "xchacha")]
fn map_framed_nonce_error(reason: FramedNonceError) -> RejectReason {
    match reason {
        FramedNonceError::NonceLength => RejectReason::NonceLength,
        FramedNonceError::Salt8Length => RejectReason::Salt8Length,
        FramedNonceError::SaltMismatch => RejectReason::NonceSaltMismatch,
        FramedNonceError::FrameCounterMismatch => RejectReason::NonceFcMismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trackone_core::crypto::dummy::DummyAead;
    use trackone_core::crypto::{AeadDecrypt, AeadEncrypt};
    use trackone_core::{EnvFact, SampleType};

    fn sample_fact() -> Fact {
        Fact {
            pod_id: PodId::from(0x1234u32),
            fc: 7,
            ingest_time: 0,
            pod_time: Some(1_700_000_000),
            kind: FactKind::Env,
            payload: FactPayload::Env(EnvFact::instant(
                SampleType::AmbientAirTemperature,
                1_700_000_000,
                21.5,
            )),
        }
    }

    struct InspectAead {
        expected_aad: [u8; 4],
    }

    impl InspectAead {
        const fn new(expected_aad: [u8; 4]) -> Self {
            Self { expected_aad }
        }
    }

    impl AeadEncrypt for InspectAead {
        type Error = Error;

        fn encrypt(
            &self,
            _nonce: &[u8],
            aad: &[u8],
            plaintext: &[u8],
            out: &mut [u8],
        ) -> Result<usize, Self::Error> {
            assert_eq!(aad, self.expected_aad);
            out[..plaintext.len()].copy_from_slice(plaintext);
            Ok(plaintext.len())
        }
    }

    impl AeadDecrypt for InspectAead {
        type Error = Error;

        fn decrypt(
            &self,
            _nonce: &[u8],
            aad: &[u8],
            ciphertext: &[u8],
            out: &mut [u8],
        ) -> Result<usize, Self::Error> {
            assert_eq!(aad, self.expected_aad);
            out[..ciphertext.len()].copy_from_slice(ciphertext);
            Ok(ciphertext.len())
        }
    }

    #[test]
    fn profile_accepts_omitted_or_rust_postcard_only() {
        assert!(is_supported_ingest_profile(None));
        assert!(is_supported_ingest_profile(Some(
            INGEST_PROFILE_RUST_POSTCARD_V1
        )));
        assert!(!is_supported_ingest_profile(Some("python-tlv-legacy")));
    }

    #[test]
    fn framed_aad_uses_legacy_dev_id_msg_type_and_flags() {
        assert_eq!(
            framed_aad_for_pod(PodId::from(0x1234u32), 1, 0),
            [0x12, 0x34, 1, 0]
        );
    }

    #[test]
    fn framed_nonce_uses_salt_counter_and_tail() {
        let nonce = framed_nonce([0x11; 8], 7, [0x22; 8]);
        assert_eq!(&nonce[..8], &[0x11; 8]);
        assert_eq!(
            u64::from_be_bytes(nonce[8..16].try_into().expect("counter bytes")),
            7
        );
        assert_eq!(&nonce[16..24], &[0x22; 8]);
        assert_eq!(validate_nonce_prefix(&nonce, &[0x11; 8], 7), Ok(()));
    }

    #[test]
    fn nonce_validation_rejects_mismatches() {
        let nonce = framed_nonce([0x11; 8], 7, [0x22; 8]);
        assert_eq!(
            validate_nonce_prefix(&nonce[..23], &[0x11; 8], 7),
            Err(FramedNonceError::NonceLength)
        );
        assert_eq!(
            validate_nonce_prefix(&nonce, &[0x11; 7], 7),
            Err(FramedNonceError::Salt8Length)
        );
        assert_eq!(
            validate_nonce_prefix(&nonce, &[0x12; 8], 7),
            Err(FramedNonceError::SaltMismatch)
        );
        assert_eq!(
            validate_nonce_prefix(&nonce, &[0x11; 8], 8),
            Err(FramedNonceError::FrameCounterMismatch)
        );
    }

    #[test]
    fn postcard_fact_roundtrips_and_validates_frame_binding() {
        let fact = sample_fact();
        let (encoded, used) = encode_fact_postcard_buf(&fact).expect("encode");
        let decoded = decode_fact_postcard(&encoded[..used]).expect("decode");

        assert_eq!(decoded, fact);
        assert_eq!(validate_fact_binding(&decoded, 0x1234, 7), Ok(()));
        assert_eq!(
            validate_fact_binding(&decoded, 0x5678, 7),
            Err(FramedFactBindingError::PodIdMismatch)
        );
        assert_eq!(
            validate_fact_binding(&decoded, 0x1234, 8),
            Err(FramedFactBindingError::FrameCounterMismatch)
        );
    }

    #[test]
    fn fact_encrypt_decrypt_roundtrip() {
        static KEY: &[u8] = b"frame-test-key";
        let cipher = DummyAead::new(KEY);
        let fact = make_fact(
            PodId::from(5u32),
            1,
            FactPayload::Env(EnvFact::instant(
                SampleType::AmbientAirTemperature,
                1_700_000_000,
                20.0,
            )),
        );

        let nonce = [0u8; AEAD_NONCE_LEN];
        let enc = encrypt_fact::<128, _>(&cipher, nonce, &fact).expect("encrypt fact");
        let dec = decrypt_fact::<128, _>(&cipher, &enc).expect("decrypt fact");

        assert_eq!(fact, dec);
    }

    #[test]
    fn fact_encrypt_decrypt_use_dev_id_msg_type_flags_aad() {
        let cipher = InspectAead::new([0x12, 0x34, 1, 0]);
        let fact = make_fact(
            PodId::from(0x1234u32),
            1,
            FactPayload::Env(EnvFact::instant(
                SampleType::AmbientAirTemperature,
                1_700_000_000,
                20.0,
            )),
        );

        let nonce = [0u8; AEAD_NONCE_LEN];
        let enc = encrypt_fact::<128, _>(&cipher, nonce, &fact).expect("encrypt fact");
        let dec = decrypt_fact::<128, _>(&cipher, &enc).expect("decrypt fact");

        assert_eq!(fact, dec);
    }

    #[test]
    fn fact_serialization_within_max_len() {
        let fact = make_fact(
            PodId::from(99u32),
            12345,
            FactPayload::Env(EnvFact::summary(
                SampleType::AmbientRelativeHumidity,
                1_700_000_000,
                1_700_003_600,
                50.0,
                70.0,
                60.0,
                144,
            )),
        );

        let mut buf = [0u8; MAX_FACT_LEN];
        let used = postcard::to_slice(&fact, &mut buf).expect("serialize fact");
        assert!(
            used.len() <= MAX_FACT_LEN,
            "Fact serialized length {} > MAX_FACT_LEN",
            used.len()
        );
    }

    #[test]
    fn encrypt_fact_ciphertext_buffer_too_small() {
        static KEY: &[u8] = b"test-key";
        let cipher = DummyAead::new(KEY);
        let fact = make_fact(
            PodId::from(1u32),
            1,
            FactPayload::Env(EnvFact::instant(
                SampleType::AmbientAirTemperature,
                1_700_000_000,
                20.0,
            )),
        );

        let result = encrypt_fact::<1, _>(&cipher, [0u8; AEAD_NONCE_LEN], &fact);
        assert!(result.is_err(), "should fail with small buffer");
    }

    #[test]
    fn decrypt_fact_corrupted_ciphertext() {
        static KEY: &[u8] = b"test-key";
        let cipher = DummyAead::new(KEY);
        let fact = make_fact(
            PodId::from(5u32),
            1,
            FactPayload::Env(EnvFact::instant(
                SampleType::AmbientAirTemperature,
                1_700_000_000,
                20.0,
            )),
        );

        let mut enc =
            encrypt_fact::<128, _>(&cipher, [0u8; AEAD_NONCE_LEN], &fact).expect("encrypt fact");
        if !enc.ciphertext.is_empty() {
            enc.ciphertext[0] ^= 0xFF;
        }

        let result = decrypt_fact::<128, _>(&cipher, &enc);
        if let Ok(decoded) = result {
            assert_ne!(decoded, fact);
        }
    }

    #[test]
    fn decrypt_fact_buffer_size_mismatch() {
        let cipher = DummyAead::new(b"test-key");
        let mut large_ciphertext = HVec::<u8, 512>::new();
        for i in 0..300 {
            large_ciphertext.push((i % 256) as u8).unwrap();
        }

        let frame = EncryptedFrame::<512> {
            pod_id: PodId::from(42u32),
            fc: 100,
            nonce: [0u8; AEAD_NONCE_LEN],
            ciphertext: large_ciphertext,
        };

        let result = decrypt_fact::<512, _>(&cipher, &frame);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::DeserializeError);
    }

    #[cfg(feature = "std")]
    #[test]
    fn replay_window_accepts_and_prunes() {
        let mut state = ReplayWindow::new(3, Some(1));

        state.check_and_update(2).expect("fc=2");
        state.check_and_update(3).expect("fc=3");
        state.check_and_update(4).expect("fc=4");
        state.check_and_update(5).expect("fc=5");

        assert_eq!(state.highest_fc_seen(), Some(5));
        assert_eq!(state.seen_fcs(), vec![2, 3, 4, 5]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn replay_window_rejects_duplicates_and_out_of_window() {
        let mut state = ReplayWindow::new(4, Some(10));

        state.check_and_update(10).expect("first observation");
        assert_eq!(
            state.check_and_update(10).unwrap_err(),
            RejectReason::Duplicate
        );
        assert_eq!(
            state.check_and_update(5).unwrap_err(),
            RejectReason::OutOfWindow
        );
        assert_eq!(
            state.check_and_update(20).unwrap_err(),
            RejectReason::OutOfWindow
        );
    }

    #[cfg(feature = "xchacha")]
    fn sample_frame_and_device() -> (FrameInput<'static>, [u8; 8], [u8; 32]) {
        let key = [7u8; 32];
        let salt8 = *b"salt0001";
        let fact = Fact {
            pod_id: PodId::from(1u32),
            fc: 3,
            ingest_time: 0,
            pod_time: Some(1_700_000_000),
            kind: FactKind::Env,
            payload: FactPayload::Env(EnvFact::instant(
                SampleType::AmbientAirTemperature,
                1_700_000_000,
                21.5,
            )),
        };
        let (plaintext, used) = encode_fact_postcard_buf(&fact).expect("encode");
        let nonce = framed_nonce(salt8, 3, *b"rand0001");
        let aad = framed_aad(1, 1, 0);
        let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("cipher");
        let combined = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext[..used],
                    aad: aad.as_slice(),
                },
            )
            .expect("encrypt");
        let (ct, tag) = combined.split_at(combined.len() - AEAD_TAG_LEN);

        let frame = FrameInput {
            header: FrameHeader {
                dev_id: 1,
                msg_type: 1,
                fc: 3,
                flags: 0,
            },
            nonce: Box::leak(Box::new(nonce)),
            ct: Box::leak(ct.to_vec().into_boxed_slice()),
            tag: Box::leak(tag.to_vec().into_boxed_slice()),
        };
        (frame, salt8, key)
    }

    #[cfg(feature = "xchacha")]
    #[test]
    fn validate_and_decrypt_succeeds_for_valid_frame() {
        let (frame, salt8, key) = sample_frame_and_device();
        let accepted = validate_and_decrypt(
            frame,
            DeviceMaterial {
                salt8: &salt8,
                ck_up: &key,
            },
        )
        .expect("postcard fact");

        assert_eq!(accepted.fact.pod_id, PodId::from(1u32));
        assert_eq!(accepted.fact.fc, 3);
        assert_eq!(accepted.fact.kind, FactKind::Env);
    }

    #[cfg(feature = "xchacha")]
    #[test]
    fn validate_and_decrypt_rejects_nonzero_flags() {
        let (frame, salt8, key) = sample_frame_and_device();
        let err = validate_and_decrypt(
            FrameInput {
                header: FrameHeader {
                    flags: 1,
                    ..frame.header
                },
                ..frame
            },
            DeviceMaterial {
                salt8: &salt8,
                ck_up: &key,
            },
        )
        .unwrap_err();
        assert_eq!(err, RejectReason::UnsupportedFlags);
    }

    #[cfg(feature = "xchacha")]
    #[test]
    fn rust_postcard_profile_rejects_legacy_tlv_plaintext() {
        let key = [7u8; 32];
        let salt8 = *b"salt0001";
        let plaintext = [0x01, 4, 0, 0, 0, 3, 0x03, 2, 0x09, 0xE0];
        let nonce = framed_nonce(salt8, 3, *b"rand0001");
        let aad = framed_aad(1, 1, 0);
        let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("cipher");
        let combined = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: aad.as_slice(),
                },
            )
            .expect("encrypt");
        let (ct, tag) = combined.split_at(combined.len() - AEAD_TAG_LEN);

        let frame = FrameInput {
            header: FrameHeader {
                dev_id: 1,
                msg_type: 1,
                fc: 3,
                flags: 0,
            },
            nonce: &nonce,
            ct,
            tag,
        };
        let err = validate_and_decrypt(
            frame,
            DeviceMaterial {
                salt8: &salt8,
                ck_up: &key,
            },
        )
        .unwrap_err();
        assert_eq!(err, RejectReason::DecryptFailed);
    }

    #[cfg(feature = "xchacha")]
    #[test]
    fn postcard_fact_counter_must_match_frame_counter() {
        let key = [7u8; 32];
        let salt8 = *b"salt0001";
        let mut fact = sample_fact();
        fact.pod_id = PodId::from(1u32);
        fact.fc = 4;
        let (plaintext, used) = encode_fact_postcard_buf(&fact).expect("encode");
        let nonce = framed_nonce(salt8, 3, *b"rand0001");
        let aad = framed_aad(1, 1, 0);
        let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("cipher");
        let combined = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext[..used],
                    aad: aad.as_slice(),
                },
            )
            .expect("encrypt");
        let (ct, tag) = combined.split_at(combined.len() - AEAD_TAG_LEN);

        let err = validate_and_decrypt(
            FrameInput {
                header: FrameHeader {
                    dev_id: 1,
                    msg_type: 1,
                    fc: 3,
                    flags: 0,
                },
                nonce: &nonce,
                ct,
                tag,
            },
            DeviceMaterial {
                salt8: &salt8,
                ck_up: &key,
            },
        )
        .unwrap_err();
        assert_eq!(err, RejectReason::PostcardFcMismatch);
    }

    #[cfg(feature = "xchacha")]
    #[test]
    fn validate_and_decrypt_rejects_oversized_ciphertext() {
        let (frame, salt8, key) = sample_frame_and_device();
        let oversized = vec![0u8; MAX_FRAME_CIPHERTEXT_BYTES + 1];
        let err = validate_and_decrypt(
            FrameInput {
                ct: &oversized,
                ..frame
            },
            DeviceMaterial {
                salt8: &salt8,
                ck_up: &key,
            },
        )
        .unwrap_err();
        assert_eq!(err, RejectReason::CiphertextTooLarge);
    }

    #[cfg(feature = "xchacha")]
    #[test]
    fn emit_fixture_produces_admissible_frame() {
        let salt8 = *b"salt0001";
        let key = [7u8; 32];
        let fixture = emit_fixture(
            1,
            3,
            DeviceMaterial {
                salt8: &salt8,
                ck_up: &key,
            },
            1,
            0,
            Some(1_700_000_000),
        )
        .expect("fixture");

        let accepted = validate_and_decrypt(
            FrameInput {
                header: FrameHeader {
                    dev_id: fixture.dev_id,
                    msg_type: fixture.msg_type,
                    fc: fixture.fc,
                    flags: fixture.flags,
                },
                nonce: &fixture.nonce,
                ct: &fixture.ct,
                tag: &fixture.tag,
            },
            DeviceMaterial {
                salt8: &salt8,
                ck_up: &key,
            },
        )
        .expect("fixture decrypt");

        assert_eq!(accepted.fact.pod_id, PodId::from(1u32));
        assert_eq!(accepted.fact.fc, 3);
    }

    #[cfg(feature = "xchacha")]
    #[test]
    fn emit_fixture_rejects_nonzero_flags() {
        let salt8 = *b"salt0001";
        let key = [7u8; 32];
        let err = emit_fixture(
            1,
            3,
            DeviceMaterial {
                salt8: &salt8,
                ck_up: &key,
            },
            1,
            1,
            Some(1_700_000_000),
        )
        .unwrap_err();
        assert_eq!(err, FixtureError::Reject(RejectReason::UnsupportedFlags));
    }
}
