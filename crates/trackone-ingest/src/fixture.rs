//! Deterministic framed fixture emission.

use crate::RejectReason;

/// Error returned while generating deterministic framed fixtures.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FixtureError {
    Reject(RejectReason),
    EncodeFailed,
    EncryptFailed,
}

#[cfg(feature = "xchacha")]
use crate::{DeviceMaterial, encode_fact_postcard, framed_aad, framed_nonce};
#[cfg(feature = "xchacha")]
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
#[cfg(feature = "xchacha")]
use std::vec::Vec;
#[cfg(feature = "xchacha")]
use trackone_core::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, EnvFact, Fact, FactKind, FactPayload, MAX_FACT_LEN, PodId,
    SampleType,
};

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
    let nonce_ref = (&nonce[..]).try_into().expect("checked nonce length");
    let combined = cipher
        .encrypt(
            nonce_ref,
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
