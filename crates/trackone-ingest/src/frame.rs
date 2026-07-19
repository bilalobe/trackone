//! Bounded frame types, postcard encoding, and generic AEAD helpers.

use heapless::Vec as HVec;
use serde::{Deserialize, Serialize};
use trackone_core::crypto::{AeadDecrypt, AeadEncrypt};
use trackone_core::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, CoreResult, Error, Fact, FactKind, FactPayload, FrameCounter,
    MAX_FACT_LEN, PodId,
};

use crate::framed_aad_for_pod;

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
