//! Bounded frame types, postcard encoding, and generic AEAD helpers.

use heapless::Vec as HVec;
use serde::{Deserialize, Serialize};
use trackone_core::crypto::{AeadDecrypt, AeadEncrypt};
use trackone_core::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, CoreResult, Error, Fact, FactKind, FactPayload, FrameCounter,
    MAX_FACT_LEN, PodId,
};

use crate::{framed_aad_for_pod, validate_fact_binding};

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
///
/// `expected_pod_id` is authorization state from the provisioning trust root.
/// It must never be derived from an incoming frame or decrypted payload. The
/// legacy 16-bit frame `dev_id` is only a routing hint; admission binds the
/// decrypted fact to this full 64-bit identity.
///
/// # Example
///
/// ```
/// use trackone_core::PodId;
/// use trackone_ingest::DeviceMaterial;
///
/// let provisioned_pod_id = PodId::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x12, 0x34]);
/// let salt8 = [0x11; 8];
/// let ck_up = [0x22; 32];
/// let material = DeviceMaterial::new(provisioned_pod_id, &salt8, &ck_up);
///
/// assert_eq!(material.expected_pod_id(), provisioned_pod_id);
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DeviceMaterial<'a> {
    expected_pod_id: PodId,
    salt8: &'a [u8],
    ck_up: &'a [u8],
}

impl<'a> DeviceMaterial<'a> {
    /// Construct material loaded from the authoritative provisioning record.
    pub const fn new(expected_pod_id: PodId, salt8: &'a [u8], ck_up: &'a [u8]) -> Self {
        Self {
            expected_pod_id,
            salt8,
            ck_up,
        }
    }

    /// Full canonical identity authorized to use this key material.
    pub const fn expected_pod_id(self) -> PodId {
        self.expected_pod_id
    }

    /// Provisioned nonce salt.
    pub const fn salt8(self) -> &'a [u8] {
        self.salt8
    }

    /// Provisioned uplink AEAD key.
    pub const fn ck_up(self) -> &'a [u8] {
        self.ck_up
    }
}

/// A framed input accepted into the Rust-native postcard fact plane.
#[derive(Clone, Debug, PartialEq)]
pub struct AcceptedFrame {
    pub header: FrameHeader,
    pub fact: Fact,
}

/// Encode a canonical `Fact` under the Rust postcard framed plaintext profile.
pub fn encode_fact_postcard<'a>(fact: &Fact, out: &'a mut [u8]) -> CoreResult<&'a [u8]> {
    fact.validate().map_err(Error::InvalidFact)?;
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
    let fact: Fact = postcard::from_bytes(bytes).map_err(|_| Error::DeserializeError)?;
    fact.validate().map_err(Error::InvalidFact)?;
    Ok(fact)
}

/// Helper to construct a `Fact`.
pub fn make_fact(pod_id: PodId, fc: FrameCounter, payload: FactPayload) -> CoreResult<Fact> {
    let kind = match &payload {
        FactPayload::Env(_) => FactKind::Env,
        FactPayload::Custom(_) => FactKind::Custom,
    };

    let fact = Fact {
        pod_id,
        fc,
        ingest_time: 0,
        pod_time: None,
        kind,
        payload,
    };
    fact.validate().map_err(Error::InvalidFact)?;
    Ok(fact)
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

/// Decrypt and bind an `EncryptedFrame` to a provisioned device identity.
///
/// `expected_pod_id` must come from the provisioning trust root, never from
/// `frame.pod_id`. Both the envelope and decoded fact must match it exactly.
pub fn decrypt_fact<const N: usize, C>(
    cipher: &C,
    frame: &EncryptedFrame<N>,
    expected_pod_id: PodId,
) -> CoreResult<Fact>
where
    C: AeadDecrypt<Error = Error>,
{
    if frame.pod_id != expected_pod_id {
        return Err(Error::CryptoError);
    }
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

    let fact = decode_fact_postcard(&plaintext_buf[..pt_len])?;
    validate_fact_binding(&fact, expected_pod_id, frame.fc).map_err(|_| Error::CryptoError)?;
    Ok(fact)
}
