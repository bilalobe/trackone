//! Frame construction and encryption helpers.
//!
//! This module is `no_std`-friendly and uses `heapless` for bounded
//! buffers. Concrete AEAD implementations are provided by callers via
//! the `AeadEncrypt`/`AeadDecrypt` traits.

use heapless::Vec;

use crate::crypto::{AeadDecrypt, AeadEncrypt};
use crate::types::{CoreResult, EncryptedFrame, Error, Fact};
use trackone_constants::MAX_FACT_LEN;

/// Helper to construct a `Fact`.
pub fn make_fact(
    pod_id: crate::types::PodId,
    fc: crate::types::FrameCounter,
    payload: crate::types::FactPayload,
) -> Fact {
    Fact {
        pod_id,
        fc,
        payload,
    }
}

/// Serialize + encrypt a `Fact` into an `EncryptedFrame`.
///
/// Wire format:
/// - serialize `Fact` with postcard into a fixed internal buffer (size = MAX_FACT_LEN)
/// - encrypt serialized bytes with AEAD
pub fn encrypt_fact<const N: usize, C>(
    cipher: &C,
    nonce: [u8; 24],
    fact: &Fact,
) -> CoreResult<EncryptedFrame<N>>
where
    C: AeadEncrypt<Error = Error>,
{
    // Serialize fact into a fixed-size buffer. MAX_FACT_LEN is a policy knob.
    let mut serialized = [0u8; MAX_FACT_LEN];
    let used = postcard::to_slice(fact, &mut serialized).map_err(|_| Error::SerializeError)?;

    let aad = &[]; // Future: include header metadata as AAD.

    let mut ciphertext_buf = [0u8; N];
    if ciphertext_buf.len() < used.len() {
        return Err(Error::SerializeBufferTooSmall);
    }

    let ct_len = cipher
        .encrypt(&nonce, aad, used, &mut ciphertext_buf)
        .map_err(|_| Error::CryptoError)?;

    let mut ciphertext_vec: Vec<u8, N> = Vec::new();
    ciphertext_vec
        .extend_from_slice(&ciphertext_buf[..ct_len])
        .map_err(|_| Error::CiphertextTooLarge)?;

    Ok(EncryptedFrame {
        pod_id: fact.pod_id,
        fc: fact.fc,
        nonce,
        ciphertext: ciphertext_vec,
    })
}

/// Decrypt + deserialize an `EncryptedFrame` back into a `Fact`.
pub fn decrypt_fact<const N: usize, C>(cipher: &C, frame: &EncryptedFrame<N>) -> CoreResult<Fact>
where
    C: AeadDecrypt<Error = Error>,
{
    let aad = &[];
    let mut plaintext_buf = [0u8; MAX_FACT_LEN];

    if plaintext_buf.len() < frame.ciphertext.len() {
        return Err(Error::SerializeBufferTooSmall);
    }

    let pt_len = cipher
        .decrypt(
            &frame.nonce,
            aad,
            frame.ciphertext.as_slice(),
            &mut plaintext_buf,
        )
        .map_err(|_| Error::CryptoError)?;

    let fact: Fact =
        postcard::from_bytes(&plaintext_buf[..pt_len]).map_err(|_| Error::DeserializeError)?;
    Ok(fact)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::dummy::DummyAead;
    use crate::types::{FactPayload, PodId};

    #[test]
    fn fact_encrypt_decrypt_roundtrip() {
        static KEY: &[u8] = b"frame-test-key";
        let cipher = DummyAead::new(KEY);

        let fact = make_fact(
            PodId(5),
            1,
            FactPayload::Temperature {
                milli_celsius: 20_000,
            },
        );

        let nonce = [0u8; 24];
        let enc = encrypt_fact::<128, _>(&cipher, nonce, &fact).expect("encrypt fact");
        let dec = decrypt_fact::<128, _>(&cipher, &enc).expect("decrypt fact");

        assert_eq!(fact, dec);
    }

    #[test]
    fn fact_serialization_within_max_len() {
        // Build a representative fact and ensure postcard serialization fits within MAX_FACT_LEN
        let fact = make_fact(PodId(99), 12345, FactPayload::Battery { millivolts: 3700 });

        let mut buf = [0u8; MAX_FACT_LEN];
        let used = postcard::to_slice(&fact, &mut buf).expect("serialize fact");
        assert!(
            used.len() <= MAX_FACT_LEN,
            "Fact serialized length {} > MAX_FACT_LEN",
            used.len()
        );
    }
}
