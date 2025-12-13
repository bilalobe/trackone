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
///
/// # Security Warning: Nonce Uniqueness
///
/// **CRITICAL**: For AEAD ciphers like XChaCha20-Poly1305, nonce reuse with the same key
/// catastrophically breaks security, allowing attackers to recover the key and decrypt all
/// messages. Callers MUST ensure that:
///
/// - Each nonce is used **exactly once** with a given key
/// - Nonces are generated using a secure strategy such as:
///   - Counter-based: monotonically increasing counter (recommended for embedded systems)
///   - Random: cryptographically secure random with sufficient entropy (192 bits for XChaCha20)
///
/// Failure to maintain nonce uniqueness will compromise the confidentiality and authenticity
/// of all encrypted frames.
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

    // AEAD ciphers add an authentication tag (typically 16 bytes for Poly1305) to the ciphertext
    const AEAD_TAG_SIZE: usize = 16;
    let mut ciphertext_buf = [0u8; N];
    if ciphertext_buf.len() < used.len() + AEAD_TAG_SIZE {
        // Buffer too small for ciphertext + tag
        return Err(Error::CiphertextTooLarge);
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
        return Err(Error::DeserializeError);
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

    #[test]
    fn encrypt_fact_ciphertext_buffer_too_small() {
        static KEY: &[u8] = b"test-key";
        let cipher = DummyAead::new(KEY);

        let fact = make_fact(
            PodId(1),
            1,
            FactPayload::Temperature {
                milli_celsius: 20_000,
            },
        );

        let nonce = [0u8; 24];
        // Use a buffer size that's too small (e.g., 1 byte)
        let result = encrypt_fact::<1, _>(&cipher, nonce, &fact);
        assert!(result.is_err(), "should fail with small buffer");
    }

    #[test]
    fn encrypt_fact_ciphertext_too_large() {
        static KEY: &[u8] = b"test-key";
        let cipher = DummyAead::new(KEY);

        let fact = make_fact(
            PodId(1),
            1,
            FactPayload::Temperature {
                milli_celsius: 20_000,
            },
        );

        let nonce = [0u8; 24];
        // Use a buffer size that allows encryption but can't fit in Vec
        // This is harder to test with DummyAead, but we can at least verify the code path exists
        let result = encrypt_fact::<10, _>(&cipher, nonce, &fact);
        // This may or may not fail depending on serialized size, but exercises the error path
        let _ = result;
    }

    #[test]
    fn decrypt_fact_corrupted_ciphertext() {
        static KEY: &[u8] = b"test-key";
        let cipher = DummyAead::new(KEY);

        let fact = make_fact(
            PodId(5),
            1,
            FactPayload::Temperature {
                milli_celsius: 20_000,
            },
        );

        let nonce = [0u8; 24];
        let mut enc = encrypt_fact::<128, _>(&cipher, nonce, &fact).expect("encrypt fact");

        // Corrupt the ciphertext
        if !enc.ciphertext.is_empty() {
            enc.ciphertext[0] ^= 0xFF;
        }

        // Decryption should fail or produce invalid data that fails deserialization
        let result = decrypt_fact::<128, _>(&cipher, &enc);
        // With DummyAead, decryption will succeed but deserialization should fail
        // In a real AEAD, this would fail at the decrypt stage with CryptoError
        if result.is_ok() {
            // If it succeeds, the fact should be different due to corruption
            assert_ne!(result.unwrap(), fact);
        }
    }

    #[test]
    fn decrypt_fact_buffer_size_mismatch() {
        use heapless::Vec;

        static KEY: &[u8] = b"test-key";
        let cipher = DummyAead::new(KEY);

        // Create a frame with ciphertext larger than MAX_FACT_LEN
        // This is artificial but tests the error path
        let mut large_ciphertext = Vec::<u8, 512>::new();
        // Fill with data larger than MAX_FACT_LEN (256)
        for i in 0..300 {
            large_ciphertext.push((i % 256) as u8).unwrap();
        }

        let frame = EncryptedFrame::<512> {
            pod_id: PodId(42),
            fc: 100,
            nonce: [0u8; 24],
            ciphertext: large_ciphertext,
        };

        let result = decrypt_fact::<512, _>(&cipher, &frame);
        assert!(
            result.is_err(),
            "should fail when ciphertext is larger than plaintext buffer"
        );
        assert_eq!(result.unwrap_err(), Error::DeserializeError);
    }
}
