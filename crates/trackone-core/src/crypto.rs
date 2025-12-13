//! Cryptographic abstractions used by trackone-core.
//!
//! This module defines traits and key/nonce types in a `no_std`-friendly
//! way. Concrete algorithm implementations live in higher-level crates
//! (e.g., gateway or firmware), which implement these traits.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Symmetric key material for an AEAD cipher.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey<const N: usize>(pub [u8; N]);

/// Trait for AEAD encryption.
pub trait AeadEncrypt {
    type Error;

    /// Encrypt `plaintext` into `out`, return ciphertext length.
    fn encrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Self::Error>;
}

/// Trait for AEAD decryption.
pub trait AeadDecrypt {
    type Error;

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Self::Error>;
}

/// Dummy AEAD implementation used only for tests to validate plumbing.
#[cfg(any(test, feature = "dummy-aead"))]
pub mod dummy {
    use super::{AeadDecrypt, AeadEncrypt};
    use crate::types::Error;

    /// Extremely simple XOR-based AEAD for testing only.
    pub struct DummyAead {
        key: &'static [u8],
    }

    impl DummyAead {
        pub const fn new(key: &'static [u8]) -> Self {
            Self { key }
        }
    }

    impl AeadEncrypt for DummyAead {
        type Error = Error;

        fn encrypt(
            &self,
            _nonce: &[u8],
            _aad: &[u8],
            plaintext: &[u8],
            out: &mut [u8],
        ) -> Result<usize, Self::Error> {
            if out.len() < plaintext.len() {
                return Err(Error::CryptoError);
            }
            for (i, b) in plaintext.iter().enumerate() {
                out[i] = b ^ self.key[i % self.key.len()];
            }
            Ok(plaintext.len())
        }
    }

    impl AeadDecrypt for DummyAead {
        type Error = Error;

        fn decrypt(
            &self,
            _nonce: &[u8],
            _aad: &[u8],
            ciphertext: &[u8],
            out: &mut [u8],
        ) -> Result<usize, Self::Error> {
            if out.len() < ciphertext.len() {
                return Err(Error::CryptoError);
            }
            for (i, b) in ciphertext.iter().enumerate() {
                out[i] = b ^ self.key[i % self.key.len()];
            }
            Ok(ciphertext.len())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn dummy_roundtrip() {
            static KEY: &[u8] = b"test-key";
            let aead = DummyAead::new(KEY);

            let plaintext = b"hello";
            let mut buf = [0u8; 16];

            let ct_len = aead
                .encrypt(&[0u8; 24], &[], plaintext, &mut buf)
                .expect("encrypt");

            let mut out = [0u8; 16];
            let pt_len = aead
                .decrypt(&[0u8; 24], &[], &buf[..ct_len], &mut out)
                .expect("decrypt");

            assert_eq!(&out[..pt_len], plaintext);
        }
    }
}
