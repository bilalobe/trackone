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
    // === SECURITY WARNING ===
    //
    // The `dummy-aead` feature enables a non-secure, XOR-based AEAD implementation
    // intended ONLY for testing and development. It provides NO confidentiality and
    // NO authentication.
    //
    // We intentionally do **not** hard-error in trackone-core by default because
    // workspace CI and developers may use `--all-features`.
    //
    // To enforce safety in *security-sensitive builds*, downstream crates should
    // enable either:
    //   - `trackone-core/deny-dummy-aead` (strong guard), or
    //   - `trackone-core/production` (semantic prod marker),
    // which will refuse to compile if `dummy-aead` is present.

    // Safety gates: if the downstream crate is building in a security-sensitive
    // mode, it must be impossible to also enable `dummy-aead`.
    #[cfg(all(
        feature = "dummy-aead",
        any(feature = "deny-dummy-aead", feature = "production")
    ))]
    compile_error!(
        "`dummy-aead` is enabled in a security-sensitive build (`deny-dummy-aead` or `production`). Disable `dummy-aead`.",
    );

    use super::{AeadDecrypt, AeadEncrypt};
    use crate::types::Error;

    /// **SECURITY WARNING: DO NOT USE IN PRODUCTION!**
    ///
    /// `DummyAead` is an extremely simple XOR-based AEAD implementation for testing
    /// and development only. It provides **NO confidentiality** and **NO authentication**.
    ///
    /// To avoid accidental use, ensure the `dummy-aead` feature is **not** enabled in
    /// production builds.
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
        use crate::AEAD_NONCE_LEN;

        #[test]
        fn dummy_roundtrip() {
            static KEY: &[u8] = b"test-key";
            let aead = DummyAead::new(KEY);

            let plaintext = b"hello";
            let mut buf = [0u8; 16];

            let ct_len = aead
                .encrypt(&[0u8; AEAD_NONCE_LEN], &[], plaintext, &mut buf)
                .expect("encrypt");

            let mut out = [0u8; 16];
            let pt_len = aead
                .decrypt(&[0u8; AEAD_NONCE_LEN], &[], &buf[..ct_len], &mut out)
                .expect("decrypt");

            assert_eq!(&out[..pt_len], plaintext);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_key_instantiation() {
        let key = SymmetricKey::<32>([42u8; 32]);
        assert_eq!(key.0[0], 42);
        assert_eq!(key.0[31], 42);
    }

    #[test]
    fn symmetric_key_clone() {
        let key1 = SymmetricKey::<32>([42u8; 32]);
        let key2 = key1.clone();
        assert_eq!(key1.0, key2.0);
    }

    // Note: Testing actual zeroization on drop is challenging in safe Rust
    // because we can't safely inspect memory after drop. The zeroize crate
    // itself has tests that verify the zeroization behavior works correctly.
    // Here we verify that the type compiles and can be used as expected.
}
