//! Gateway-only Merkle tree helpers.
//!
//! This module is enabled via the `gateway` feature and uses SHA-256
//! to hash frame bytes into a simple binary Merkle tree.

use sha2::{Digest, Sha256};

use crate::types::EncryptedFrame;

pub type Hash = [u8; 32];

/// Hash an encrypted frame into a Merkle leaf.
pub fn hash_frame<const N: usize>(frame: &EncryptedFrame<N>) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(frame.pod_id.0.to_be_bytes());
    hasher.update(frame.fc.to_be_bytes());
    hasher.update(frame.nonce);
    hasher.update(frame.ciphertext.as_slice());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute a Merkle root from a list of leaves. If the number of
/// leaves is odd, the last leaf is duplicated.
pub fn merkle_root(leaves: &[Hash]) -> Option<Hash> {
    if leaves.is_empty() {
        return None;
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                level[i]
            };

            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);
            let result = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&result);
            next.push(out);

            i += 2;
        }
        level = next;
    }

    level.pop()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_leaves_none() {
        assert!(merkle_root(&[]).is_none());
    }

    #[test]
    fn simple_merkle_root_stable() {
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let root1 = merkle_root(&leaves).expect("root");
        let root2 = merkle_root(&leaves).expect("root");
        assert_eq!(root1, root2);
    }

    #[test]
    fn hash_frame_deterministic() {
        use crate::types::{PodId, EncryptedFrame};
        use heapless::Vec;

        let mut ciphertext = Vec::<u8, 64>::new();
        ciphertext.extend_from_slice(&[1, 2, 3, 4]).unwrap();

        let frame = EncryptedFrame::<64> {
            pod_id: PodId(42),
            fc: 100,
            nonce: [5u8; 24],
            ciphertext,
        };

        let hash1 = hash_frame(&frame);
        let hash2 = hash_frame(&frame);
        assert_eq!(hash1, hash2, "same frame should produce same hash");
    }

    #[test]
    fn hash_frame_different_frames_different_hashes() {
        use crate::types::{PodId, EncryptedFrame};
        use heapless::Vec;

        let mut ciphertext1 = Vec::<u8, 64>::new();
        ciphertext1.extend_from_slice(&[1, 2, 3, 4]).unwrap();

        let frame1 = EncryptedFrame::<64> {
            pod_id: PodId(42),
            fc: 100,
            nonce: [5u8; 24],
            ciphertext: ciphertext1,
        };

        let mut ciphertext2 = Vec::<u8, 64>::new();
        ciphertext2.extend_from_slice(&[1, 2, 3, 5]).unwrap(); // Different last byte

        let frame2 = EncryptedFrame::<64> {
            pod_id: PodId(42),
            fc: 100,
            nonce: [5u8; 24],
            ciphertext: ciphertext2,
        };

        let hash1 = hash_frame(&frame1);
        let hash2 = hash_frame(&frame2);
        assert_ne!(hash1, hash2, "different frames should produce different hashes");
    }
}
