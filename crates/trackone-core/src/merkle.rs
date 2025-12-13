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
}
