use sha2::{Digest, Sha256};

use crate::hex_lower;

pub type Hash = [u8; 32];

fn sha256(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// ADR-003 Merkle result (root + sorted leaf hashes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleResult {
    pub root: Hash,
    pub leaf_hashes: Vec<Hash>,
}

impl MerkleResult {
    pub fn root_hex(&self) -> String {
        hex_lower(&self.root)
    }

    pub fn leaf_hashes_hex(&self) -> Vec<String> {
        self.leaf_hashes.iter().map(|h| hex_lower(h)).collect()
    }
}

/// Compute an ADR-003 Merkle root over leaf bytes.
///
/// Policy:
/// - leaf hash: SHA-256(leaf_bytes)
/// - leaf ordering: sort by leaf hash (lexicographic)
/// - internal nodes: SHA-256(left || right), duplicate last if odd
/// - empty set: SHA-256(b"")
pub fn merkle_root_from_leaves(leaves: &[Vec<u8>]) -> MerkleResult {
    if leaves.is_empty() {
        return MerkleResult {
            root: sha256(b""),
            leaf_hashes: Vec::new(),
        };
    }

    let mut leaf_hashes: Vec<Hash> = leaves.iter().map(|leaf| sha256(leaf)).collect();
    leaf_hashes.sort_unstable();

    let root = merkle_root_from_sorted_leaf_hashes(&leaf_hashes);
    MerkleResult { root, leaf_hashes }
}

fn merkle_root_from_sorted_leaf_hashes(sorted_leaf_hashes: &[Hash]) -> Hash {
    if sorted_leaf_hashes.is_empty() {
        return sha256(b"");
    }

    let mut level: Vec<Hash> = sorted_leaf_hashes.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);
            let result = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&result);
            next.push(out);
        }
        level = next;
    }

    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_matches_policy() {
        let got = merkle_root_from_leaves(&[]);
        assert_eq!(got.root, sha256(b""));
        assert!(got.leaf_hashes.is_empty());
    }

    #[test]
    fn root_is_order_independent() {
        let a = b"leaf-a".to_vec();
        let b = b"leaf-b".to_vec();
        let c = b"leaf-c".to_vec();

        let root1 = merkle_root_from_leaves(&[a.clone(), b.clone(), c.clone()]);
        let root2 = merkle_root_from_leaves(&[c, a, b]);
        assert_eq!(root1.root, root2.root);
        assert_eq!(root1.leaf_hashes, root2.leaf_hashes);
    }
}
