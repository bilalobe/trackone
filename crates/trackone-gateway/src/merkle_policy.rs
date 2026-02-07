use sha2::{Digest, Sha256};

pub type Hash = trackone_core::merkle::Hash;

fn sha256(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute a Merkle root over canonical leaf bytes.
///
/// Policy (ADR-003):
/// - leaf hash: SHA-256(leaf_bytes)
/// - leaf ordering: sort by leaf hash (lexicographic)
/// - internal nodes: SHA-256(left || right), duplicate last if odd
/// - empty set: SHA-256(b"")
pub fn compute_merkle_root(leaves: &[Vec<u8>]) -> Hash {
    if leaves.is_empty() {
        return sha256(b"");
    }

    let mut leaf_hashes: Vec<Hash> = leaves.iter().map(|leaf| sha256(leaf)).collect();
    leaf_hashes.sort_unstable();

    // Non-empty leaves => root must exist.
    trackone_core::merkle::merkle_root(&leaf_hashes).expect("non-empty leaves")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_set_matches_adr_003() {
        assert_eq!(compute_merkle_root(&[]), sha256(b""));
    }

    #[test]
    fn root_is_order_independent() {
        let a = b"leaf-a".to_vec();
        let b = b"leaf-b".to_vec();
        let c = b"leaf-c".to_vec();

        let root1 = compute_merkle_root(&vec![a.clone(), b.clone(), c.clone()]);
        let root2 = compute_merkle_root(&vec![c, a, b]);
        assert_eq!(root1, root2);
    }
}
