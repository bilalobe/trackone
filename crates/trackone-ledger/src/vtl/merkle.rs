//! VTL's domain-separated, hash-sorted Merkle commitment operations.
//!
//! This module is deliberately independent of artifact encoding and decoding:
//! callers provide exact canonical-record bytes or already-computed leaf hashes.

use super::{MAX_BATCH_RECORD_LIMIT, MerkleResult};
use crate::sha256_digest;

fn prefixed_hash(prefix: u8, data: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(data.len() + 1);
    bytes.push(prefix);
    bytes.extend_from_slice(data);
    sha256_digest(&bytes)
}

fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => sha256_digest(b""),
        1 => leaves[0],
        n => {
            let k = 1usize << ((usize::BITS - 1 - (n - 1).leading_zeros()) as usize);
            let left = mth(&leaves[..k]);
            let right = mth(&leaves[k..]);
            let mut bytes = Vec::with_capacity(65);
            bytes.push(1);
            bytes.extend_from_slice(&left);
            bytes.extend_from_slice(&right);
            sha256_digest(&bytes)
        }
    }
}

/// Reduce an already sorted list of leaf hashes using the profile's recursive
/// split rule.
pub fn merkle_root_from_leaf_hashes(leaves: &[[u8; 32]]) -> [u8; 32] {
    mth(leaves)
}

/// Compute the domain-separated, hash-sorted multiset tree.
pub fn merkle_root_from_records(records: &[Vec<u8>]) -> MerkleResult {
    let mut leaf_hashes = records
        .iter()
        .map(|record| prefixed_hash(0, record))
        .collect::<Vec<_>>();
    leaf_hashes.sort_unstable();
    MerkleResult {
        root: mth(&leaf_hashes),
        leaf_hashes,
    }
}

/// Form aligned batch-subtree roots from the complete sorted leaf list.
pub fn batch_roots_from_leaf_hashes(
    leaf_hashes: &[[u8; 32]],
    batch_record_limit: u64,
) -> Option<Vec<[u8; 32]>> {
    if batch_record_limit == 0
        || batch_record_limit > MAX_BATCH_RECORD_LIMIT
        || !batch_record_limit.is_power_of_two()
    {
        return None;
    }
    let limit = usize::try_from(batch_record_limit).ok()?;
    Some(leaf_hashes.chunks(limit).map(mth).collect())
}

/// Compose aligned subtree roots back into the segment root.
pub fn compose_batch_roots(
    batch_roots: &[[u8; 32]],
    record_count: u64,
    batch_record_limit: u64,
) -> Option<[u8; 32]> {
    if record_count == 0
        || batch_record_limit == 0
        || batch_record_limit > MAX_BATCH_RECORD_LIMIT
        || !batch_record_limit.is_power_of_two()
    {
        return None;
    }
    let expected = 1 + ((record_count - 1) / batch_record_limit);
    if u64::try_from(batch_roots.len()).ok()? != expected {
        return None;
    }
    compose_batch_range(batch_roots, record_count, batch_record_limit)
}

fn compose_batch_range(
    roots: &[[u8; 32]],
    leaf_count: u64,
    batch_record_limit: u64,
) -> Option<[u8; 32]> {
    if leaf_count <= batch_record_limit {
        return (roots.len() == 1).then_some(roots[0]);
    }
    let split_leaf_count = 1_u64 << (63 - (leaf_count - 1).leading_zeros());
    let split_root = usize::try_from(split_leaf_count / batch_record_limit).ok()?;
    let left = compose_batch_range(
        roots.get(..split_root)?,
        split_leaf_count,
        batch_record_limit,
    )?;
    let right = compose_batch_range(
        roots.get(split_root..)?,
        leaf_count - split_leaf_count,
        batch_record_limit,
    )?;
    let mut bytes = Vec::with_capacity(65);
    bytes.push(1);
    bytes.extend_from_slice(&left);
    bytes.extend_from_slice(&right);
    Some(sha256_digest(&bytes))
}
