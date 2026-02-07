use serde::{Deserialize, Serialize};

use crate::canonical_json;
use crate::merkle;
use crate::{hex_lower, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeaderV1 {
    pub version: u32,
    pub site_id: String,
    pub day: String,
    pub batch_id: String,
    pub merkle_root: String,
    pub count: u64,
    pub leaf_hashes: Vec<String>,
}

impl BlockHeaderV1 {
    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>> {
        canonical_json::canonicalize_serialize(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DayRecordV1 {
    pub version: u32,
    pub site_id: String,
    pub date: String,
    pub prev_day_root: String,
    pub batches: Vec<BlockHeaderV1>,
    pub day_root: String,
}

impl DayRecordV1 {
    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>> {
        canonical_json::canonicalize_serialize(self)
    }
}

/// Build a v1 block header from leaf bytes (already canonicalized at the caller).
pub fn block_header_v1_from_canonical_leaves(
    site_id: impl Into<String>,
    day: impl Into<String>,
    batch_id: impl Into<String>,
    leaves: &[Vec<u8>],
) -> BlockHeaderV1 {
    let result = merkle::merkle_root_from_leaves(leaves);
    BlockHeaderV1 {
        version: 1,
        site_id: site_id.into(),
        day: day.into(),
        batch_id: batch_id.into(),
        merkle_root: hex_lower(&result.root),
        count: leaves.len() as u64,
        leaf_hashes: result.leaf_hashes_hex(),
    }
}

/// Build a v1 day record for the current single-batch-per-day pipeline (ADR-003).
pub fn day_record_v1_single_batch(
    site_id: impl Into<String>,
    date: impl Into<String>,
    prev_day_root: impl Into<String>,
    batch: BlockHeaderV1,
) -> DayRecordV1 {
    let day_root = batch.merkle_root.clone();
    DayRecordV1 {
        version: 1,
        site_id: site_id.into(),
        date: date.into(),
        prev_day_root: prev_day_root.into(),
        batches: vec![batch],
        day_root,
    }
}
