//! Segment-predecessor validation for disclosed VTL chain material.

use super::manifest::Manifest;
use super::paths::referenced_artifact;
use super::result::Conclusions;
use std::path::Path;
use trackone_ledger::sha256_digest;
use trackone_ledger::vtl::{SegmentRecord, ZERO_SHA256, decode_segment_record};

pub(super) fn validate_chain(
    root: &Path,
    manifest: &Manifest,
    segment: &SegmentRecord,
    conclusions: &mut Conclusions,
) {
    if segment.segment_number == 0 {
        if segment.prev_segment_sha256 == ZERO_SHA256 {
            conclusions.chain_status = Some("epoch");
        } else {
            conclusions.chain_status = Some("failed");
            conclusions.fail("segment_chain_mismatch");
        }
        return;
    }
    let Some(reference) = &manifest.artifacts.predecessor_segment_cbor else {
        conclusions.chain_status = Some("predecessor_not_disclosed");
        return;
    };
    let predecessor_bytes = match referenced_artifact(root, reference) {
        Ok(bytes) => bytes,
        Err(_) => {
            conclusions.chain_status = Some("failed");
            conclusions.fail("segment_chain_mismatch");
            return;
        }
    };
    let valid = decode_segment_record(&predecessor_bytes).is_ok_and(|predecessor| {
        predecessor.ledger_id == segment.ledger_id
            && predecessor.commitment_profile_id == segment.commitment_profile_id
            && predecessor.segment_number.checked_add(1) == Some(segment.segment_number)
            && sha256_digest(&predecessor_bytes) == segment.prev_segment_sha256
    });
    conclusions.chain_status = Some(if valid { "validated" } else { "failed" });
    if !valid {
        conclusions.fail("segment_chain_mismatch");
    }
}
