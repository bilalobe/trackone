//! Disclosure-class shape checks and disclosed-record recomputation.

use super::manifest::{Manifest, RecordBatchOpening};
use super::paths::{parse_uint64, referenced_artifact};
use super::result::Conclusions;
use super::{EvidenceError, VerificationScope, VerifyPolicy};
use std::collections::BTreeSet;
use std::path::Path;
use trackone_ledger::sha256_digest;
use trackone_ledger::vtl::{
    SegmentDecodeError, SegmentRecord, merkle_root_from_leaf_hashes, validate_canonical_record,
};

/// Hash a claimed opening one record at a time.
///
/// Aggregate memory must not grow with the reference count: an untrusted
/// manifest may point thousands of references at the same maximally sized
/// artifact, so each record is opened, validated, hashed, and dropped before
/// the next is read.  Canonical-record failures are reported by the caller
/// only once the whole opening has loaded, preserving the conclusions of the
/// former collect-then-validate order.
fn opening_leaves(
    root: &Path,
    opening: &RecordBatchOpening,
    pending: &mut BTreeSet<&'static str>,
) -> super::Result<Vec<[u8; 32]>> {
    let mut leaves = Vec::with_capacity(opening.records.len());
    for reference in &opening.records {
        let record = referenced_artifact(root, reference)?;
        if let Err(error) = validate_canonical_record(&record) {
            pending.insert(match error {
                SegmentDecodeError::ResourceLimit(_) => "verifier_policy_rejection",
                _ => "invalid_canonical_record",
            });
        }
        let mut preimage = Vec::with_capacity(record.len() + 1);
        preimage.push(0);
        preimage.extend_from_slice(&record);
        leaves.push(sha256_digest(&preimage));
    }
    Ok(leaves)
}

pub(super) fn validate_disclosure(
    root: &Path,
    manifest: &Manifest,
    segment: &SegmentRecord,
    policy: &VerifyPolicy,
    conclusions: &mut Conclusions,
) -> bool {
    let openings = manifest.artifacts.record_batches.as_deref().unwrap_or(&[]);
    let batch_count = segment.batch_roots.len();
    let mut numbers = BTreeSet::new();
    let mut indexed_openings = Vec::new();
    for opening in openings {
        let Some(number) = parse_uint64(&opening.batch_number) else {
            conclusions.fail("insufficient_disclosure");
            continue;
        };
        if usize::try_from(number)
            .ok()
            .is_none_or(|value| value >= batch_count)
            || !numbers.insert(number)
        {
            conclusions.fail("insufficient_disclosure");
            continue;
        }
        indexed_openings.push((number, opening));
    }

    let shape_valid = match manifest.disclosure_class.as_str() {
        "A" if segment.record_count == 0 => openings.is_empty(),
        "A" => openings.len() == batch_count && numbers.len() == batch_count,
        "B" => batch_count > 1 && !openings.is_empty() && openings.len() < batch_count,
        "C" => openings.is_empty(),
        _ => false,
    };
    if !shape_valid {
        conclusions.fail("insufficient_disclosure");
        return false;
    }

    // The claimed disclosure has a complete structural contract even when a
    // selected scope deliberately does not consume some of its records.  Do
    // not open those artifacts here, but do make sure every claimed batch has
    // the cardinality committed by the authoritative segment.
    if indexed_openings.iter().any(|(number, opening)| {
        expected_opening_count(segment, batch_count, *number).and_then(|expected| {
            u64::try_from(opening.records.len())
                .ok()
                .map(|actual| actual == expected)
        }) != Some(true)
    }) {
        conclusions.fail("insufficient_disclosure");
        return false;
    }

    let consume = match conclusions.scope {
        VerificationScope::AnchorOnly => return true,
        VerificationScope::PublicRecompute => {
            if manifest.disclosure_class != "A" {
                conclusions.fail("insufficient_disclosure");
                return false;
            }
            numbers.clone()
        }
        VerificationScope::DisclosedBatchRecompute => {
            if batch_count <= 1 || manifest.disclosure_class == "C" {
                conclusions.fail("insufficient_disclosure");
                return false;
            }
            if manifest.disclosure_class == "A" {
                if policy.selected_batches.is_empty()
                    || policy.selected_batches.len() >= batch_count
                    || !policy.selected_batches.is_subset(&numbers)
                {
                    conclusions.fail("insufficient_disclosure");
                    return false;
                }
                policy.selected_batches.clone()
            } else {
                if !policy.selected_batches.is_empty() && policy.selected_batches != numbers {
                    conclusions.fail("insufficient_disclosure");
                    return false;
                }
                numbers.clone()
            }
        }
    };

    let mut opened = Vec::<(usize, Vec<[u8; 32]>)>::new();
    for (number_u64, opening) in indexed_openings {
        if !consume.contains(&number_u64) {
            continue;
        }
        let number = usize::try_from(number_u64).expect("validated above");
        let expected = expected_opening_count(segment, batch_count, number_u64);
        let mut pending = BTreeSet::new();
        let mut leaves = match opening_leaves(root, opening, &mut pending) {
            Ok(leaves) => leaves,
            Err(EvidenceError::VerificationFailed(_)) => {
                conclusions.fail("commitment_mismatch");
                continue;
            }
            Err(_) => {
                conclusions.fail("insufficient_disclosure");
                continue;
            }
        };
        if u64::try_from(leaves.len()).ok() != expected {
            conclusions.fail("insufficient_disclosure");
            continue;
        }
        for failure in pending {
            conclusions.fail(failure);
        }
        leaves.sort_unstable();
        if merkle_root_from_leaf_hashes(&leaves) != segment.batch_roots[number] {
            conclusions.fail("commitment_mismatch");
        }
        opened.push((number, leaves));
    }

    opened.sort_by_key(|(number, _)| *number);
    for adjacent in opened.windows(2) {
        if adjacent[0].0 + 1 == adjacent[1].0
            && adjacent[0]
                .1
                .last()
                .zip(adjacent[1].1.first())
                .is_some_and(|(left, right)| left > right)
        {
            conclusions.fail("commitment_mismatch");
        }
    }
    if conclusions.scope == VerificationScope::PublicRecompute && segment.record_count > 0 {
        let leaves = opened
            .iter()
            .flat_map(|(_, leaves)| leaves.iter().copied())
            .collect::<Vec<_>>();
        if merkle_root_from_leaf_hashes(&leaves) != segment.segment_root {
            conclusions.fail("commitment_mismatch");
        }
    }
    true
}

fn expected_opening_count(segment: &SegmentRecord, batch_count: usize, number: u64) -> Option<u64> {
    let number = usize::try_from(number).ok()?;
    if number >= batch_count {
        return None;
    }
    if number + 1 == batch_count {
        u64::try_from(number)
            .ok()
            .and_then(|value| value.checked_mul(segment.closure_policy.batch_record_limit))
            .and_then(|full_before| segment.record_count.checked_sub(full_before))
    } else {
        Some(segment.closure_policy.batch_record_limit)
    }
}
