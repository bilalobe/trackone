use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use trackone_ledger::canonical_cbor;
use trackone_ledger::merkle;
use trackone_ledger::types::{self, BlockHeaderV1, DayRecordV1};

#[derive(Debug, Deserialize)]
struct FactEntry {
    json_path: String,
    cbor_path: String,
    cbor_sha256: String,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    site_id: String,
    date: String,
    prev_day_root: String,
    batch_id: String,
    facts: Vec<FactEntry>,
    block_header_path: String,
    day_record_json_path: String,
    day_record_cbor_path: String,
    leaf_hashes: Vec<String>,
    merkle_root: String,
    day_cbor_sha256: String,
}

#[derive(Debug, Deserialize)]
struct V2Manifest {
    schema: String,
    draft_revision: String,
    commitment_profile_id: String,
    records: Vec<V2Record>,
    batches: Vec<V2Batch>,
    segment: V2Segment,
    successor_segment: V2Segment,
    negative_segments: Vec<V2NegativeSegment>,
    segment_root: String,
}

#[derive(Debug, Deserialize)]
struct V2Record {
    cbor_path: String,
    cbor_hex: String,
    cbor_sha256: String,
    leaf_sha256: String,
}

#[derive(Debug, Deserialize)]
struct V2Batch {
    batch_number: String,
    count: String,
    leaf_hashes: Vec<String>,
    merkle_root: String,
}

#[derive(Debug, Deserialize)]
struct V2Segment {
    cbor_path: String,
    cbor_sha256: String,
    cbor_size: usize,
    ledger_id: String,
    site_id: String,
    segment_number: String,
    closure_policy: V2ClosurePolicy,
    close_reason: String,
    prev_segment_sha256: String,
    segment_root: String,
}

#[derive(Debug, Deserialize)]
struct V2ClosurePolicy {
    version: u8,
    interval_ms: String,
    batch_record_limit: String,
    record_limit: Option<String>,
    size_limit_bytes: Option<String>,
    empty_mode: String,
}

#[derive(Debug, Deserialize)]
struct V2NegativeSegment {
    id: String,
    cbor_path: String,
    cbor_sha256: String,
    cbor_size: usize,
    expected_invariant: String,
}

fn vector_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../toolset/vectors/verifiable-telemetry-canonical-cbor-v1")
}

/// Returns `true` when the canonical-CBOR vector corpus is present on disk.
fn vector_corpus_present() -> bool {
    vector_root().join("manifest.json").exists()
}

fn v2_vector_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../toolset/vectors/verifiable-telemetry-canonical-cbor-v2")
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    trackone_ledger::hex_lower(digest.as_ref())
}

/// Verify that the Rust implementation reproduces the published canonical-CBOR
/// commitment vectors exactly.
///
/// The vector corpus lives under `toolset/vectors/verifiable-telemetry-canonical-cbor-v1/`
/// in the monorepo root.  That directory is **not** packaged with the published
/// crate, so this test is marked `#[ignore]` to prevent failures in downstream
/// environments.  Run it explicitly from the workspace root:
///
/// ```text
/// cargo test -p trackone-ledger -- --ignored rust_reproduces_published_commitment_vectors
/// ```
#[test]
#[ignore = "requires the monorepo's toolset/vectors corpus – run with --ignored"]
fn rust_reproduces_published_commitment_vectors() {
    if !vector_corpus_present() {
        eprintln!("skipping: vector corpus not present at {:?}", vector_root());
        return;
    }
    let root = vector_root();
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();

    let mut leaves = Vec::new();
    for fact in &manifest.facts {
        let json_bytes = fs::read(root.join(&fact.json_path)).unwrap();
        let expected = fs::read(root.join(&fact.cbor_path)).unwrap();
        let actual = canonical_cbor::canonicalize_json_bytes_to_cbor(&json_bytes).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(hex_sha256(&actual), fact.cbor_sha256);
        leaves.push(actual);
    }

    let merkle = merkle::merkle_root_from_leaves(&leaves);
    assert_eq!(merkle.root_hex(), manifest.merkle_root);
    assert_eq!(merkle.leaf_hashes_hex(), manifest.leaf_hashes);

    let expected_header: BlockHeaderV1 =
        serde_json::from_slice(&fs::read(root.join(&manifest.block_header_path)).unwrap()).unwrap();
    let actual_header = types::block_header_v1_from_canonical_leaves(
        manifest.site_id.clone(),
        manifest.date.clone(),
        manifest.batch_id.clone(),
        &leaves,
    );
    assert_eq!(actual_header, expected_header);

    let day_json = fs::read(root.join(&manifest.day_record_json_path)).unwrap();
    let expected_day: DayRecordV1 = serde_json::from_slice(&day_json).unwrap();
    let expected_day_cbor = fs::read(root.join(&manifest.day_record_cbor_path)).unwrap();
    let actual_day = types::day_record_v1_single_batch(
        manifest.site_id,
        manifest.date,
        manifest.prev_day_root,
        actual_header,
    );
    assert_eq!(actual_day, expected_day);
    assert_eq!(
        actual_day.canonical_cbor_bytes().unwrap(),
        expected_day_cbor
    );
    assert_eq!(hex_sha256(&expected_day_cbor), manifest.day_cbor_sha256);
}

/// Verify the corrected draft-08 v2 record, Merkle, batch, segment, and strict
/// chain-position vectors from exact on-disk artifacts.
#[test]
#[ignore = "requires the monorepo's toolset/vectors corpus – run with --ignored"]
fn rust_reproduces_draft_08_v2_segment_vectors() {
    let root = v2_vector_root();
    let manifest: V2Manifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest.schema, "trackone-v2-vector-manifest-2");
    assert_eq!(
        manifest.draft_revision,
        "draft-elkhatabi-verifiable-telemetry-ledgers-08"
    );
    assert_eq!(
        manifest.commitment_profile_id,
        trackone_ledger::v2::COMMITMENT_PROFILE_ID
    );
    assert!(
        !manifest.records.is_empty(),
        "v2 vector corpus must not be empty"
    );

    let records = manifest
        .records
        .iter()
        .map(|record| {
            let bytes = fs::read(root.join(&record.cbor_path)).unwrap();
            assert_eq!(bytes, hex::decode(&record.cbor_hex).unwrap());
            assert_eq!(hex_sha256(&bytes), record.cbor_sha256);
            trackone_ledger::v2::validate_canonical_record_v2(&bytes).unwrap();

            let mut leaf_preimage = Vec::with_capacity(bytes.len() + 1);
            leaf_preimage.push(0);
            leaf_preimage.extend_from_slice(&bytes);
            assert_eq!(hex_sha256(&leaf_preimage), record.leaf_sha256);
            bytes
        })
        .collect::<Vec<_>>();
    let merkle = trackone_ledger::v2::merkle_root_from_records(&records);
    assert_eq!(merkle.root_hex(), manifest.segment_root);

    let segment_bytes = fs::read(root.join(&manifest.segment.cbor_path)).unwrap();
    assert_eq!(segment_bytes.len(), manifest.segment.cbor_size);
    assert_eq!(hex_sha256(&segment_bytes), manifest.segment.cbor_sha256);
    let segment = trackone_ledger::v2::decode_segment_record_v2(&segment_bytes).unwrap();
    assert_eq!(
        segment.canonical_cbor_bytes().unwrap(),
        segment_bytes,
        "strict decode must reproduce the exact authoritative bytes"
    );
    assert_eq!(segment.ledger_id, manifest.segment.ledger_id);
    assert_eq!(segment.site_id, manifest.segment.site_id);
    assert_eq!(
        segment.segment_number,
        manifest.segment.segment_number.parse::<u64>().unwrap()
    );
    assert_eq!(segment.close_reason, manifest.segment.close_reason);
    assert_eq!(
        segment.prev_segment_sha256,
        manifest.segment.prev_segment_sha256
    );
    assert_eq!(segment.segment_root, manifest.segment.segment_root);
    assert_eq!(manifest.segment.segment_root, manifest.segment_root);
    assert_eq!(manifest.segment.closure_policy.version, 1);
    assert_eq!(
        segment.closure_policy.interval_ms,
        manifest
            .segment
            .closure_policy
            .interval_ms
            .parse::<u64>()
            .unwrap()
    );
    assert_eq!(
        segment.closure_policy.batch_record_limit,
        manifest
            .segment
            .closure_policy
            .batch_record_limit
            .parse::<u64>()
            .unwrap()
    );
    assert_eq!(
        segment.closure_policy.record_limit,
        manifest
            .segment
            .closure_policy
            .record_limit
            .as_deref()
            .map(|value| value.parse::<u64>().unwrap())
    );
    assert_eq!(
        segment.closure_policy.size_limit_bytes,
        manifest
            .segment
            .closure_policy
            .size_limit_bytes
            .as_deref()
            .map(|value| value.parse::<u64>().unwrap())
    );
    assert_eq!(
        segment.closure_policy.empty_mode.as_str(),
        manifest.segment.closure_policy.empty_mode
    );
    let constructed_epoch = trackone_ledger::v2::SegmentRecordV2::new_epoch(
        segment.ledger_id.clone(),
        segment.site_id.clone(),
        segment.closure_policy.clone(),
        segment.close_reason.clone(),
        segment.batches.clone(),
        segment.segment_root.clone(),
    )
    .unwrap();
    assert_eq!(
        constructed_epoch.canonical_cbor_bytes().unwrap(),
        segment_bytes,
        "validated epoch construction must reproduce the corpus artifact"
    );

    assert_eq!(segment.batches.len(), manifest.batches.len());
    for (batch, expected) in segment.batches.iter().zip(&manifest.batches) {
        assert_eq!(
            batch.batch_number,
            expected.batch_number.parse::<u64>().unwrap()
        );
        assert_eq!(batch.count, expected.count.parse::<u64>().unwrap());
        assert_eq!(batch.leaf_hashes, expected.leaf_hashes);
        assert_eq!(batch.merkle_root, expected.merkle_root);
        assert_eq!(batch.ledger_id, segment.ledger_id);
        assert_eq!(batch.site_id, segment.site_id);
        assert_eq!(batch.segment_number, segment.segment_number);
    }
    let embedded_leaves = segment
        .batches
        .iter()
        .flat_map(|batch| batch.leaf_hashes.iter().cloned())
        .collect::<Vec<_>>();
    assert_eq!(
        embedded_leaves,
        merkle
            .leaf_hashes
            .iter()
            .map(|hash| trackone_ledger::hex_lower(hash))
            .collect::<Vec<_>>()
    );

    let successor_bytes = fs::read(root.join(&manifest.successor_segment.cbor_path)).unwrap();
    assert_eq!(successor_bytes.len(), manifest.successor_segment.cbor_size);
    assert_eq!(
        hex_sha256(&successor_bytes),
        manifest.successor_segment.cbor_sha256
    );
    let successor = trackone_ledger::v2::decode_segment_record_v2(&successor_bytes).unwrap();
    assert_eq!(successor.canonical_cbor_bytes().unwrap(), successor_bytes);
    assert_eq!(successor.ledger_id, manifest.successor_segment.ledger_id);
    assert_eq!(successor.site_id, manifest.successor_segment.site_id);
    assert_eq!(
        successor.segment_number,
        manifest
            .successor_segment
            .segment_number
            .parse::<u64>()
            .unwrap()
    );
    assert_eq!(
        successor.prev_segment_sha256,
        manifest.successor_segment.prev_segment_sha256
    );
    assert_eq!(
        successor.segment_root,
        manifest.successor_segment.segment_root
    );
    assert_eq!(successor.batches.len(), segment.batches.len());
    for (successor_batch, epoch_batch) in successor.batches.iter().zip(&segment.batches) {
        assert_eq!(successor_batch.ledger_id, successor.ledger_id);
        assert_eq!(successor_batch.site_id, successor.site_id);
        assert_eq!(successor_batch.segment_number, successor.segment_number);
        assert_eq!(successor_batch.batch_number, epoch_batch.batch_number);
        assert_eq!(successor_batch.count, epoch_batch.count);
        assert_eq!(successor_batch.leaf_hashes, epoch_batch.leaf_hashes);
        assert_eq!(successor_batch.merkle_root, epoch_batch.merkle_root);
    }
    assert_eq!(
        successor.prev_segment_sha256,
        hex_sha256(&segment_bytes),
        "successor must bind the exact authoritative predecessor bytes"
    );

    let constructed = trackone_ledger::v2::SegmentRecordV2::new_successor(
        &segment_bytes,
        segment.closure_policy.clone(),
        segment.close_reason.clone(),
        segment.batches.clone(),
        segment.segment_root.clone(),
    )
    .unwrap();
    assert_eq!(
        constructed.canonical_cbor_bytes().unwrap(),
        successor_bytes,
        "validated successor construction must reproduce the corpus artifact"
    );

    assert_eq!(manifest.negative_segments.len(), 1);
    let negative = &manifest.negative_segments[0];
    assert_eq!(negative.id, "segment-7-zero-predecessor");
    let invalid_bytes = fs::read(root.join(&negative.cbor_path)).unwrap();
    assert_eq!(invalid_bytes.len(), negative.cbor_size);
    assert_eq!(hex_sha256(&invalid_bytes), negative.cbor_sha256);
    let error = trackone_ledger::v2::decode_segment_record_v2(&invalid_bytes).unwrap_err();
    assert_eq!(
        error.invariant_error().map(|error| error.code()),
        Some(negative.expected_invariant.as_str())
    );
}
