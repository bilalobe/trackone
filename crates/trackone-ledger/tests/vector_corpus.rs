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

fn vector_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../toolset/vectors/trackone-canonical-cbor-v1")
}

/// Returns `true` when the canonical-CBOR vector corpus is present on disk.
fn vector_corpus_present() -> bool {
    vector_root().join("manifest.json").exists()
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    trackone_ledger::hex_lower(digest.as_ref())
}

/// Verify that the Rust implementation reproduces the published canonical-CBOR
/// commitment vectors exactly.
///
/// The vector corpus lives under `toolset/vectors/trackone-canonical-cbor-v1/`
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
