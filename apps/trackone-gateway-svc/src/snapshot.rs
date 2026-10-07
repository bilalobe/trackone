//! Immutable disclosure-snapshot export from the producer's PostgreSQL store.

use postgres::{Client, IsolationLevel};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use trackone_ledger::vtl::{
    batch_roots_from_leaf_hashes, decode_segment_record, merkle_root_from_records,
    validate_canonical_record,
};
use trackone_ledger::{sha256_digest, sha256_hex};

const MANIFEST_NAME: &str = "segment.verify.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisclosureClass {
    A,
    B,
    C,
}

impl DisclosureClass {
    pub fn parse(value: &str) -> Result<Self, ExportError> {
        match value {
            "A" => Ok(Self::A),
            "B" => Ok(Self::B),
            "C" => Ok(Self::C),
            _ => Err(ExportError::Invalid("class must be A, B, or C".into())),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
        }
    }
}

#[derive(Debug)]
pub enum ExportError {
    Invalid(String),
    Absent,
    Pending,
    Unavailable,
    Database(String),
    Io(std::io::Error),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Absent => formatter.write_str("sealed segment was not found"),
            Self::Pending => formatter.write_str(
                "segment has no usable retained timestamp response; queued export is refused",
            ),
            Self::Unavailable => formatter.write_str(
                "segment has no usable retained timestamp response; failed export is refused",
            ),
            Self::Database(message) => write!(formatter, "database snapshot failed: {message}"),
            Self::Io(error) => write!(formatter, "snapshot publication failed: {error}"),
        }
    }
}

impl std::error::Error for ExportError {}

impl From<std::io::Error> for ExportError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug)]
struct SnapshotMaterial {
    artifact: Vec<u8>,
    artifact_sha256: String,
    predecessor: Option<Vec<u8>>,
    records: Vec<Vec<u8>>,
    tsa_response: Vec<u8>,
}

#[derive(Serialize)]
struct ArtifactRef {
    path: String,
    sha256: String,
}

#[derive(Serialize)]
struct RecordBatchOpening {
    batch_number: String,
    records: Vec<ArtifactRef>,
}

#[derive(Serialize)]
struct Artifacts {
    segment_cbor: ArtifactRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_segment_cbor: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    record_batches: Option<Vec<RecordBatchOpening>>,
    tsa_tsr: ArtifactRef,
}

#[derive(Serialize)]
struct TsaState {
    status: &'static str,
}

#[derive(Serialize)]
struct Anchoring {
    tsa: TsaState,
}

#[derive(Serialize)]
struct Manifest {
    version: u8,
    ledger_id: String,
    segment_number: String,
    commitment_profile_id: String,
    disclosure_class: &'static str,
    artifacts: Artifacts,
    anchoring: Anchoring,
}

/// Export one timestamp-complete producer segment as an immutable directory.
pub fn export_snapshot(
    client: &mut Client,
    ledger_id: &str,
    segment_number: u64,
    class: DisclosureClass,
    selected_batches: &BTreeSet<u64>,
    output: &Path,
) -> Result<(), ExportError> {
    if ledger_id.len() != 32
        || !ledger_id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ExportError::Invalid(
            "ledger-id must be 16-byte lowercase hexadecimal".into(),
        ));
    }
    validate_destination(output)?;
    let export = prepare_snapshot(client, ledger_id, segment_number, class, selected_batches)?;
    publish_directory(output, &export)
}

pub(crate) fn prepare_snapshot(
    client: &mut Client,
    ledger_id: &str,
    segment_number: u64,
    class: DisclosureClass,
    selected_batches: &BTreeSet<u64>,
) -> Result<PreparedExport, ExportError> {
    let material = read_material(client, ledger_id, segment_number)?;
    prepare_export(ledger_id, segment_number, class, selected_batches, material)
}

pub(crate) struct PreparedExport {
    pub(crate) files: Vec<(PathBuf, Vec<u8>)>,
}

fn read_material(
    client: &mut Client,
    ledger_id: &str,
    segment_number: u64,
) -> Result<SnapshotMaterial, ExportError> {
    let mut transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .map_err(database_error)?;
    let number = segment_number.to_string();
    let row = transaction
        .query_opt(
            "SELECT artifact_cbor, artifact_sha256, tsa_status, tsa_response \
             FROM trackone_vtl_sealed_segment \
             WHERE ledger_id=$1 AND segment_number=$2::text::numeric",
            &[&ledger_id, &number],
        )
        .map_err(database_error)?
        .ok_or(ExportError::Absent)?;
    let status: String = row.get(2);
    let response: Option<Vec<u8>> = row.get(3);
    if status != "verified" || response.as_ref().is_none_or(Vec::is_empty) {
        return Err(if status == "queued" {
            ExportError::Pending
        } else {
            ExportError::Unavailable
        });
    }
    let response = response.ok_or(ExportError::Unavailable)?;
    let records = transaction
        .query(
            "SELECT record_cbor FROM trackone_vtl_sealed_record \
             WHERE ledger_id=$1 AND segment_number=$2::text::numeric ORDER BY ordinal",
            &[&ledger_id, &number],
        )
        .map_err(database_error)?
        .into_iter()
        .map(|record| record.get(0))
        .collect();
    let predecessor = if segment_number == 0 {
        None
    } else {
        let previous = (segment_number - 1).to_string();
        Some(
            transaction
                .query_opt(
                    "SELECT artifact_cbor FROM trackone_vtl_sealed_segment \
                     WHERE ledger_id=$1 AND segment_number=$2::text::numeric",
                    &[&ledger_id, &previous],
                )
                .map_err(database_error)?
                .ok_or_else(|| ExportError::Invalid("immediate predecessor was not found".into()))?
                .get(0),
        )
    };
    transaction.commit().map_err(database_error)?;
    Ok(SnapshotMaterial {
        artifact: row.get(0),
        artifact_sha256: row.get(1),
        predecessor,
        records,
        tsa_response: response,
    })
}

fn prepare_export(
    ledger_id: &str,
    segment_number: u64,
    class: DisclosureClass,
    selected_batches: &BTreeSet<u64>,
    material: SnapshotMaterial,
) -> Result<PreparedExport, ExportError> {
    if class != DisclosureClass::B && !selected_batches.is_empty() {
        return Err(ExportError::Invalid(
            "--batch is valid only with disclosure class B".into(),
        ));
    }
    if sha256_hex(&material.artifact) != material.artifact_sha256 {
        return Err(ExportError::Invalid(
            "stored artifact bytes do not match the stored artifact digest".into(),
        ));
    }
    let segment = decode_segment_record(&material.artifact)
        .map_err(|error| ExportError::Invalid(format!("stored segment is invalid: {error}")))?;
    if segment.ledger_id != ledger_id || segment.segment_number != segment_number {
        return Err(ExportError::Invalid(
            "stored segment identity does not match the requested segment".into(),
        ));
    }
    if u64::try_from(material.records.len()) != Ok(segment.record_count) {
        return Err(ExportError::Invalid(
            "retained-record count does not match the sealed artifact".into(),
        ));
    }
    for record in &material.records {
        validate_canonical_record(record).map_err(|error| {
            ExportError::Invalid(format!("retained canonical record is invalid: {error}"))
        })?;
    }
    let computed = merkle_root_from_records(&material.records);
    let batch_roots = batch_roots_from_leaf_hashes(
        &computed.leaf_hashes,
        segment.closure_policy.batch_record_limit,
    )
    .ok_or_else(|| ExportError::Invalid("stored batch policy is unsupported".into()))?;
    if computed.root != segment.segment_root || batch_roots != segment.batch_roots {
        return Err(ExportError::Invalid(
            "retained records do not reproduce the sealed artifact".into(),
        ));
    }
    if let Some(predecessor) = &material.predecessor {
        let predecessor_record = decode_segment_record(predecessor).map_err(|error| {
            ExportError::Invalid(format!("stored predecessor is invalid: {error}"))
        })?;
        if predecessor_record.ledger_id != ledger_id
            || predecessor_record.segment_number.checked_add(1) != Some(segment_number)
            || sha256_digest(predecessor) != segment.prev_segment_sha256
        {
            return Err(ExportError::Invalid(
                "stored predecessor does not match the sealed artifact chain".into(),
            ));
        }
    }

    let batch_count = u64::try_from(segment.batch_roots.len())
        .map_err(|_| ExportError::Invalid("batch count exceeds uint64".into()))?;
    let disclosed = match class {
        DisclosureClass::A => (0..batch_count).collect::<BTreeSet<_>>(),
        DisclosureClass::B => {
            if batch_count <= 1
                || selected_batches.is_empty()
                || u64::try_from(selected_batches.len()) == Ok(batch_count)
                || selected_batches.iter().any(|number| *number >= batch_count)
            {
                return Err(ExportError::Invalid(
                    "class B requires a non-empty proper subset of complete batch numbers".into(),
                ));
            }
            selected_batches.clone()
        }
        DisclosureClass::C => BTreeSet::new(),
    };

    // Stable duplicate-preserving occurrence order: leaf digest, then original
    // ordinal. The digest ordering is the authoritative global batch partition.
    let mut ordered = material
        .records
        .iter()
        .enumerate()
        .map(|(ordinal, record)| {
            let mut preimage = Vec::with_capacity(record.len() + 1);
            preimage.push(0);
            preimage.extend_from_slice(record);
            (sha256_digest(&preimage), ordinal, record)
        })
        .collect::<Vec<_>>();
    ordered.sort_by_key(|(digest, ordinal, _)| (*digest, *ordinal));
    let batch_limit = usize::try_from(segment.closure_policy.batch_record_limit)
        .map_err(|_| ExportError::Invalid("batch limit exceeds platform capacity".into()))?;

    let mut files = vec![(PathBuf::from("segment.cbor"), material.artifact)];
    let mut openings = Vec::new();
    for batch_number in disclosed {
        let batch_index = usize::try_from(batch_number)
            .map_err(|_| ExportError::Invalid("batch number exceeds platform capacity".into()))?;
        let start = batch_index
            .checked_mul(batch_limit)
            .ok_or_else(|| ExportError::Invalid("batch offset overflow".into()))?;
        let end = (start + batch_limit).min(ordered.len());
        let batch = ordered
            .get(start..end)
            .ok_or_else(|| ExportError::Invalid("selected batch is incomplete".into()))?;
        let mut references = Vec::with_capacity(batch.len());
        for (index, (_, ordinal, record)) in batch.iter().enumerate() {
            let path = format!(
                "records/batch-{batch_number:020}/occurrence-{index:020}-ordinal-{ordinal:020}.cbor"
            );
            files.push((PathBuf::from(&path), (*record).clone()));
            references.push(ArtifactRef {
                path,
                sha256: sha256_hex(record),
            });
        }
        openings.push(RecordBatchOpening {
            batch_number: batch_number.to_string(),
            records: references,
        });
    }

    let predecessor_ref = material.predecessor.map(|bytes| {
        let reference = ArtifactRef {
            path: "predecessor.cbor".into(),
            sha256: sha256_hex(&bytes),
        };
        files.push((PathBuf::from("predecessor.cbor"), bytes));
        reference
    });
    let tsa_ref = ArtifactRef {
        path: "timestamp.tsr".into(),
        sha256: sha256_hex(&material.tsa_response),
    };
    files.push((PathBuf::from("timestamp.tsr"), material.tsa_response));
    let manifest = Manifest {
        version: 1,
        ledger_id: ledger_id.into(),
        segment_number: segment_number.to_string(),
        commitment_profile_id: segment.commitment_profile_id,
        disclosure_class: class.as_str(),
        artifacts: Artifacts {
            segment_cbor: ArtifactRef {
                path: "segment.cbor".into(),
                sha256: material.artifact_sha256,
            },
            predecessor_segment_cbor: predecessor_ref,
            record_batches: (!openings.is_empty()).then_some(openings),
            tsa_tsr: tsa_ref,
        },
        anchoring: Anchoring {
            tsa: TsaState { status: "present" },
        },
    };
    files.push((
        PathBuf::from(MANIFEST_NAME),
        serde_json::to_vec_pretty(&manifest)
            .map_err(|error| ExportError::Invalid(error.to_string()))?,
    ));
    Ok(PreparedExport { files })
}

fn snapshot_parent(output: &Path) -> &Path {
    output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn validate_destination(output: &Path) -> Result<(), ExportError> {
    if output.file_name().is_none() {
        return Err(ExportError::Invalid(
            "output must name a snapshot directory".into(),
        ));
    }
    if output.exists() {
        return Err(ExportError::Invalid(
            "output destination already exists".into(),
        ));
    }
    let parent = snapshot_parent(output);
    if !parent.is_dir() {
        return Err(ExportError::Invalid(
            "output parent directory does not exist".into(),
        ));
    }
    Ok(())
}

fn publish_directory(output: &Path, export: &PreparedExport) -> Result<(), ExportError> {
    let parent = snapshot_parent(output);
    let name = output
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| ExportError::Invalid("output file name must be UTF-8".into()))?;
    let staging_dir = tempfile::Builder::new()
        .prefix(&format!(".{name}."))
        .suffix(".private-staging")
        .tempdir_in(parent)?;
    let staging = staging_dir.path();
    for (relative, bytes) in &export.files {
        let path = staging.join(relative);
        if let Some(directory) = path.parent() {
            fs::create_dir_all(directory)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
            }
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    // Keep the staging tree private until all files are complete. The exporter
    // owns the published tree; read/traverse bits let a separate static host
    // service account serve it after the atomic rename.
    set_serving_permissions(staging)?;
    sync_directories(staging)?;
    #[cfg(target_os = "linux")]
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staging,
        rustix::fs::CWD,
        output,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| ExportError::Io(error.into()))?;
    #[cfg(not(target_os = "linux"))]
    {
        if output.exists() {
            return Err(ExportError::Invalid(
                "output destination already exists".into(),
            ));
        }
        fs::rename(staging, output)?;
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn set_serving_permissions(root: &Path) -> Result<(), ExportError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for entry in fs::read_dir(root)? {
            let path = entry?.path();
            if path.is_dir() {
                set_serving_permissions(&path)?;
            } else {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
            }
        }
        fs::set_permissions(root, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn sync_directories(root: &Path) -> Result<(), ExportError> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            sync_directories(&path)?;
        }
    }
    File::open(root)?.sync_all()?;
    Ok(())
}

fn database_error(error: postgres::Error) -> ExportError {
    ExportError::Database(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trackone_ledger::vtl::{ClosurePolicy, EmptyMode, SegmentRecord};

    fn record(counter: u8) -> Vec<u8> {
        vec![
            0x87, 0x01, 0x48, 0, 0, 0, 0, 0, 0, 0, counter, counter, 0, 0xf6, 0, 0xf6,
        ]
    }

    fn material() -> SnapshotMaterial {
        let records = vec![record(3), record(1), record(1), record(2), record(4)];
        let merkle = merkle_root_from_records(&records);
        let segment = SegmentRecord::new_epoch(
            "b7a1d5e40c6f438e9a75db27c96f31aa",
            ClosurePolicy {
                interval_ms: 60_000,
                batch_record_limit: 2,
                record_limit: Some(5),
                size_limit_bytes: None,
                empty_mode: EmptyMode::Suppress,
            },
            "record_limit",
            5,
            batch_roots_from_leaf_hashes(&merkle.leaf_hashes, 2).unwrap(),
            merkle.root,
        )
        .unwrap()
        .canonical_cbor_bytes()
        .unwrap();
        SnapshotMaterial {
            artifact_sha256: sha256_hex(&segment),
            artifact: segment,
            predecessor: None,
            records,
            tsa_response: b"timestamp".to_vec(),
        }
    }

    #[test]
    fn checked_in_http_bundles_match_shared_builder() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../toolset/vectors/vtl-http-binding");
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../toolset/vectors/vtl-known-answer/vector.json"
        ))
        .unwrap();
        let decode = |value: &str| {
            value
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect::<Vec<_>>()
        };
        for (class, folder) in [
            (DisclosureClass::A, "class-a"),
            (DisclosureClass::B, "class-b"),
            (DisclosureClass::C, "class-c"),
        ] {
            let artifact = decode(vector["segment_cbor_hex"].as_str().unwrap());
            let material = SnapshotMaterial {
                artifact_sha256: sha256_hex(&artifact),
                artifact,
                predecessor: None,
                records: vector["records_cbor_hex"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| decode(v.as_str().unwrap()))
                    .collect(),
                tsa_response: fs::read(root.join(folder).join("timestamp.tsr")).unwrap(),
            };
            let selected = if class == DisclosureClass::B {
                BTreeSet::from([0])
            } else {
                BTreeSet::new()
            };
            let prepared = prepare_export(
                vector["ledger_id"].as_str().unwrap(),
                0,
                class,
                &selected,
                material,
            )
            .unwrap();
            for (path, bytes) in prepared.files {
                assert_eq!(
                    fs::read(root.join(folder).join(&path)).unwrap(),
                    bytes,
                    "{folder}/{}",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn bare_output_name_uses_current_directory() {
        assert_eq!(snapshot_parent(Path::new("snapshot")), Path::new("."));
        assert_eq!(
            snapshot_parent(Path::new("exports/snapshot")),
            Path::new("exports")
        );
    }

    #[test]
    fn publication_is_complete_and_does_not_replace_existing_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("snapshot");
        let prepared = PreparedExport {
            files: vec![(PathBuf::from("records/example.cbor"), b"original".to_vec())],
        };
        validate_destination(&output).unwrap();
        publish_directory(&output, &prepared).unwrap();
        assert_eq!(
            fs::read(output.join("records/example.cbor")).unwrap(),
            b"original"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for directory in [&output, &output.join("records")] {
                assert_eq!(
                    fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                    0o755
                );
            }
            assert_eq!(
                fs::metadata(output.join("records/example.cbor"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o644
            );
        }
        assert!(validate_destination(&output).is_err());
        assert!(publish_directory(&output, &prepared).is_err());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
        assert_eq!(
            fs::read(output.join("records/example.cbor")).unwrap(),
            b"original"
        );
    }

    #[test]
    fn failed_publication_cleans_up_staging_directory() {
        let root = tempfile::tempdir().unwrap();
        let prepared = PreparedExport {
            files: vec![
                (PathBuf::from("duplicate"), vec![1]),
                (PathBuf::from("duplicate"), vec![2]),
            ],
        };
        assert!(publish_directory(&root.path().join("snapshot"), &prepared).is_err());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn class_b_exports_selected_complete_batch_and_preserves_duplicate_occurrences() {
        let prepared = prepare_export(
            "b7a1d5e40c6f438e9a75db27c96f31aa",
            0,
            DisclosureClass::B,
            &BTreeSet::from([0]),
            material(),
        )
        .unwrap();
        let manifest = prepared
            .files
            .iter()
            .find(|(path, _)| path == Path::new(MANIFEST_NAME))
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&manifest.1).unwrap();
        assert_eq!(value["disclosure_class"], "B");
        assert_eq!(
            value["artifacts"]["record_batches"][0]["records"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            prepared
                .files
                .iter()
                .filter(|(path, _)| path.starts_with("records"))
                .count(),
            2
        );
    }

    #[test]
    fn class_c_contains_no_record_openings() {
        let prepared = prepare_export(
            "b7a1d5e40c6f438e9a75db27c96f31aa",
            0,
            DisclosureClass::C,
            &BTreeSet::new(),
            material(),
        )
        .unwrap();
        assert!(
            !prepared
                .files
                .iter()
                .any(|(path, _)| path.starts_with("records"))
        );
    }
}
