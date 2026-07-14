//! Draft -08 segment commitment profile.
//!
//! This module intentionally does not share the v1 day-record types: changing
//! the commitment unit or preimage is a profile change, not a migration of
//! existing artifacts.
use crate::{hex_lower, sha256_digest, sha256_hex};
use std::collections::BTreeMap;

pub const COMMITMENT_PROFILE_ID: &str = "verifiable-telemetry-canonical-cbor-v2";
pub const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentBatchV2 {
    pub ledger_id: String,
    pub site_id: String,
    pub segment_number: u64,
    pub batch_number: u64,
    pub merkle_root: String,
    pub count: u64,
    pub leaf_hashes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosurePolicyV1 {
    pub interval_ms: u64,
    pub batch_record_limit: u64,
    pub record_limit: Option<u64>,
    pub size_limit_bytes: Option<u64>,
    pub empty_mode: EmptyMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmptyMode {
    Emit,
    Suppress,
}
impl EmptyMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Emit => "emit",
            Self::Suppress => "suppress",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentRecordV2 {
    pub ledger_id: String,
    pub site_id: String,
    pub segment_number: u64,
    pub closure_policy: ClosurePolicyV1,
    pub close_reason: String,
    pub prev_segment_sha256: String,
    pub batches: Vec<SegmentBatchV2>,
    pub segment_root: String,
}

/// Stable semantic failure categories for a decoded or constructed v2 segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V2InvariantError {
    SegmentHexField,
    SegmentIdentityOrClosurePolicy,
    EpochPredecessorNotZero,
    SuccessorPredecessorIsZero,
    EmptySegment,
    EmbeddedBatchIdentityOrCardinality,
    BatchLeafHash,
    BatchLeavesUnsorted,
    BatchRootMismatch,
    NonFinalBatchShort,
    BatchPartitionsUnsorted,
    SegmentRootMismatch,
}

impl V2InvariantError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::SegmentHexField => "segment-hex-field",
            Self::SegmentIdentityOrClosurePolicy => "segment-identity-or-closure-policy",
            Self::EpochPredecessorNotZero => "epoch-predecessor-not-zero",
            Self::SuccessorPredecessorIsZero => "successor-predecessor-is-zero",
            Self::EmptySegment => "empty-segment",
            Self::EmbeddedBatchIdentityOrCardinality => "embedded-batch-identity-or-cardinality",
            Self::BatchLeafHash => "batch-leaf-hash",
            Self::BatchLeavesUnsorted => "batch-leaves-unsorted",
            Self::BatchRootMismatch => "batch-root-mismatch",
            Self::NonFinalBatchShort => "non-final-batch-short",
            Self::BatchPartitionsUnsorted => "batch-partitions-unsorted",
            Self::SegmentRootMismatch => "segment-root-mismatch",
        }
    }

    fn from_message(message: &str) -> Option<Self> {
        match message {
            "segment hex field is invalid" => Some(Self::SegmentHexField),
            "segment identity or closure policy is invalid" => {
                Some(Self::SegmentIdentityOrClosurePolicy)
            }
            "epoch segment must use zero predecessor" => Some(Self::EpochPredecessorNotZero),
            "successor segment must have a predecessor" => Some(Self::SuccessorPredecessorIsZero),
            "empty segment is invalid" => Some(Self::EmptySegment),
            "embedded batch identity or cardinality is invalid" => {
                Some(Self::EmbeddedBatchIdentityOrCardinality)
            }
            "invalid batch leaf hash" => Some(Self::BatchLeafHash),
            "batch leaf hashes are not sorted" => Some(Self::BatchLeavesUnsorted),
            "batch root does not match batch leaves" => Some(Self::BatchRootMismatch),
            "only the final batch may be shorter than the batch limit" => {
                Some(Self::NonFinalBatchShort)
            }
            "batch leaves are not consecutive sorted partitions" => {
                Some(Self::BatchPartitionsUnsorted)
            }
            "segment root does not match embedded leaves" => Some(Self::SegmentRootMismatch),
            _ => None,
        }
    }
}

impl core::fmt::Display for V2InvariantError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::SegmentHexField => "segment hex field is invalid",
            Self::SegmentIdentityOrClosurePolicy => "segment identity or closure policy is invalid",
            Self::EpochPredecessorNotZero => "epoch segment must use zero predecessor",
            Self::SuccessorPredecessorIsZero => "successor segment must have a predecessor",
            Self::EmptySegment => "empty segment is invalid",
            Self::EmbeddedBatchIdentityOrCardinality => {
                "embedded batch identity or cardinality is invalid"
            }
            Self::BatchLeafHash => "invalid batch leaf hash",
            Self::BatchLeavesUnsorted => "batch leaf hashes are not sorted",
            Self::BatchRootMismatch => "batch root does not match batch leaves",
            Self::NonFinalBatchShort => "only the final batch may be shorter than the batch limit",
            Self::BatchPartitionsUnsorted => "batch leaves are not consecutive sorted partitions",
            Self::SegmentRootMismatch => "segment root does not match embedded leaves",
        })
    }
}

impl std::error::Error for V2InvariantError {}

/// Profile-visible metadata decoded from an exact canonical-record preimage.
/// Payload semantics remain opaque and outside this profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalRecordMetadataV1 {
    pub version: u8,
    pub device_id: [u8; 8],
    pub fc: u64,
    pub ingest_time: u64,
    pub device_time: Option<u64>,
    pub kind: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleResultV2 {
    pub root: [u8; 32],
    pub leaf_hashes: Vec<[u8; 32]>,
}

/// Stable failure categories for decoding authoritative v2 CBOR artifacts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V2DecodeError {
    Malformed(&'static str),
    NonCanonical(&'static str),
    MissingField(&'static str),
    UnexpectedField(String),
    InvalidField(&'static str),
    Invariant(String),
}

impl core::fmt::Display for V2DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(message)
            | Self::NonCanonical(message)
            | Self::MissingField(message)
            | Self::InvalidField(message) => f.write_str(message),
            Self::UnexpectedField(field) => write!(f, "unexpected v2 segment field: {field}"),
            Self::Invariant(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for V2DecodeError {}

impl V2DecodeError {
    /// Return a stable semantic invariant category when decoding reached the
    /// v2 model but the decoded segment violated a cross-field invariant.
    pub fn invariant_error(&self) -> Option<V2InvariantError> {
        match self {
            Self::Invariant(message) => V2InvariantError::from_message(message),
            _ => None,
        }
    }
}

/// Failures while deriving a valid epoch or successor segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V2ConstructionError {
    InvalidPredecessor(V2DecodeError),
    SegmentNumberExhausted,
    TooManyBatches,
    Invariant(V2InvariantError),
}

impl core::fmt::Display for V2ConstructionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPredecessor(error) => write!(f, "invalid predecessor segment: {error}"),
            Self::SegmentNumberExhausted => f.write_str("segment number is exhausted"),
            Self::TooManyBatches => f.write_str("batch count exceeds uint64"),
            Self::Invariant(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for V2ConstructionError {}

type DecodeResult<T> = core::result::Result<T, V2DecodeError>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum CborValue {
    Uint(u64),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(String, CborValue)>),
    Null,
}
impl MerkleResultV2 {
    pub fn root_hex(&self) -> String {
        hex_lower(&self.root)
    }
}

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

/// Reduce an already sorted list of v2 leaf hashes using the profile's
/// recursive split rule. This is primarily used when constructing the
/// authoritative per-batch metadata after records have been globally sorted.
pub fn merkle_root_from_leaf_hashes(leaves: &[[u8; 32]]) -> [u8; 32] {
    mth(leaves)
}

/// Compute the draft -08, domain-separated, hash-sorted multiset tree.
pub fn merkle_root_from_records(records: &[Vec<u8>]) -> MerkleResultV2 {
    let mut leaf_hashes = records
        .iter()
        .map(|record| prefixed_hash(0, record))
        .collect::<Vec<_>>();
    leaf_hashes.sort_unstable();
    MerkleResultV2 {
        root: mth(&leaf_hashes),
        leaf_hashes,
    }
}

fn put_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let p = major << 5;
    match n {
        0..=23 => out.push(p | n as u8),
        24..=0xff => {
            out.push(p | 24);
            out.push(n as u8);
        }
        0x100..=0xffff => {
            out.push(p | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(p | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(p | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}
fn cbor_uint(out: &mut Vec<u8>, value: u64) {
    put_head(out, 0, value);
}
fn cbor_text(out: &mut Vec<u8>, value: &str) {
    put_head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}
fn cbor_null(out: &mut Vec<u8>) {
    out.push(0xf6);
}
fn cbor_map<F: FnOnce(&mut Vec<u8>)>(out: &mut Vec<u8>, len: u64, body: F) {
    put_head(out, 5, len);
    body(out);
}
fn cbor_array<F: FnOnce(&mut Vec<u8>)>(out: &mut Vec<u8>, len: u64, body: F) {
    put_head(out, 4, len);
    body(out);
}
fn key(out: &mut Vec<u8>, key: &str) {
    cbor_text(out, key);
}

fn valid_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_close_reason(value: &str) -> bool {
    matches!(
        value,
        "interval"
            | "reconfigure"
            | "record_limit"
            | "size_limit"
            | "shutdown"
            | "recovery"
            | "manual"
    )
}

impl SegmentRecordV2 {
    /// Construct a validated epoch segment and propagate its identity into all
    /// embedded batches.
    pub fn new_epoch(
        ledger_id: impl Into<String>,
        site_id: impl Into<String>,
        closure_policy: ClosurePolicyV1,
        close_reason: impl Into<String>,
        batches: Vec<SegmentBatchV2>,
        segment_root: impl Into<String>,
    ) -> Result<Self, V2ConstructionError> {
        Self::new_at_position(
            ledger_id.into(),
            site_id.into(),
            0,
            ZERO_SHA256.to_string(),
            closure_policy,
            close_reason.into(),
            batches,
            segment_root.into(),
        )
    }

    /// Construct a validated successor from the predecessor's exact canonical
    /// artifact bytes. Ledger/site identity, serial, and predecessor digest are
    /// derived rather than accepted independently.
    pub fn new_successor(
        predecessor_bytes: &[u8],
        closure_policy: ClosurePolicyV1,
        close_reason: impl Into<String>,
        batches: Vec<SegmentBatchV2>,
        segment_root: impl Into<String>,
    ) -> Result<Self, V2ConstructionError> {
        let predecessor = decode_segment_record_v2(predecessor_bytes)
            .map_err(V2ConstructionError::InvalidPredecessor)?;
        let segment_number = predecessor
            .segment_number
            .checked_add(1)
            .ok_or(V2ConstructionError::SegmentNumberExhausted)?;
        Self::new_at_position(
            predecessor.ledger_id,
            predecessor.site_id,
            segment_number,
            sha256_hex(predecessor_bytes),
            closure_policy,
            close_reason.into(),
            batches,
            segment_root.into(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_at_position(
        ledger_id: String,
        site_id: String,
        segment_number: u64,
        prev_segment_sha256: String,
        closure_policy: ClosurePolicyV1,
        close_reason: String,
        mut batches: Vec<SegmentBatchV2>,
        segment_root: String,
    ) -> Result<Self, V2ConstructionError> {
        for (number, batch) in batches.iter_mut().enumerate() {
            batch.ledger_id.clone_from(&ledger_id);
            batch.site_id.clone_from(&site_id);
            batch.segment_number = segment_number;
            batch.batch_number =
                u64::try_from(number).map_err(|_| V2ConstructionError::TooManyBatches)?;
        }
        let segment = Self {
            ledger_id,
            site_id,
            segment_number,
            closure_policy,
            close_reason,
            prev_segment_sha256,
            batches,
            segment_root,
        };
        segment
            .validate_detailed()
            .map_err(V2ConstructionError::Invariant)?;
        Ok(segment)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validate_detailed().map_err(|error| error.to_string())
    }

    pub fn validate_detailed(&self) -> Result<(), V2InvariantError> {
        if !valid_hex(&self.ledger_id, 32)
            || !valid_hex(&self.prev_segment_sha256, 64)
            || !valid_hex(&self.segment_root, 64)
        {
            return Err(V2InvariantError::SegmentHexField);
        }
        if self.site_id.is_empty()
            || self.closure_policy.interval_ms == 0
            || self.closure_policy.batch_record_limit == 0
            || self.closure_policy.record_limit == Some(0)
            || self.closure_policy.size_limit_bytes == Some(0)
            || !valid_close_reason(&self.close_reason)
        {
            return Err(V2InvariantError::SegmentIdentityOrClosurePolicy);
        }
        if self.segment_number == 0 && self.prev_segment_sha256 != ZERO_SHA256 {
            return Err(V2InvariantError::EpochPredecessorNotZero);
        }
        if self.segment_number != 0 && self.prev_segment_sha256 == ZERO_SHA256 {
            return Err(V2InvariantError::SuccessorPredecessorIsZero);
        }
        if self.batches.is_empty() {
            if self.closure_policy.empty_mode != EmptyMode::Emit
                || self.segment_root != sha256_hex(b"")
            {
                return Err(V2InvariantError::EmptySegment);
            }
            return Ok(());
        }
        let mut leaves = Vec::new();
        for (number, batch) in self.batches.iter().enumerate() {
            if batch.ledger_id != self.ledger_id
                || batch.site_id != self.site_id
                || batch.segment_number != self.segment_number
                || batch.batch_number != number as u64
                || batch.count == 0
                || batch.count as usize != batch.leaf_hashes.len()
                || batch.count > self.closure_policy.batch_record_limit
            {
                return Err(V2InvariantError::EmbeddedBatchIdentityOrCardinality);
            }
            if batch.leaf_hashes.iter().any(|hash| !valid_hex(hash, 64)) {
                return Err(V2InvariantError::BatchLeafHash);
            }
            if batch.leaf_hashes.windows(2).any(|pair| pair[0] > pair[1]) {
                return Err(V2InvariantError::BatchLeavesUnsorted);
            }
            let batch_hashes = batch
                .leaf_hashes
                .iter()
                .map(|hash| decode_hex32(hash))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| V2InvariantError::BatchLeafHash)?;
            if hex_lower(&mth(&batch_hashes)) != batch.merkle_root {
                return Err(V2InvariantError::BatchRootMismatch);
            }
            if number + 1 != self.batches.len()
                && batch.count != self.closure_policy.batch_record_limit
            {
                return Err(V2InvariantError::NonFinalBatchShort);
            }
            leaves.extend(batch.leaf_hashes.iter().cloned());
        }
        if leaves.windows(2).any(|pair| pair[0] > pair[1]) {
            return Err(V2InvariantError::BatchPartitionsUnsorted);
        }
        let hashes = leaves
            .iter()
            .map(|h| decode_hex32(h))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| V2InvariantError::BatchLeafHash)?;
        if hex_lower(&mth(&hashes)) != self.segment_root {
            return Err(V2InvariantError::SegmentRootMismatch);
        }
        Ok(())
    }

    /// Canonical deterministic CBOR bytes for the authoritative artifact.
    pub fn canonical_cbor_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut out = Vec::new();
        // Keys are emitted in RFC 8949 deterministic text-key order.
        cbor_map(&mut out, 10, |out| {
            key(out, "batches");
            cbor_array(out, self.batches.len() as u64, |out| {
                for batch in &self.batches {
                    encode_batch(out, batch)
                }
            });
            key(out, "site_id");
            cbor_text(out, &self.site_id);
            key(out, "version");
            cbor_uint(out, 2);
            key(out, "ledger_id");
            cbor_text(out, &self.ledger_id);
            key(out, "close_reason");
            cbor_text(out, &self.close_reason);
            key(out, "segment_root");
            cbor_text(out, &self.segment_root);
            key(out, "closure_policy");
            encode_policy(out, &self.closure_policy);
            key(out, "segment_number");
            cbor_uint(out, self.segment_number);
            key(out, "prev_segment_sha256");
            cbor_text(out, &self.prev_segment_sha256);
            key(out, "commitment_profile_id");
            cbor_text(out, COMMITMENT_PROFILE_ID);
        });
        Ok(out)
    }
    pub fn sha256(&self) -> Result<String, String> {
        Ok(sha256_hex(&self.canonical_cbor_bytes()?))
    }
}

/// Decode and validate one authoritative draft-08 segment artifact.
///
/// This accepts only the constrained deterministic-CBOR subset used by the
/// segment schema.  It never decodes and re-encodes a malformed input into a
/// seemingly valid artifact: the decoded value must reproduce the supplied
/// bytes exactly.
pub fn decode_segment_record_v2(bytes: &[u8]) -> DecodeResult<SegmentRecordV2> {
    let mut pos = 0;
    let value = parse_cbor_value(bytes, &mut pos)?;
    if pos != bytes.len() {
        return Err(V2DecodeError::Malformed("segment CBOR has trailing bytes"));
    }
    let mut fields = into_map(value)?;
    let version = take_uint(&mut fields, "version")?;
    if version != 2 {
        return Err(V2DecodeError::InvalidField("segment version must be 2"));
    }
    let profile = take_text(&mut fields, "commitment_profile_id")?;
    if profile != COMMITMENT_PROFILE_ID {
        return Err(V2DecodeError::InvalidField(
            "unsupported commitment profile",
        ));
    }
    let ledger_id = take_text(&mut fields, "ledger_id")?;
    let site_id = take_text(&mut fields, "site_id")?;
    let segment_number = take_uint(&mut fields, "segment_number")?;
    let closure_policy = decode_policy(take(&mut fields, "closure_policy")?)?;
    let close_reason = take_text(&mut fields, "close_reason")?;
    let prev_segment_sha256 = take_text(&mut fields, "prev_segment_sha256")?;
    let batches = decode_batches(take(&mut fields, "batches")?)?;
    let segment_root = take_text(&mut fields, "segment_root")?;
    if let Some(field) = fields.into_keys().next() {
        return Err(V2DecodeError::UnexpectedField(field));
    }
    let record = SegmentRecordV2 {
        ledger_id,
        site_id,
        segment_number,
        closure_policy,
        close_reason,
        prev_segment_sha256,
        batches,
        segment_root,
    };
    record
        .validate_detailed()
        .map_err(|error| V2DecodeError::Invariant(error.to_string()))?;
    let canonical = record
        .canonical_cbor_bytes()
        .map_err(V2DecodeError::Invariant)?;
    if canonical != bytes {
        return Err(V2DecodeError::NonCanonical(
            "segment CBOR does not round-trip canonically",
        ));
    }
    Ok(record)
}

/// Validate the exact seven-element canonical-record array used by the v2
/// commitment profile and return only its profile-visible metadata.
pub fn validate_canonical_record_v2(bytes: &[u8]) -> DecodeResult<CanonicalRecordMetadataV1> {
    let mut pos = 0;
    let (major, len) = read_typed_argument(bytes, &mut pos)?;
    if major != 4 || len != 7 {
        return Err(V2DecodeError::InvalidField(
            "canonical record must be a seven-element array",
        ));
    }
    let version = read_uint_item(bytes, &mut pos, "record version")?;
    if version != 1 {
        return Err(V2DecodeError::InvalidField("record version must be 1"));
    }
    let device_id = read_device_id(bytes, &mut pos)?;
    let fc = read_uint_item(bytes, &mut pos, "fc")?;
    let ingest_time = read_uint_item(bytes, &mut pos, "ingest_time")?;
    let device_time = if bytes.get(pos) == Some(&0xf6) {
        pos += 1;
        None
    } else {
        Some(read_uint_item(bytes, &mut pos, "device_time")?)
    };
    let kind = read_uint_item(bytes, &mut pos, "kind")?;
    validate_commitment_value(bytes, &mut pos)?;
    if pos != bytes.len() {
        return Err(V2DecodeError::Malformed(
            "canonical record has trailing bytes",
        ));
    }
    Ok(CanonicalRecordMetadataV1 {
        version: 1,
        device_id,
        fc,
        ingest_time,
        device_time,
        kind,
    })
}

fn read_typed_argument(bytes: &[u8], pos: &mut usize) -> DecodeResult<(u8, u64)> {
    let initial = *bytes
        .get(*pos)
        .ok_or(V2DecodeError::Malformed("truncated CBOR item"))?;
    *pos += 1;
    Ok((
        initial >> 5,
        read_cbor_argument(bytes, pos, initial & 0x1f)?,
    ))
}

fn read_uint_item(bytes: &[u8], pos: &mut usize, field: &'static str) -> DecodeResult<u64> {
    let (major, value) = read_typed_argument(bytes, pos)?;
    if major != 0 {
        return Err(V2DecodeError::InvalidField(field));
    }
    Ok(value)
}

fn read_device_id(bytes: &[u8], pos: &mut usize) -> DecodeResult<[u8; 8]> {
    let (major, len) = read_typed_argument(bytes, pos)?;
    if major != 2 || len != 8 {
        return Err(V2DecodeError::InvalidField(
            "device_id must be an eight-byte string",
        ));
    }
    let end = pos
        .checked_add(8)
        .filter(|end| *end <= bytes.len())
        .ok_or(V2DecodeError::Malformed("truncated device_id"))?;
    let mut device_id = [0u8; 8];
    device_id.copy_from_slice(&bytes[*pos..end]);
    *pos = end;
    Ok(device_id)
}

fn validate_commitment_value(bytes: &[u8], pos: &mut usize) -> DecodeResult<()> {
    let start = *pos;
    let initial = *bytes
        .get(*pos)
        .ok_or(V2DecodeError::Malformed("truncated CBOR payload item"))?;
    *pos += 1;
    let major = initial >> 5;
    let ai = initial & 0x1f;
    if major == 7 {
        return validate_simple_or_float(bytes, pos, start, ai);
    }
    let len = read_cbor_argument(bytes, pos, ai)?;
    match major {
        0 | 1 => Ok(()),
        2 | 3 => {
            let width = usize::try_from(len)
                .map_err(|_| V2DecodeError::Malformed("CBOR string length overflows platform"))?;
            let end = pos
                .checked_add(width)
                .filter(|end| *end <= bytes.len())
                .ok_or(V2DecodeError::Malformed("truncated CBOR string"))?;
            if major == 3 {
                core::str::from_utf8(&bytes[*pos..end])
                    .map_err(|_| V2DecodeError::Malformed("CBOR text is not UTF-8"))?;
            }
            *pos = end;
            Ok(())
        }
        4 => {
            for _ in 0..len {
                validate_commitment_value(bytes, pos)?;
            }
            Ok(())
        }
        5 => validate_commitment_map(bytes, pos, len),
        6 => Err(V2DecodeError::InvalidField(
            "CBOR tags are not permitted in commitment bytes",
        )),
        _ => Err(V2DecodeError::Malformed("invalid CBOR major type")),
    }
}

fn validate_commitment_map(bytes: &[u8], pos: &mut usize, len: u64) -> DecodeResult<()> {
    let mut previous_key: Option<Vec<u8>> = None;
    for _ in 0..len {
        let key_start = *pos;
        let initial = *bytes
            .get(*pos)
            .ok_or(V2DecodeError::Malformed("truncated CBOR map key"))?;
        *pos += 1;
        if initial >> 5 != 3 {
            return Err(V2DecodeError::InvalidField(
                "commitment map keys must be text",
            ));
        }
        let key_len = read_cbor_argument(bytes, pos, initial & 0x1f)?;
        let width = usize::try_from(key_len)
            .map_err(|_| V2DecodeError::Malformed("CBOR map key length overflows platform"))?;
        let end = pos
            .checked_add(width)
            .filter(|end| *end <= bytes.len())
            .ok_or(V2DecodeError::Malformed("truncated CBOR map key"))?;
        core::str::from_utf8(&bytes[*pos..end])
            .map_err(|_| V2DecodeError::Malformed("CBOR map key is not UTF-8"))?;
        *pos = end;
        let raw_key = bytes[key_start..end].to_vec();
        if let Some(previous) = &previous_key
            && (previous.len() > raw_key.len()
                || (previous.len() == raw_key.len() && previous >= &raw_key))
        {
            return Err(V2DecodeError::NonCanonical(
                "CBOR map keys are not in deterministic order",
            ));
        }
        previous_key = Some(raw_key);
        validate_commitment_value(bytes, pos)?;
    }
    Ok(())
}

fn validate_simple_or_float(
    bytes: &[u8],
    pos: &mut usize,
    start: usize,
    ai: u8,
) -> DecodeResult<()> {
    match ai {
        20..=22 => Ok(()),
        25 => {
            let bits = read_fixed::<2>(bytes, pos)?;
            validate_float_encoding(bytes, start, *pos, decode_f16(u16::from_be_bytes(bits)))
        }
        26 => {
            let bits = read_fixed::<4>(bytes, pos)?;
            validate_float_encoding(
                bytes,
                start,
                *pos,
                f32::from_bits(u32::from_be_bytes(bits)) as f64,
            )
        }
        27 => {
            let bits = read_fixed::<8>(bytes, pos)?;
            validate_float_encoding(bytes, start, *pos, f64::from_bits(u64::from_be_bytes(bits)))
        }
        _ => Err(V2DecodeError::InvalidField("unsupported CBOR simple value")),
    }
}

fn read_fixed<const N: usize>(bytes: &[u8], pos: &mut usize) -> DecodeResult<[u8; N]> {
    let end = pos
        .checked_add(N)
        .filter(|end| *end <= bytes.len())
        .ok_or(V2DecodeError::Malformed("truncated CBOR float"))?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*pos..end]);
    *pos = end;
    Ok(out)
}

fn decode_f16(bits: u16) -> f64 {
    let sign = if bits & 0x8000 == 0 { 1.0 } else { -1.0 };
    let exponent = (bits >> 10) & 0x1f;
    let fraction = bits & 0x03ff;
    match exponent {
        0 => sign * (fraction as f64) * 2f64.powi(-24),
        31 if fraction == 0 => sign * f64::INFINITY,
        31 => f64::NAN,
        _ => sign * (1.0 + (fraction as f64) / 1024.0) * 2f64.powi(exponent as i32 - 15),
    }
}

fn validate_float_encoding(bytes: &[u8], start: usize, end: usize, value: f64) -> DecodeResult<()> {
    let canonical = crate::canonical_cbor::canonical_float_bytes(value)
        .map_err(|_| V2DecodeError::InvalidField("non-finite CBOR float"))?;
    if canonical != bytes[start..end] {
        return Err(V2DecodeError::NonCanonical(
            "CBOR float is not encoded at its shortest exact width",
        ));
    }
    Ok(())
}

fn parse_cbor_value(bytes: &[u8], pos: &mut usize) -> DecodeResult<CborValue> {
    let initial = *bytes
        .get(*pos)
        .ok_or(V2DecodeError::Malformed("truncated CBOR item"))?;
    *pos += 1;
    let major = initial >> 5;
    let len = read_cbor_argument(bytes, pos, initial & 0x1f)?;
    match major {
        0 => Ok(CborValue::Uint(len)),
        3 => {
            let end =
                pos.checked_add(usize::try_from(len).map_err(|_| {
                    V2DecodeError::Malformed("CBOR text length overflows platform")
                })?)
                .filter(|end| *end <= bytes.len())
                .ok_or(V2DecodeError::Malformed("truncated CBOR text"))?;
            let text = core::str::from_utf8(&bytes[*pos..end])
                .map_err(|_| V2DecodeError::Malformed("CBOR text is not UTF-8"))?
                .to_owned();
            *pos = end;
            Ok(CborValue::Text(text))
        }
        4 => {
            let mut items =
                Vec::with_capacity(usize::try_from(len).map_err(|_| {
                    V2DecodeError::Malformed("CBOR array length overflows platform")
                })?);
            for _ in 0..len {
                items.push(parse_cbor_value(bytes, pos)?);
            }
            Ok(CborValue::Array(items))
        }
        5 => {
            let mut entries = Vec::with_capacity(
                usize::try_from(len)
                    .map_err(|_| V2DecodeError::Malformed("CBOR map length overflows platform"))?,
            );
            let mut previous_key: Option<Vec<u8>> = None;
            for _ in 0..len {
                let start = *pos;
                let key = parse_cbor_value(bytes, pos)?;
                let raw_key = bytes[start..*pos].to_vec();
                if let Some(previous) = &previous_key
                    && (previous.len() > raw_key.len()
                        || (previous.len() == raw_key.len() && previous >= &raw_key))
                {
                    return Err(V2DecodeError::NonCanonical(
                        "CBOR map keys are not in deterministic order",
                    ));
                }
                let CborValue::Text(key) = key else {
                    return Err(V2DecodeError::InvalidField("segment map keys must be text"));
                };
                previous_key = Some(raw_key);
                entries.push((key, parse_cbor_value(bytes, pos)?));
            }
            Ok(CborValue::Map(entries))
        }
        7 if initial & 0x1f == 22 => Ok(CborValue::Null),
        1 | 2 | 6 | 7 => Err(V2DecodeError::InvalidField(
            "unsupported CBOR value in segment artifact",
        )),
        _ => Err(V2DecodeError::Malformed("invalid CBOR major type")),
    }
}

fn read_cbor_argument(bytes: &[u8], pos: &mut usize, ai: u8) -> DecodeResult<u64> {
    let read = |width: usize, pos: &mut usize| -> DecodeResult<&[u8]> {
        let end = pos
            .checked_add(width)
            .filter(|end| *end <= bytes.len())
            .ok_or(V2DecodeError::Malformed("truncated CBOR argument"))?;
        let part = &bytes[*pos..end];
        *pos = end;
        Ok(part)
    };
    match ai {
        value @ 0..=23 => Ok(value as u64),
        24 => {
            let value = read(1, pos)?[0] as u64;
            if value < 24 {
                Err(V2DecodeError::NonCanonical("CBOR argument is not shortest"))
            } else {
                Ok(value)
            }
        }
        25 => {
            let part = read(2, pos)?;
            let value = u16::from_be_bytes([part[0], part[1]]) as u64;
            if value <= u8::MAX as u64 {
                Err(V2DecodeError::NonCanonical("CBOR argument is not shortest"))
            } else {
                Ok(value)
            }
        }
        26 => {
            let part = read(4, pos)?;
            let value = u32::from_be_bytes([part[0], part[1], part[2], part[3]]) as u64;
            if value <= u16::MAX as u64 {
                Err(V2DecodeError::NonCanonical("CBOR argument is not shortest"))
            } else {
                Ok(value)
            }
        }
        27 => {
            let part = read(8, pos)?;
            let value = u64::from_be_bytes([
                part[0], part[1], part[2], part[3], part[4], part[5], part[6], part[7],
            ]);
            if value <= u32::MAX as u64 {
                Err(V2DecodeError::NonCanonical("CBOR argument is not shortest"))
            } else {
                Ok(value)
            }
        }
        _ => Err(V2DecodeError::NonCanonical(
            "indefinite or reserved CBOR argument",
        )),
    }
}

fn into_map(value: CborValue) -> DecodeResult<BTreeMap<String, CborValue>> {
    let CborValue::Map(entries) = value else {
        return Err(V2DecodeError::InvalidField(
            "segment artifact must be a CBOR map",
        ));
    };
    Ok(entries.into_iter().collect())
}
fn take(fields: &mut BTreeMap<String, CborValue>, name: &'static str) -> DecodeResult<CborValue> {
    fields.remove(name).ok_or(V2DecodeError::MissingField(name))
}
fn take_text(fields: &mut BTreeMap<String, CborValue>, name: &'static str) -> DecodeResult<String> {
    let CborValue::Text(value) = take(fields, name)? else {
        return Err(V2DecodeError::InvalidField(name));
    };
    Ok(value)
}
fn take_uint(fields: &mut BTreeMap<String, CborValue>, name: &'static str) -> DecodeResult<u64> {
    let CborValue::Uint(value) = take(fields, name)? else {
        return Err(V2DecodeError::InvalidField(name));
    };
    Ok(value)
}
fn optional_positive(
    fields: &mut BTreeMap<String, CborValue>,
    name: &'static str,
) -> DecodeResult<Option<u64>> {
    match take(fields, name)? {
        CborValue::Null => Ok(None),
        CborValue::Uint(value) if value > 0 => Ok(Some(value)),
        _ => Err(V2DecodeError::InvalidField(name)),
    }
}

fn decode_policy(value: CborValue) -> DecodeResult<ClosurePolicyV1> {
    let mut fields = into_map(value)?;
    if take_uint(&mut fields, "version")? != 1 {
        return Err(V2DecodeError::InvalidField(
            "closure policy version must be 1",
        ));
    }
    let interval_ms = take_uint(&mut fields, "interval_ms")?;
    let batch_record_limit = take_uint(&mut fields, "batch_record_limit")?;
    if interval_ms == 0 || batch_record_limit == 0 {
        return Err(V2DecodeError::InvalidField(
            "closure policy limits must be positive",
        ));
    }
    let record_limit = optional_positive(&mut fields, "record_limit")?;
    let size_limit_bytes = optional_positive(&mut fields, "size_limit_bytes")?;
    let empty_mode = match take_text(&mut fields, "empty_mode")?.as_str() {
        "emit" => EmptyMode::Emit,
        "suppress" => EmptyMode::Suppress,
        _ => return Err(V2DecodeError::InvalidField("invalid empty_mode")),
    };
    if let Some(field) = fields.into_keys().next() {
        return Err(V2DecodeError::UnexpectedField(field));
    }
    Ok(ClosurePolicyV1 {
        interval_ms,
        batch_record_limit,
        record_limit,
        size_limit_bytes,
        empty_mode,
    })
}

fn decode_batches(value: CborValue) -> DecodeResult<Vec<SegmentBatchV2>> {
    let CborValue::Array(items) = value else {
        return Err(V2DecodeError::InvalidField("batches"));
    };
    items.into_iter().map(decode_batch).collect()
}
fn decode_batch(value: CborValue) -> DecodeResult<SegmentBatchV2> {
    let mut fields = into_map(value)?;
    if take_uint(&mut fields, "version")? != 2 {
        return Err(V2DecodeError::InvalidField("batch version must be 2"));
    }
    let ledger_id = take_text(&mut fields, "ledger_id")?;
    let site_id = take_text(&mut fields, "site_id")?;
    let segment_number = take_uint(&mut fields, "segment_number")?;
    let batch_number = take_uint(&mut fields, "batch_number")?;
    let merkle_root = take_text(&mut fields, "merkle_root")?;
    let count = take_uint(&mut fields, "count")?;
    let CborValue::Array(items) = take(&mut fields, "leaf_hashes")? else {
        return Err(V2DecodeError::InvalidField("leaf_hashes"));
    };
    let mut leaf_hashes = Vec::with_capacity(items.len());
    for item in items {
        let CborValue::Text(hash) = item else {
            return Err(V2DecodeError::InvalidField("leaf_hashes"));
        };
        leaf_hashes.push(hash);
    }
    if let Some(field) = fields.into_keys().next() {
        return Err(V2DecodeError::UnexpectedField(field));
    }
    Ok(SegmentBatchV2 {
        ledger_id,
        site_id,
        segment_number,
        batch_number,
        merkle_root,
        count,
        leaf_hashes,
    })
}

fn encode_policy(out: &mut Vec<u8>, policy: &ClosurePolicyV1) {
    cbor_map(out, 6, |out| {
        key(out, "version");
        cbor_uint(out, 1);
        key(out, "empty_mode");
        cbor_text(out, policy.empty_mode.as_str());
        key(out, "interval_ms");
        cbor_uint(out, policy.interval_ms);
        key(out, "record_limit");
        match policy.record_limit {
            Some(v) => cbor_uint(out, v),
            None => cbor_null(out),
        };
        key(out, "size_limit_bytes");
        match policy.size_limit_bytes {
            Some(v) => cbor_uint(out, v),
            None => cbor_null(out),
        };
        key(out, "batch_record_limit");
        cbor_uint(out, policy.batch_record_limit);
    });
}
fn encode_batch(out: &mut Vec<u8>, batch: &SegmentBatchV2) {
    cbor_map(out, 8, |out| {
        key(out, "count");
        cbor_uint(out, batch.count);
        key(out, "site_id");
        cbor_text(out, &batch.site_id);
        key(out, "version");
        cbor_uint(out, 2);
        key(out, "ledger_id");
        cbor_text(out, &batch.ledger_id);
        key(out, "leaf_hashes");
        cbor_array(out, batch.leaf_hashes.len() as u64, |out| {
            for h in &batch.leaf_hashes {
                cbor_text(out, h)
            }
        });
        key(out, "merkle_root");
        cbor_text(out, &batch.merkle_root);
        key(out, "batch_number");
        cbor_uint(out, batch.batch_number);
        key(out, "segment_number");
        cbor_uint(out, batch.segment_number);
    });
}
fn decode_hex32(text: &str) -> Result<[u8; 32], String> {
    if !valid_hex(text, 64) {
        return Err("invalid hex".into());
    };
    let mut out = [0; 32];
    for (i, chunk) in text.as_bytes().chunks_exact(2).enumerate() {
        out[i] = u8::from_str_radix(core::str::from_utf8(chunk).map_err(|_| "invalid hex")?, 16)
            .map_err(|_| "invalid hex")?
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_with_payload(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![
            0x87, 0x01, 0x48, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0x00, 0xf6, 0x00,
        ];
        record.extend_from_slice(payload);
        record
    }

    fn epoch_segment() -> SegmentRecordV2 {
        let records = vec![hex::decode("87014800000000000000010100f600f6").unwrap()];
        let merkle = merkle_root_from_records(&records);
        let leaf = hex_lower(&merkle.leaf_hashes[0]);
        SegmentRecordV2::new_epoch(
            "b7a1d5e40c6f438e9a75db27c96f31aa",
            "an-001",
            ClosurePolicyV1 {
                interval_ms: 60_000,
                batch_record_limit: 1,
                record_limit: None,
                size_limit_bytes: None,
                empty_mode: EmptyMode::Suppress,
            },
            "interval",
            vec![SegmentBatchV2 {
                ledger_id: String::new(),
                site_id: String::new(),
                segment_number: u64::MAX,
                batch_number: u64::MAX,
                merkle_root: leaf.clone(),
                count: 1,
                leaf_hashes: vec![leaf],
            }],
            merkle.root_hex(),
        )
        .unwrap()
    }

    #[test]
    fn compact_draft_leaves_match() {
        let records = vec![
            hex::decode("87014800000000000000010100f600f6").unwrap(),
            hex::decode("87014800000000000000020201f600f6").unwrap(),
            hex::decode("87014800000000000000030302f600f6").unwrap(),
        ];
        for record in &records {
            validate_canonical_record_v2(record).unwrap();
        }
        let r = merkle_root_from_records(&records);
        assert_eq!(
            hex_lower(&r.leaf_hashes[0]),
            "4f82e3e7ee90a111774dd951471a31d4582e0908a0bd5fd63c0080c0231f40cc"
        );
        assert_eq!(
            r.root_hex(),
            "bc6502552ed0c515f58d1c632e54db37594042609b59838eb0d5b3d5842aa054"
        );
    }

    #[test]
    fn canonical_record_decoder_accepts_draft_shape_and_payload_subset() {
        let record = record_with_payload(&[
            0xa2, 0x61, b'a', 0xf9, 0x3c, 0x00, 0x62, b'b', b'b', 0x82, 0x20, 0x42, 0xaa, 0xbb,
        ]);
        let metadata = validate_canonical_record_v2(&record).unwrap();
        assert_eq!(metadata.version, 1);
        assert_eq!(metadata.device_id, [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(metadata.fc, 1);
        assert_eq!(metadata.ingest_time, 0);
        assert_eq!(metadata.device_time, None);
        assert_eq!(metadata.kind, 0);
        assert!(
            validate_canonical_record_v2(&record_with_payload(&[0xfa, 0x47, 0xc3, 0x50, 0x00,]))
                .is_ok()
        );
        assert!(
            validate_canonical_record_v2(&record_with_payload(&[
                0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a,
            ]))
            .is_ok()
        );
    }

    #[test]
    fn canonical_record_decoder_rejects_shape_and_cbor_violations() {
        assert!(validate_canonical_record_v2(&[0x80]).is_err());
        assert!(
            validate_canonical_record_v2(&record_with_payload(&[0xfa, 0x3f, 0x80, 0x00, 0x00,]))
                .is_err()
        );
        assert!(validate_canonical_record_v2(&record_with_payload(&[0xf9, 0x7e, 0x00])).is_err());
        assert!(validate_canonical_record_v2(&record_with_payload(&[0xf9, 0x7c, 0x00])).is_err());
        assert!(validate_canonical_record_v2(&record_with_payload(&[0xc0, 0xf6])).is_err());
        assert!(
            validate_canonical_record_v2(&record_with_payload(&[
                0xa2, 0x62, b'b', b'b', 0xf6, 0x61, b'a', 0xf6,
            ]))
            .is_err()
        );
        assert!(
            validate_canonical_record_v2(&record_with_payload(&[
                0xa2, 0x61, b'a', 0xf6, 0x61, b'a', 0xf6,
            ]))
            .is_err()
        );
        assert!(validate_canonical_record_v2(&record_with_payload(&[0x61, 0xff])).is_err());
        assert!(validate_canonical_record_v2(&record_with_payload(&[0x9f, 0xff])).is_err());
    }

    #[test]
    fn segment_validation_preserves_duplicate_record_multiplicity() {
        let record = record_with_payload(&[0xf6]);
        let merkle = merkle_root_from_records(&[record.clone(), record]);
        let leaf = hex_lower(&merkle.leaf_hashes[0]);
        let mut segment = epoch_segment();
        segment.closure_policy.batch_record_limit = 2;
        segment.batches[0].count = 2;
        segment.batches[0].leaf_hashes = vec![leaf.clone(), leaf];
        segment.batches[0].merkle_root = merkle.root_hex();
        segment.segment_root = merkle.root_hex();
        assert!(segment.validate().is_ok());
    }

    #[test]
    fn decoder_round_trips_valid_epoch_segment() {
        let original = epoch_segment();
        let bytes = original.canonical_cbor_bytes().unwrap();
        assert_eq!(decode_segment_record_v2(&bytes).unwrap(), original);
    }

    #[test]
    fn decoder_rejects_trailing_and_noncanonical_bytes() {
        let mut bytes = epoch_segment().canonical_cbor_bytes().unwrap();
        bytes.push(0xf6);
        assert!(matches!(
            decode_segment_record_v2(&bytes),
            Err(V2DecodeError::Malformed("segment CBOR has trailing bytes"))
        ));
        assert!(matches!(
            decode_segment_record_v2(&[0xbf]),
            Err(V2DecodeError::NonCanonical(_))
        ));
    }

    #[test]
    fn model_validation_rejects_successor_zero_predecessor() {
        let mut successor = epoch_segment();
        successor.segment_number = 7;
        successor.batches[0].segment_number = 7;
        assert_eq!(
            successor.validate_detailed(),
            Err(V2InvariantError::SuccessorPredecessorIsZero)
        );
        assert_eq!(
            successor.validate().unwrap_err(),
            "successor segment must have a predecessor"
        );
        assert_eq!(
            V2InvariantError::SuccessorPredecessorIsZero.code(),
            "successor-predecessor-is-zero"
        );
    }

    #[test]
    fn successor_constructor_derives_chain_and_batch_identity() {
        let predecessor = epoch_segment();
        let predecessor_bytes = predecessor.canonical_cbor_bytes().unwrap();
        let mut batch = predecessor.batches[0].clone();
        batch.ledger_id = "wrong".into();
        batch.site_id = "wrong".into();
        batch.segment_number = 99;
        batch.batch_number = 99;

        let successor = SegmentRecordV2::new_successor(
            &predecessor_bytes,
            predecessor.closure_policy.clone(),
            "interval",
            vec![batch],
            predecessor.segment_root.clone(),
        )
        .unwrap();

        assert_eq!(successor.ledger_id, predecessor.ledger_id);
        assert_eq!(successor.site_id, predecessor.site_id);
        assert_eq!(successor.segment_number, 1);
        assert_eq!(
            successor.prev_segment_sha256,
            sha256_hex(&predecessor_bytes)
        );
        assert_eq!(successor.batches[0].ledger_id, successor.ledger_id);
        assert_eq!(successor.batches[0].site_id, successor.site_id);
        assert_eq!(successor.batches[0].segment_number, 1);
        assert_eq!(successor.batches[0].batch_number, 0);
        let bytes = successor.canonical_cbor_bytes().unwrap();
        assert_eq!(decode_segment_record_v2(&bytes).unwrap(), successor);
    }

    #[test]
    fn successor_constructor_rejects_invalid_or_exhausted_predecessors() {
        assert!(matches!(
            SegmentRecordV2::new_successor(
                &[0x80],
                epoch_segment().closure_policy,
                "interval",
                Vec::new(),
                sha256_hex(b""),
            ),
            Err(V2ConstructionError::InvalidPredecessor(_))
        ));

        let mut predecessor = epoch_segment();
        predecessor.segment_number = u64::MAX;
        predecessor.prev_segment_sha256 = "11".repeat(32);
        predecessor.batches[0].segment_number = u64::MAX;
        let predecessor_bytes = predecessor.canonical_cbor_bytes().unwrap();
        assert_eq!(
            SegmentRecordV2::new_successor(
                &predecessor_bytes,
                predecessor.closure_policy.clone(),
                "interval",
                predecessor.batches.clone(),
                predecessor.segment_root.clone(),
            ),
            Err(V2ConstructionError::SegmentNumberExhausted)
        );
    }
}
