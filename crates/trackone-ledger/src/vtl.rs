//! Verifiable Telemetry Ledgers commitment profile.
//!
//! This module intentionally does not share the v1 day-record types: changing
//! the commitment unit or preimage is a profile change, not a migration of
//! existing artifacts.
use crate::{hex_lower, sha256_digest};
use std::collections::BTreeMap;

mod merkle;

pub use merkle::{
    batch_roots_from_leaf_hashes, compose_batch_roots, merkle_root_from_leaf_hashes,
    merkle_root_from_records,
};

pub const COMMITMENT_PROFILE_ID: &str = "c08ade4e-1785-4eb6-9648-b7003d76288d";
pub const SEGMENT_MEDIA_TYPE: &str = "application/cbor";
pub const SPECIALIZED_SEGMENT_MEDIA_TYPE: &str = "application/vnd.vtl.segment+cbor";
pub const ZERO_SHA256: [u8; 32] = [0; 32];
pub const MAX_BATCH_RECORD_LIMIT: u64 = 1 << 63;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosurePolicy {
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
pub struct SegmentRecord {
    pub commitment_profile_id: String,
    pub ledger_id: String,
    pub segment_number: u64,
    pub closure_policy: ClosurePolicy,
    pub close_reason: String,
    pub prev_segment_sha256: [u8; 32],
    pub record_count: u64,
    pub batch_roots: Vec<[u8; 32]>,
    pub segment_root: [u8; 32],
}

struct SegmentChainPosition {
    ledger_id: String,
    segment_number: u64,
    predecessor_sha256: [u8; 32],
}

/// Stable semantic failure categories for a decoded or constructed segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentInvariantError {
    SegmentHexField,
    SegmentIdentityOrClosurePolicy,
    EpochPredecessorNotZero,
    EmptySegment,
    BatchRootCardinality,
    SegmentRootMismatch,
}

impl SegmentInvariantError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::SegmentHexField => "segment-hex-field",
            Self::SegmentIdentityOrClosurePolicy => "segment-identity-or-closure-policy",
            Self::EpochPredecessorNotZero => "epoch-predecessor-not-zero",
            Self::EmptySegment => "empty-segment",
            Self::BatchRootCardinality => "batch-root-cardinality",
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
            "empty segment is invalid" => Some(Self::EmptySegment),
            "batch root cardinality is invalid" => Some(Self::BatchRootCardinality),
            "segment root does not match composed batch roots" => Some(Self::SegmentRootMismatch),
            _ => None,
        }
    }
}

impl core::fmt::Display for SegmentInvariantError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::SegmentHexField => "segment hex field is invalid",
            Self::SegmentIdentityOrClosurePolicy => "segment identity or closure policy is invalid",
            Self::EpochPredecessorNotZero => "epoch segment must use zero predecessor",
            Self::EmptySegment => "empty segment is invalid",
            Self::BatchRootCardinality => "batch root cardinality is invalid",
            Self::SegmentRootMismatch => "segment root does not match composed batch roots",
        })
    }
}

impl std::error::Error for SegmentInvariantError {}

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
pub struct MerkleResult {
    pub root: [u8; 32],
    pub leaf_hashes: Vec<[u8; 32]>,
}

/// Stable failure categories for decoding authoritative VTL segment artifacts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SegmentDecodeError {
    Malformed(&'static str),
    NonCanonical(&'static str),
    ResourceLimit(&'static str),
    MissingField(&'static str),
    UnexpectedField(String),
    InvalidField(&'static str),
    Invariant(String),
}

impl core::fmt::Display for SegmentDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(message)
            | Self::NonCanonical(message)
            | Self::ResourceLimit(message)
            | Self::MissingField(message)
            | Self::InvalidField(message) => f.write_str(message),
            Self::UnexpectedField(field) => write!(f, "unexpected segment field: {field}"),
            Self::Invariant(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for SegmentDecodeError {}

impl SegmentDecodeError {
    /// Return a stable semantic invariant category when decoding reached the
    /// profile model but the decoded segment violated a cross-field invariant.
    pub fn invariant_error(&self) -> Option<SegmentInvariantError> {
        match self {
            Self::Invariant(message) => SegmentInvariantError::from_message(message),
            _ => None,
        }
    }
}

/// Failures while deriving a valid epoch or successor segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SegmentConstructionError {
    InvalidPredecessor(SegmentDecodeError),
    SegmentNumberExhausted,
    Invariant(SegmentInvariantError),
}

impl core::fmt::Display for SegmentConstructionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPredecessor(error) => write!(f, "invalid predecessor segment: {error}"),
            Self::SegmentNumberExhausted => f.write_str("segment number is exhausted"),
            Self::Invariant(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for SegmentConstructionError {}

type DecodeResult<T> = core::result::Result<T, SegmentDecodeError>;

const MAX_CBOR_NESTING_DEPTH: usize = 32;

struct DecodeBudget {
    remaining_items: usize,
}

impl DecodeBudget {
    fn for_input(bytes: &[u8]) -> Self {
        Self {
            remaining_items: bytes.len(),
        }
    }

    fn consume_item(&mut self) -> DecodeResult<()> {
        self.remaining_items =
            self.remaining_items
                .checked_sub(1)
                .ok_or(SegmentDecodeError::ResourceLimit(
                    "CBOR item budget exceeded",
                ))?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CborValue {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(String, CborValue)>),
    Null,
}
impl MerkleResult {
    pub fn root_hex(&self) -> String {
        hex_lower(&self.root)
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
fn cbor_bytes(out: &mut Vec<u8>, value: &[u8]) {
    put_head(out, 2, value.len() as u64);
    out.extend_from_slice(value);
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

impl SegmentRecord {
    /// Construct a validated epoch segment from aligned batch-subtree roots.
    pub fn new_epoch(
        ledger_id: impl Into<String>,
        closure_policy: ClosurePolicy,
        close_reason: impl Into<String>,
        record_count: u64,
        batch_roots: Vec<[u8; 32]>,
        segment_root: [u8; 32],
    ) -> Result<Self, SegmentConstructionError> {
        Self::new_at_position(
            SegmentChainPosition {
                ledger_id: ledger_id.into(),
                segment_number: 0,
                predecessor_sha256: ZERO_SHA256,
            },
            closure_policy,
            close_reason.into(),
            record_count,
            batch_roots,
            segment_root,
        )
    }

    /// Construct a validated successor from exact predecessor artifact bytes.
    pub fn new_successor(
        predecessor_bytes: &[u8],
        closure_policy: ClosurePolicy,
        close_reason: impl Into<String>,
        record_count: u64,
        batch_roots: Vec<[u8; 32]>,
        segment_root: [u8; 32],
    ) -> Result<Self, SegmentConstructionError> {
        let predecessor = decode_segment_record(predecessor_bytes)
            .map_err(SegmentConstructionError::InvalidPredecessor)?;
        let segment_number = predecessor
            .segment_number
            .checked_add(1)
            .ok_or(SegmentConstructionError::SegmentNumberExhausted)?;
        Self::new_at_position(
            SegmentChainPosition {
                ledger_id: predecessor.ledger_id,
                segment_number,
                predecessor_sha256: sha256_digest(predecessor_bytes),
            },
            closure_policy,
            close_reason.into(),
            record_count,
            batch_roots,
            segment_root,
        )
    }

    fn new_at_position(
        position: SegmentChainPosition,
        closure_policy: ClosurePolicy,
        close_reason: String,
        record_count: u64,
        batch_roots: Vec<[u8; 32]>,
        segment_root: [u8; 32],
    ) -> Result<Self, SegmentConstructionError> {
        let segment = Self {
            commitment_profile_id: COMMITMENT_PROFILE_ID.to_string(),
            ledger_id: position.ledger_id,
            segment_number: position.segment_number,
            closure_policy,
            close_reason,
            prev_segment_sha256: position.predecessor_sha256,
            record_count,
            batch_roots,
            segment_root,
        };
        segment
            .validate_detailed()
            .map_err(SegmentConstructionError::Invariant)?;
        Ok(segment)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validate_detailed().map_err(|error| error.to_string())
    }

    pub fn validate_detailed(&self) -> Result<(), SegmentInvariantError> {
        if !valid_hex(&self.ledger_id, 32) {
            return Err(SegmentInvariantError::SegmentHexField);
        }
        if self.commitment_profile_id != COMMITMENT_PROFILE_ID
            || self.closure_policy.interval_ms == 0
            || self.closure_policy.batch_record_limit == 0
            || self.closure_policy.batch_record_limit > MAX_BATCH_RECORD_LIMIT
            || !self.closure_policy.batch_record_limit.is_power_of_two()
            || self.closure_policy.record_limit == Some(0)
            || self.closure_policy.size_limit_bytes == Some(0)
            || !valid_close_reason(&self.close_reason)
        {
            return Err(SegmentInvariantError::SegmentIdentityOrClosurePolicy);
        }
        if self.segment_number == 0 && self.prev_segment_sha256 != ZERO_SHA256 {
            return Err(SegmentInvariantError::EpochPredecessorNotZero);
        }
        if self.record_count == 0 {
            if !self.batch_roots.is_empty()
                || self.segment_root != sha256_digest(b"")
                || (self.closure_policy.empty_mode != EmptyMode::Emit
                    && !matches!(self.close_reason.as_str(), "shutdown" | "recovery"))
            {
                return Err(SegmentInvariantError::EmptySegment);
            }
            return Ok(());
        }
        let expected_roots = 1 + ((self.record_count - 1) / self.closure_policy.batch_record_limit);
        if u64::try_from(self.batch_roots.len()) != Ok(expected_roots) {
            return Err(SegmentInvariantError::BatchRootCardinality);
        }
        if compose_batch_roots(
            &self.batch_roots,
            self.record_count,
            self.closure_policy.batch_record_limit,
        ) != Some(self.segment_root)
        {
            return Err(SegmentInvariantError::SegmentRootMismatch);
        }
        Ok(())
    }

    /// Canonical deterministic CBOR bytes for the authoritative artifact.
    pub fn canonical_cbor_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut out = Vec::new();
        // Keys are emitted in RFC 8949 deterministic text-key order.
        cbor_map(&mut out, 10, |out| {
            key(out, "version");
            cbor_uint(out, 1);
            key(out, "ledger_id");
            cbor_text(out, &self.ledger_id);
            key(out, "batch_roots");
            cbor_array(out, self.batch_roots.len() as u64, |out| {
                for root in &self.batch_roots {
                    cbor_bytes(out, root)
                }
            });
            key(out, "close_reason");
            cbor_text(out, &self.close_reason);
            key(out, "record_count");
            cbor_uint(out, self.record_count);
            key(out, "segment_root");
            cbor_bytes(out, &self.segment_root);
            key(out, "closure_policy");
            encode_policy(out, &self.closure_policy);
            key(out, "segment_number");
            cbor_uint(out, self.segment_number);
            key(out, "prev_segment_sha256");
            cbor_bytes(out, &self.prev_segment_sha256);
            key(out, "commitment_profile_id");
            cbor_text(out, &self.commitment_profile_id);
        });
        Ok(out)
    }
    pub fn sha256(&self) -> Result<[u8; 32], String> {
        Ok(sha256_digest(&self.canonical_cbor_bytes()?))
    }
}

/// Extract the in-band profile identifier from a top-level segment map.
///
/// This deliberately does not validate other segment fields so a verifier can
/// echo a text-valued profile identifier alongside an unrelated artifact error.
pub fn decode_segment_profile_id(bytes: &[u8]) -> DecodeResult<String> {
    extract_text_map_member(bytes, "commitment_profile_id")
        .ok_or(SegmentDecodeError::MissingField("commitment_profile_id"))
}

/// Extract a text-valued top-level map member without validating the remaining
/// segment fields. This is used by verifiers to report an in-band profile ID
/// alongside unrelated segment-artifact failures.
fn extract_text_map_member(bytes: &[u8], member: &str) -> Option<String> {
    let mut pos = 0;
    let (major, entries) = read_permissive_head(bytes, &mut pos)?;
    if major != 5 {
        return None;
    }
    for _ in 0..entries {
        let key = read_permissive_text(bytes, &mut pos)?;
        if key == member {
            return read_permissive_text(bytes, &mut pos);
        }
        skip_permissive_item(bytes, &mut pos, 0)?;
    }
    None
}

fn read_permissive_head(bytes: &[u8], pos: &mut usize) -> Option<(u8, u64)> {
    let initial = *bytes.get(*pos)?;
    *pos += 1;
    let argument = match initial & 0x1f {
        value @ 0..=23 => u64::from(value),
        24 => u64::from(*bytes.get(*pos)?),
        25 => u64::from(u16::from_be_bytes(
            bytes.get(*pos..pos.checked_add(2)?)?.try_into().ok()?,
        )),
        26 => u64::from(u32::from_be_bytes(
            bytes.get(*pos..pos.checked_add(4)?)?.try_into().ok()?,
        )),
        27 => u64::from_be_bytes(bytes.get(*pos..pos.checked_add(8)?)?.try_into().ok()?),
        _ => return None,
    };
    let width = match initial & 0x1f {
        0..=23 => 0,
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => unreachable!(),
    };
    *pos = pos.checked_add(width)?;
    Some((initial >> 5, argument))
}

fn read_permissive_text(bytes: &[u8], pos: &mut usize) -> Option<String> {
    let (major, length) = read_permissive_head(bytes, pos)?;
    if major != 3 {
        return None;
    }
    let end = pos.checked_add(usize::try_from(length).ok()?)?;
    let text = core::str::from_utf8(bytes.get(*pos..end)?).ok()?.to_owned();
    *pos = end;
    Some(text)
}

fn skip_permissive_item(bytes: &[u8], pos: &mut usize, depth: usize) -> Option<()> {
    if depth > MAX_CBOR_NESTING_DEPTH {
        return None;
    }
    let (major, length) = read_permissive_head(bytes, pos)?;
    match major {
        0 | 1 | 7 => Some(()),
        2 | 3 => {
            *pos = pos.checked_add(usize::try_from(length).ok()?)?;
            bytes.get(..*pos)?;
            Some(())
        }
        4 => (0..length).try_for_each(|_| skip_permissive_item(bytes, pos, depth + 1)),
        5 => (0..length).try_for_each(|_| {
            skip_permissive_item(bytes, pos, depth + 1)?;
            skip_permissive_item(bytes, pos, depth + 1)
        }),
        6 => skip_permissive_item(bytes, pos, depth + 1),
        _ => None,
    }
}

/// Decode and validate one authoritative segment artifact.
///
/// This accepts only the constrained deterministic-CBOR subset used by the
/// segment schema. It never decodes and re-encodes a malformed input into a
/// seemingly valid artifact: the decoded value must reproduce the supplied
/// bytes exactly.
pub fn decode_segment_record(bytes: &[u8]) -> DecodeResult<SegmentRecord> {
    let mut pos = 0;
    let mut budget = DecodeBudget::for_input(bytes);
    let value = parse_cbor_value(bytes, &mut pos, 0, &mut budget)?;
    if pos != bytes.len() {
        return Err(SegmentDecodeError::Malformed(
            "segment CBOR has trailing bytes",
        ));
    }
    let mut fields = into_map(value)?;
    let version = take_uint(&mut fields, "version")?;
    if version != 1 {
        return Err(SegmentDecodeError::InvalidField(
            "segment version must be 1",
        ));
    }
    let profile = take_text(&mut fields, "commitment_profile_id")?;
    if profile != COMMITMENT_PROFILE_ID {
        return Err(SegmentDecodeError::InvalidField(
            "unsupported commitment profile",
        ));
    }
    let ledger_id = take_text(&mut fields, "ledger_id")?;
    let segment_number = take_uint(&mut fields, "segment_number")?;
    let closure_policy = decode_policy(take(&mut fields, "closure_policy")?)?;
    let close_reason = take_text(&mut fields, "close_reason")?;
    let prev_segment_sha256 = take_sha256(&mut fields, "prev_segment_sha256")?;
    let record_count = take_uint(&mut fields, "record_count")?;
    let batch_roots = take_sha256_array(&mut fields, "batch_roots")?;
    let segment_root = take_sha256(&mut fields, "segment_root")?;
    if let Some(field) = fields.into_keys().next() {
        return Err(SegmentDecodeError::UnexpectedField(field));
    }
    let record = SegmentRecord {
        commitment_profile_id: profile,
        ledger_id,
        segment_number,
        closure_policy,
        close_reason,
        prev_segment_sha256,
        record_count,
        batch_roots,
        segment_root,
    };
    record
        .validate_detailed()
        .map_err(|error| SegmentDecodeError::Invariant(error.to_string()))?;
    let canonical = record
        .canonical_cbor_bytes()
        .map_err(SegmentDecodeError::Invariant)?;
    if canonical != bytes {
        return Err(SegmentDecodeError::NonCanonical(
            "segment CBOR does not round-trip canonically",
        ));
    }
    Ok(record)
}

/// Validate the exact seven-element canonical-record array used by the VTL
/// commitment profile and return only its profile-visible metadata.
pub fn validate_canonical_record(bytes: &[u8]) -> DecodeResult<CanonicalRecordMetadataV1> {
    let mut pos = 0;
    let (major, len) = read_typed_argument(bytes, &mut pos)?;
    if major != 4 || len != 7 {
        return Err(SegmentDecodeError::InvalidField(
            "canonical record must be a seven-element array",
        ));
    }
    let version = read_uint_item(bytes, &mut pos, "record version")?;
    if version != 1 {
        return Err(SegmentDecodeError::InvalidField("record version must be 1"));
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
    let mut budget = DecodeBudget::for_input(bytes);
    validate_commitment_value(bytes, &mut pos, 0, &mut budget)?;
    if pos != bytes.len() {
        return Err(SegmentDecodeError::Malformed(
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
        .ok_or(SegmentDecodeError::Malformed("truncated CBOR item"))?;
    *pos += 1;
    Ok((
        initial >> 5,
        read_cbor_argument(bytes, pos, initial & 0x1f)?,
    ))
}

fn read_uint_item(bytes: &[u8], pos: &mut usize, field: &'static str) -> DecodeResult<u64> {
    let (major, value) = read_typed_argument(bytes, pos)?;
    if major != 0 {
        return Err(SegmentDecodeError::InvalidField(field));
    }
    Ok(value)
}

fn read_device_id(bytes: &[u8], pos: &mut usize) -> DecodeResult<[u8; 8]> {
    let (major, len) = read_typed_argument(bytes, pos)?;
    if major != 2 || len != 8 {
        return Err(SegmentDecodeError::InvalidField(
            "device_id must be an eight-byte string",
        ));
    }
    let end = pos
        .checked_add(8)
        .filter(|end| *end <= bytes.len())
        .ok_or(SegmentDecodeError::Malformed("truncated device_id"))?;
    let mut device_id = [0u8; 8];
    device_id.copy_from_slice(&bytes[*pos..end]);
    *pos = end;
    Ok(device_id)
}

fn validate_commitment_value(
    bytes: &[u8],
    pos: &mut usize,
    depth: usize,
    budget: &mut DecodeBudget,
) -> DecodeResult<()> {
    if depth > MAX_CBOR_NESTING_DEPTH {
        return Err(SegmentDecodeError::ResourceLimit(
            "CBOR nesting depth exceeds the supported limit",
        ));
    }
    budget.consume_item()?;
    let start = *pos;
    let initial = *bytes
        .get(*pos)
        .ok_or(SegmentDecodeError::Malformed("truncated CBOR payload item"))?;
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
            let width = usize::try_from(len).map_err(|_| {
                SegmentDecodeError::Malformed("CBOR string length overflows platform")
            })?;
            let end = pos
                .checked_add(width)
                .filter(|end| *end <= bytes.len())
                .ok_or(SegmentDecodeError::Malformed("truncated CBOR string"))?;
            if major == 3 {
                core::str::from_utf8(&bytes[*pos..end])
                    .map_err(|_| SegmentDecodeError::Malformed("CBOR text is not UTF-8"))?;
            }
            *pos = end;
            Ok(())
        }
        4 => {
            ensure_collection_fits(bytes, *pos, len, 1)?;
            for _ in 0..len {
                validate_commitment_value(bytes, pos, depth + 1, budget)?;
            }
            Ok(())
        }
        5 => validate_commitment_map(bytes, pos, len, depth, budget),
        6 => Err(SegmentDecodeError::InvalidField(
            "CBOR tags are not permitted in commitment bytes",
        )),
        _ => Err(SegmentDecodeError::Malformed("invalid CBOR major type")),
    }
}

fn validate_commitment_map(
    bytes: &[u8],
    pos: &mut usize,
    len: u64,
    depth: usize,
    budget: &mut DecodeBudget,
) -> DecodeResult<()> {
    ensure_collection_fits(bytes, *pos, len, 2)?;
    let mut previous_key: Option<Vec<u8>> = None;
    for _ in 0..len {
        let key_start = *pos;
        let initial = *bytes
            .get(*pos)
            .ok_or(SegmentDecodeError::Malformed("truncated CBOR map key"))?;
        *pos += 1;
        if initial >> 5 != 3 {
            return Err(SegmentDecodeError::InvalidField(
                "commitment map keys must be text",
            ));
        }
        let key_len = read_cbor_argument(bytes, pos, initial & 0x1f)?;
        let width = usize::try_from(key_len)
            .map_err(|_| SegmentDecodeError::Malformed("CBOR map key length overflows platform"))?;
        let end = pos
            .checked_add(width)
            .filter(|end| *end <= bytes.len())
            .ok_or(SegmentDecodeError::Malformed("truncated CBOR map key"))?;
        core::str::from_utf8(&bytes[*pos..end])
            .map_err(|_| SegmentDecodeError::Malformed("CBOR map key is not UTF-8"))?;
        *pos = end;
        let mut raw_key = Vec::new();
        raw_key
            .try_reserve_exact(end - key_start)
            .map_err(|_| SegmentDecodeError::ResourceLimit("CBOR map key allocation failed"))?;
        raw_key.extend_from_slice(&bytes[key_start..end]);
        if let Some(previous) = &previous_key
            && (previous.len() > raw_key.len()
                || (previous.len() == raw_key.len() && previous >= &raw_key))
        {
            return Err(SegmentDecodeError::NonCanonical(
                "CBOR map keys are not in deterministic order",
            ));
        }
        previous_key = Some(raw_key);
        validate_commitment_value(bytes, pos, depth + 1, budget)?;
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
        _ => Err(SegmentDecodeError::InvalidField(
            "unsupported CBOR simple value",
        )),
    }
}

fn read_fixed<const N: usize>(bytes: &[u8], pos: &mut usize) -> DecodeResult<[u8; N]> {
    let end = pos
        .checked_add(N)
        .filter(|end| *end <= bytes.len())
        .ok_or(SegmentDecodeError::Malformed("truncated CBOR float"))?;
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
        .map_err(|_| SegmentDecodeError::InvalidField("non-finite CBOR float"))?;
    if canonical != bytes[start..end] {
        return Err(SegmentDecodeError::NonCanonical(
            "CBOR float is not encoded at its shortest exact width",
        ));
    }
    Ok(())
}

fn ensure_collection_fits(
    bytes: &[u8],
    pos: usize,
    len: u64,
    minimum_items_per_entry: usize,
) -> DecodeResult<usize> {
    let count = usize::try_from(len).map_err(|_| {
        SegmentDecodeError::ResourceLimit("CBOR collection length overflows platform")
    })?;
    let minimum_bytes =
        count
            .checked_mul(minimum_items_per_entry)
            .ok_or(SegmentDecodeError::ResourceLimit(
                "CBOR collection size overflows platform",
            ))?;
    let remaining = bytes.len().saturating_sub(pos);
    if minimum_bytes > remaining {
        return Err(SegmentDecodeError::Malformed(
            "CBOR collection length exceeds remaining input",
        ));
    }
    Ok(count)
}

fn parse_cbor_value(
    bytes: &[u8],
    pos: &mut usize,
    depth: usize,
    budget: &mut DecodeBudget,
) -> DecodeResult<CborValue> {
    if depth > MAX_CBOR_NESTING_DEPTH {
        return Err(SegmentDecodeError::ResourceLimit(
            "CBOR nesting depth exceeds the supported limit",
        ));
    }
    budget.consume_item()?;
    let initial = *bytes
        .get(*pos)
        .ok_or(SegmentDecodeError::Malformed("truncated CBOR item"))?;
    *pos += 1;
    let major = initial >> 5;
    let len = read_cbor_argument(bytes, pos, initial & 0x1f)?;
    match major {
        0 => Ok(CborValue::Uint(len)),
        2 => {
            let end = pos
                .checked_add(usize::try_from(len).map_err(|_| {
                    SegmentDecodeError::Malformed("CBOR byte-string length overflows platform")
                })?)
                .filter(|end| *end <= bytes.len())
                .ok_or(SegmentDecodeError::Malformed("truncated CBOR byte string"))?;
            let value = bytes[*pos..end].to_vec();
            *pos = end;
            Ok(CborValue::Bytes(value))
        }
        3 => {
            let end = pos
                .checked_add(usize::try_from(len).map_err(|_| {
                    SegmentDecodeError::Malformed("CBOR text length overflows platform")
                })?)
                .filter(|end| *end <= bytes.len())
                .ok_or(SegmentDecodeError::Malformed("truncated CBOR text"))?;
            let raw = core::str::from_utf8(&bytes[*pos..end])
                .map_err(|_| SegmentDecodeError::Malformed("CBOR text is not UTF-8"))?;
            let mut text = String::new();
            text.try_reserve_exact(raw.len())
                .map_err(|_| SegmentDecodeError::ResourceLimit("CBOR text allocation failed"))?;
            text.push_str(raw);
            *pos = end;
            Ok(CborValue::Text(text))
        }
        4 => {
            let count = ensure_collection_fits(bytes, *pos, len, 1)?;
            let mut items = Vec::new();
            items
                .try_reserve_exact(count)
                .map_err(|_| SegmentDecodeError::ResourceLimit("CBOR array allocation failed"))?;
            for _ in 0..len {
                items.push(parse_cbor_value(bytes, pos, depth + 1, budget)?);
            }
            Ok(CborValue::Array(items))
        }
        5 => {
            let count = ensure_collection_fits(bytes, *pos, len, 2)?;
            let mut entries = Vec::new();
            entries
                .try_reserve_exact(count)
                .map_err(|_| SegmentDecodeError::ResourceLimit("CBOR map allocation failed"))?;
            let mut previous_key: Option<Vec<u8>> = None;
            for _ in 0..len {
                let start = *pos;
                let key = parse_cbor_value(bytes, pos, depth + 1, budget)?;
                let mut raw_key = Vec::new();
                raw_key.try_reserve_exact(*pos - start).map_err(|_| {
                    SegmentDecodeError::ResourceLimit("CBOR map key allocation failed")
                })?;
                raw_key.extend_from_slice(&bytes[start..*pos]);
                if let Some(previous) = &previous_key
                    && (previous.len() > raw_key.len()
                        || (previous.len() == raw_key.len() && previous >= &raw_key))
                {
                    return Err(SegmentDecodeError::NonCanonical(
                        "CBOR map keys are not in deterministic order",
                    ));
                }
                let CborValue::Text(key) = key else {
                    return Err(SegmentDecodeError::InvalidField(
                        "segment map keys must be text",
                    ));
                };
                previous_key = Some(raw_key);
                entries.push((key, parse_cbor_value(bytes, pos, depth + 1, budget)?));
            }
            Ok(CborValue::Map(entries))
        }
        7 if initial & 0x1f == 22 => Ok(CborValue::Null),
        1 | 6 | 7 => Err(SegmentDecodeError::InvalidField(
            "unsupported CBOR value in segment artifact",
        )),
        _ => Err(SegmentDecodeError::Malformed("invalid CBOR major type")),
    }
}

fn read_cbor_argument(bytes: &[u8], pos: &mut usize, ai: u8) -> DecodeResult<u64> {
    let read = |width: usize, pos: &mut usize| -> DecodeResult<&[u8]> {
        let end = pos
            .checked_add(width)
            .filter(|end| *end <= bytes.len())
            .ok_or(SegmentDecodeError::Malformed("truncated CBOR argument"))?;
        let part = &bytes[*pos..end];
        *pos = end;
        Ok(part)
    };
    match ai {
        value @ 0..=23 => Ok(value as u64),
        24 => {
            let value = read(1, pos)?[0] as u64;
            if value < 24 {
                Err(SegmentDecodeError::NonCanonical(
                    "CBOR argument is not shortest",
                ))
            } else {
                Ok(value)
            }
        }
        25 => {
            let part = read(2, pos)?;
            let value = u16::from_be_bytes([part[0], part[1]]) as u64;
            if value <= u8::MAX as u64 {
                Err(SegmentDecodeError::NonCanonical(
                    "CBOR argument is not shortest",
                ))
            } else {
                Ok(value)
            }
        }
        26 => {
            let part = read(4, pos)?;
            let value = u32::from_be_bytes([part[0], part[1], part[2], part[3]]) as u64;
            if value <= u16::MAX as u64 {
                Err(SegmentDecodeError::NonCanonical(
                    "CBOR argument is not shortest",
                ))
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
                Err(SegmentDecodeError::NonCanonical(
                    "CBOR argument is not shortest",
                ))
            } else {
                Ok(value)
            }
        }
        _ => Err(SegmentDecodeError::NonCanonical(
            "indefinite or reserved CBOR argument",
        )),
    }
}

fn into_map(value: CborValue) -> DecodeResult<BTreeMap<String, CborValue>> {
    let CborValue::Map(entries) = value else {
        return Err(SegmentDecodeError::InvalidField(
            "segment artifact must be a CBOR map",
        ));
    };
    Ok(entries.into_iter().collect())
}
fn take(fields: &mut BTreeMap<String, CborValue>, name: &'static str) -> DecodeResult<CborValue> {
    fields
        .remove(name)
        .ok_or(SegmentDecodeError::MissingField(name))
}
fn take_text(fields: &mut BTreeMap<String, CborValue>, name: &'static str) -> DecodeResult<String> {
    let CborValue::Text(value) = take(fields, name)? else {
        return Err(SegmentDecodeError::InvalidField(name));
    };
    Ok(value)
}
fn take_uint(fields: &mut BTreeMap<String, CborValue>, name: &'static str) -> DecodeResult<u64> {
    let CborValue::Uint(value) = take(fields, name)? else {
        return Err(SegmentDecodeError::InvalidField(name));
    };
    Ok(value)
}
fn take_sha256(
    fields: &mut BTreeMap<String, CborValue>,
    name: &'static str,
) -> DecodeResult<[u8; 32]> {
    let CborValue::Bytes(value) = take(fields, name)? else {
        return Err(SegmentDecodeError::InvalidField(name));
    };
    value
        .try_into()
        .map_err(|_| SegmentDecodeError::InvalidField(name))
}

fn take_sha256_array(
    fields: &mut BTreeMap<String, CborValue>,
    name: &'static str,
) -> DecodeResult<Vec<[u8; 32]>> {
    let CborValue::Array(items) = take(fields, name)? else {
        return Err(SegmentDecodeError::InvalidField(name));
    };
    items
        .into_iter()
        .map(|item| {
            let CborValue::Bytes(value) = item else {
                return Err(SegmentDecodeError::InvalidField(name));
            };
            value
                .try_into()
                .map_err(|_| SegmentDecodeError::InvalidField(name))
        })
        .collect()
}
fn optional_positive(
    fields: &mut BTreeMap<String, CborValue>,
    name: &'static str,
) -> DecodeResult<Option<u64>> {
    match take(fields, name)? {
        CborValue::Null => Ok(None),
        CborValue::Uint(value) if value > 0 => Ok(Some(value)),
        _ => Err(SegmentDecodeError::InvalidField(name)),
    }
}

fn decode_policy(value: CborValue) -> DecodeResult<ClosurePolicy> {
    let mut fields = into_map(value)?;
    if take_uint(&mut fields, "version")? != 1 {
        return Err(SegmentDecodeError::InvalidField(
            "closure policy version must be 1",
        ));
    }
    let interval_ms = take_uint(&mut fields, "interval_ms")?;
    let batch_record_limit = take_uint(&mut fields, "batch_record_limit")?;
    if interval_ms == 0
        || batch_record_limit == 0
        || batch_record_limit > MAX_BATCH_RECORD_LIMIT
        || !batch_record_limit.is_power_of_two()
    {
        return Err(SegmentDecodeError::InvalidField(
            "closure policy limits must be positive",
        ));
    }
    let record_limit = optional_positive(&mut fields, "record_limit")?;
    let size_limit_bytes = optional_positive(&mut fields, "size_limit_bytes")?;
    let empty_mode = match take_text(&mut fields, "empty_mode")?.as_str() {
        "emit" => EmptyMode::Emit,
        "suppress" => EmptyMode::Suppress,
        _ => return Err(SegmentDecodeError::InvalidField("invalid empty_mode")),
    };
    if let Some(field) = fields.into_keys().next() {
        return Err(SegmentDecodeError::UnexpectedField(field));
    }
    Ok(ClosurePolicy {
        interval_ms,
        batch_record_limit,
        record_limit,
        size_limit_bytes,
        empty_mode,
    })
}

fn encode_policy(out: &mut Vec<u8>, policy: &ClosurePolicy) {
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
