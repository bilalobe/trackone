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
    pub fn validate(&self) -> Result<(), String> {
        if !valid_hex(&self.ledger_id, 32)
            || !valid_hex(&self.prev_segment_sha256, 64)
            || !valid_hex(&self.segment_root, 64)
        {
            return Err("segment hex field is invalid".into());
        }
        if self.site_id.is_empty()
            || self.closure_policy.interval_ms == 0
            || self.closure_policy.batch_record_limit == 0
            || self.closure_policy.record_limit == Some(0)
            || self.closure_policy.size_limit_bytes == Some(0)
            || !valid_close_reason(&self.close_reason)
        {
            return Err("segment identity or closure policy is invalid".into());
        }
        if self.segment_number == 0 && self.prev_segment_sha256 != ZERO_SHA256 {
            return Err("epoch segment must use zero predecessor".into());
        }
        if self.segment_number != 0 && self.prev_segment_sha256 == ZERO_SHA256 {
            return Err("successor segment must have a predecessor".into());
        }
        if self.batches.is_empty() {
            if self.closure_policy.empty_mode != EmptyMode::Emit
                || self.segment_root != sha256_hex(b"")
            {
                return Err("empty segment is invalid".into());
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
                return Err("embedded batch identity or cardinality is invalid".into());
            }
            if batch.leaf_hashes.iter().any(|hash| !valid_hex(hash, 64)) {
                return Err("invalid batch leaf hash".into());
            }
            if batch.leaf_hashes.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err("batch leaf hashes are not strictly sorted".into());
            }
            let batch_hashes = batch
                .leaf_hashes
                .iter()
                .map(|hash| decode_hex32(hash))
                .collect::<Result<Vec<_>, _>>()?;
            if hex_lower(&mth(&batch_hashes)) != batch.merkle_root {
                return Err("batch root does not match batch leaves".into());
            }
            if number + 1 != self.batches.len()
                && batch.count != self.closure_policy.batch_record_limit
            {
                return Err("only the final batch may be shorter than the batch limit".into());
            }
            leaves.extend(batch.leaf_hashes.iter().cloned());
        }
        if leaves.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("batch leaves are not consecutive sorted partitions".into());
        }
        let hashes = leaves
            .iter()
            .map(|h| decode_hex32(h))
            .collect::<Result<Vec<_>, _>>()?;
        if hex_lower(&mth(&hashes)) != self.segment_root {
            return Err("segment root does not match embedded leaves".into());
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
    record.validate().map_err(V2DecodeError::Invariant)?;
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

    fn epoch_segment() -> SegmentRecordV2 {
        let records = vec![hex::decode("87014800000000000000010100f600f6").unwrap()];
        let merkle = merkle_root_from_records(&records);
        let leaf = hex_lower(&merkle.leaf_hashes[0]);
        SegmentRecordV2 {
            ledger_id: "b7a1d5e40c6f438e9a75db27c96f31aa".into(),
            site_id: "an-001".into(),
            segment_number: 0,
            closure_policy: ClosurePolicyV1 {
                interval_ms: 60_000,
                batch_record_limit: 1,
                record_limit: None,
                size_limit_bytes: None,
                empty_mode: EmptyMode::Suppress,
            },
            close_reason: "interval".into(),
            prev_segment_sha256: ZERO_SHA256.into(),
            batches: vec![SegmentBatchV2 {
                ledger_id: "b7a1d5e40c6f438e9a75db27c96f31aa".into(),
                site_id: "an-001".into(),
                segment_number: 0,
                batch_number: 0,
                merkle_root: leaf.clone(),
                count: 1,
                leaf_hashes: vec![leaf],
            }],
            segment_root: merkle.root_hex(),
        }
    }

    #[test]
    fn compact_draft_leaves_match() {
        let records = vec![
            hex::decode("87014800000000000000010100f600f6").unwrap(),
            hex::decode("87014800000000000000020201f600f6").unwrap(),
            hex::decode("87014800000000000000030302f600f6").unwrap(),
        ];
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
    fn decoder_enforces_successor_predecessor_rule() {
        let mut successor = epoch_segment();
        successor.segment_number = 7;
        successor.batches[0].segment_number = 7;
        assert!(successor.validate().is_err());
    }
}
