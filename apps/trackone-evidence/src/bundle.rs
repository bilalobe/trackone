//! Bundle-local canonical CBOR, rejection-audit, and block discovery helpers.

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use trackone_ingest::{RejectionRecord, validate_rejection_record};

use crate::{EvidenceError, Result};

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct BlockHeader {
    pub(crate) site_id: String,
    pub(crate) day: String,
    pub(crate) merkle_root: String,
}

fn read_cbor_uint(data: &[u8], pos: &mut usize, ai: u8) -> Result<u64> {
    match ai {
        n @ 0..=23 => Ok(n as u64),
        24 => {
            let value = *data
                .get(*pos)
                .ok_or_else(|| EvidenceError::Invalid("truncated CBOR".to_string()))?
                as u64;
            *pos += 1;
            if value < 24 {
                return Err(EvidenceError::Invalid(
                    "CBOR integer is not shortest-form".to_string(),
                ));
            }
            Ok(value)
        }
        25 => {
            let bytes = data
                .get(*pos..*pos + 2)
                .ok_or_else(|| EvidenceError::Invalid("truncated CBOR".to_string()))?;
            *pos += 2;
            let value = u16::from_be_bytes([bytes[0], bytes[1]]) as u64;
            if value <= u8::MAX as u64 {
                return Err(EvidenceError::Invalid(
                    "CBOR integer is not shortest-form".to_string(),
                ));
            }
            Ok(value)
        }
        26 => {
            let bytes = data
                .get(*pos..*pos + 4)
                .ok_or_else(|| EvidenceError::Invalid("truncated CBOR".to_string()))?;
            *pos += 4;
            let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
            if value <= u16::MAX as u64 {
                return Err(EvidenceError::Invalid(
                    "CBOR integer is not shortest-form".to_string(),
                ));
            }
            Ok(value)
        }
        27 => {
            let bytes = data
                .get(*pos..*pos + 8)
                .ok_or_else(|| EvidenceError::Invalid("truncated CBOR".to_string()))?;
            *pos += 8;
            let value = u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            if value <= u32::MAX as u64 {
                return Err(EvidenceError::Invalid(
                    "CBOR integer is not shortest-form".to_string(),
                ));
            }
            Ok(value)
        }
        _ => Err(EvidenceError::Invalid(
            "indefinite or reserved CBOR additional information".to_string(),
        )),
    }
}

fn parse_canonical_cbor_value(data: &[u8], pos: &mut usize) -> Result<()> {
    let initial = *data
        .get(*pos)
        .ok_or_else(|| EvidenceError::Invalid("empty CBOR value".to_string()))?;
    *pos += 1;
    let major = initial >> 5;
    let ai = initial & 0x1f;

    match major {
        0 | 1 => {
            let _ = read_cbor_uint(data, pos, ai)?;
        }
        2 | 3 => {
            let len = read_cbor_uint(data, pos, ai)? as usize;
            let end = pos
                .checked_add(len)
                .filter(|end| *end <= data.len())
                .ok_or_else(|| EvidenceError::Invalid("truncated CBOR bytes/text".to_string()))?;
            if major == 3 {
                std::str::from_utf8(&data[*pos..end])
                    .map_err(|_| EvidenceError::Invalid("CBOR text is not UTF-8".to_string()))?;
            }
            *pos = end;
        }
        4 => {
            let len = read_cbor_uint(data, pos, ai)? as usize;
            for _ in 0..len {
                parse_canonical_cbor_value(data, pos)?;
            }
        }
        5 => {
            let len = read_cbor_uint(data, pos, ai)? as usize;
            let mut previous_key: Option<Vec<u8>> = None;
            for _ in 0..len {
                let key_start = *pos;
                parse_canonical_cbor_value(data, pos)?;
                let key = data[key_start..*pos].to_vec();
                if let Some(previous) = previous_key.as_ref()
                    && (previous.len() > key.len()
                        || (previous.len() == key.len() && previous.as_slice() >= key.as_slice()))
                {
                    return Err(EvidenceError::Invalid(
                        "CBOR map keys are not canonical-order".to_string(),
                    ));
                }
                previous_key = Some(key);
                parse_canonical_cbor_value(data, pos)?;
            }
        }
        6 => {
            return Err(EvidenceError::Invalid(
                "CBOR tags are outside the beta fact contract".to_string(),
            ));
        }
        7 => match ai {
            20..=23 => {}
            24 => {
                let simple = *data
                    .get(*pos)
                    .ok_or_else(|| EvidenceError::Invalid("truncated CBOR simple".to_string()))?;
                *pos += 1;
                if simple < 32 {
                    return Err(EvidenceError::Invalid(
                        "CBOR simple value is not shortest-form".to_string(),
                    ));
                }
            }
            _ => {
                return Err(EvidenceError::Invalid(
                    "CBOR simple/float value is outside the beta fact contract".to_string(),
                ));
            }
        },
        _ => unreachable!(),
    }
    Ok(())
}

pub(crate) fn validate_canonical_cbor_fact(bytes: &[u8]) -> Result<()> {
    let mut pos = 0;
    parse_canonical_cbor_value(bytes, &mut pos)?;
    if pos != bytes.len() {
        return Err(EvidenceError::Invalid(
            "CBOR fact has trailing bytes".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_rejection_audit(path: &Path) -> Result<usize> {
    let text = fs::read_to_string(path)?;
    let mut count = 0usize;
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: RejectionRecord = serde_json::from_str(line).map_err(|err| {
            EvidenceError::Invalid(format!(
                "rejection audit line {} invalid JSON: {err}",
                idx + 1
            ))
        })?;
        validate_rejection_record(&record).map_err(|err| {
            EvidenceError::Invalid(format!(
                "rejection audit line {} invalid record: {err}",
                idx + 1
            ))
        })?;
        count += 1;
    }
    Ok(count)
}

pub(crate) fn find_block(root: &Path) -> Result<PathBuf> {
    let mut entries = fs::read_dir(root.join("blocks"))?
        .filter_map(|entry| entry.ok().map(|item| item.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".block.json"))
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries
        .into_iter()
        .next()
        .ok_or_else(|| EvidenceError::Invalid("no block header found".to_string()))
}
