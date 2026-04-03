//! Deterministic CBOR encoding for TrackOne commitments.
//!
//! TrackOne uses a **deterministic CBOR profile** (inspired by RFC 8949 Section 4.2)
//! for stable cryptographic commitments and reproducible hashing.
//!
//! This is NOT strictly RFC 8949 "canonical CBOR" - it's a project-specific profile with:
//! - integers encoded in shortest form (per RFC 8949)
//! - floats ALWAYS encoded as float32 (0xFA) for cross-implementation stability
//!   (stricter than RFC 8949's "shortest float that preserves value")
//! - arrays with positional encoding (schema-coupled, minimal overhead)
//! - explicit schema version as first array element for forward compatibility
//!
//! Arrays are preferred over maps because:
//! - ~5-10 bytes smaller per record
//! - Simpler encoding logic (no key sorting)
//! - Schema is already versioned and fixed in TrackOne core types
//!
//! Notes:
//! - `ciborium::into_writer` is convenient for debugging but does not guarantee
//!   determinism. Use `CanonicalCbor` trait for commitments.
//! - Field order in arrays is part of the canonical contract and MUST NOT change
//!   without a schema version bump.
//! - Schema version is embedded as the first array element to enable safe evolution.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use std::vec::Vec;

use crate::identity_input::ProvisioningRecord;
use crate::types::{EnvFact, Fact, FactPayload};

/// Encodes a value to CBOR.
///
/// This function is intended for *benchmarks and debugging*, not commitments.
#[cfg(feature = "std")]
pub fn to_cbor_vec<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).expect("serialize to CBOR");
    buf
}

/// Encodes a value to CBOR using deterministic/canonical rules.
///
/// This is the function you want for hashing, commitments, and reproducible
/// size measurements.
#[cfg(feature = "std")]
pub fn to_canonical_cbor_vec<T: CanonicalCbor>(value: &T) -> Vec<u8> {
    value.to_canonical_cbor_vec()
}

/// Trait for types that can be encoded as canonical CBOR.
///
/// We keep this separate from general `Serialize` so that we never accidentally
/// treat a generic serde CBOR encoding as a commitment.
#[cfg(feature = "std")]
pub trait CanonicalCbor {
    fn to_canonical_cbor_vec(&self) -> Vec<u8>;
}

// --- Internal CBOR helpers (minimal, canonical subset) ---------------------

#[cfg(feature = "std")]
fn major_u64(buf: &mut Vec<u8>, major: u8, n: u64) {
    // major: 0=unsigned, 1=negative, 2=bytes, 3=text, 4=array, 5=map
    // canonical: shortest encoding.
    if n < 24 {
        buf.push((major << 5) | (n as u8));
    } else if n <= u8::MAX as u64 {
        buf.push((major << 5) | 24);
        buf.push(n as u8);
    } else if n <= u16::MAX as u64 {
        buf.push((major << 5) | 25);
        buf.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        buf.push((major << 5) | 26);
        buf.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        buf.push((major << 5) | 27);
        buf.extend_from_slice(&n.to_be_bytes());
    }
}

#[cfg(feature = "std")]
fn cbor_uint(buf: &mut Vec<u8>, n: u64) {
    major_u64(buf, 0, n);
}

#[cfg(feature = "std")]
fn cbor_nint(buf: &mut Vec<u8>, n: i64) {
    // CBOR negative integer stores -(n+1) as unsigned in major type 1.
    debug_assert!(n < 0);
    let m = (-1i128 - (n as i128)) as u64;
    major_u64(buf, 1, m);
}

#[cfg(feature = "std")]
fn cbor_i64(buf: &mut Vec<u8>, n: i64) {
    if n >= 0 {
        cbor_uint(buf, n as u64);
    } else {
        cbor_nint(buf, n);
    }
}

#[cfg(feature = "std")]
fn cbor_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    major_u64(buf, 2, b.len() as u64);
    buf.extend_from_slice(b);
}

#[cfg(feature = "std")]
fn cbor_text(buf: &mut Vec<u8>, s: &str) {
    major_u64(buf, 3, s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
}

#[cfg(feature = "std")]
fn cbor_f32(buf: &mut Vec<u8>, v: f32) {
    // Deterministic choice: encode as float32 (0xFA) always.
    // Additionally, normalize NaN to a single canonical quiet NaN bit pattern
    // to preserve deterministic encoding across platforms and sources.
    buf.push(0xFA);

    let bits: u32 = if v.is_nan() { 0x7FC0_0000 } else { v.to_bits() };
    buf.extend_from_slice(&bits.to_be_bytes());
}

#[cfg(feature = "std")]
fn cbor_null(buf: &mut Vec<u8>) {
    buf.push(0xF6);
}

#[cfg(feature = "std")]
fn cbor_array_len(buf: &mut Vec<u8>, n: usize) {
    major_u64(buf, 4, n as u64);
}

// --- Canonical encodings for TrackOne types --------------------------------

// Schema versions for forward compatibility
const SCHEMA_VERSION_PROVISIONING_RECORD: u64 = 1;
const SCHEMA_VERSION_ENV_FACT: u64 = 1;
const SCHEMA_VERSION_FACT: u64 = 1;

// Field order in arrays is part of the canonical contract. They MUST NOT change
// without a schema version bump.

#[cfg(feature = "std")]
impl CanonicalCbor for ProvisioningRecord {
    fn to_canonical_cbor_vec(&self) -> Vec<u8> {
        // Array encoding (positional), schema v1:
        // [0] schema_version (uint)
        // [1] device_id (bstr, 8)
        // [2] firmware_version (tstr)
        // [3] firmware_hash (bstr, 32)
        // [4] identity_pubkey (bstr, 32)
        // [5] birth_cert_sig (bstr, 64)
        // [6] provisioned_at (i64)
        // [7] site_id (tstr|null)
        let mut buf = Vec::new();
        cbor_array_len(&mut buf, 8);

        cbor_uint(&mut buf, SCHEMA_VERSION_PROVISIONING_RECORD);
        cbor_bytes(&mut buf, &self.device_id.0);
        cbor_text(&mut buf, &self.firmware_version);
        cbor_bytes(&mut buf, &self.firmware_hash);
        cbor_bytes(&mut buf, &self.identity_pubkey);
        cbor_bytes(&mut buf, &self.birth_cert_sig);
        cbor_i64(&mut buf, self.provisioned_at);

        match &self.site_id {
            Some(s) => cbor_text(&mut buf, s),
            None => cbor_null(&mut buf),
        }

        buf
    }
}

#[cfg(feature = "std")]
impl CanonicalCbor for EnvFact {
    fn to_canonical_cbor_vec(&self) -> Vec<u8> {
        // Array encoding (positional), schema v1:
        // [0] schema_version (uint)
        // [1] sample_type (uint)
        // [2] phenomenon_time_start (i64)
        // [3] phenomenon_time_end (i64)
        // [4] value (f32|null)
        // [5] min (f32|null)
        // [6] max (f32|null)
        // [7] mean (f32|null)
        // [8] count (uint|null)
        // [9] quality (f32|null)
        // [10] sensor_channel (uint|null)
        let mut buf = Vec::new();
        cbor_array_len(&mut buf, 11);

        cbor_uint(&mut buf, SCHEMA_VERSION_ENV_FACT);
        cbor_uint(&mut buf, self.sample_type as u64);
        cbor_i64(&mut buf, self.phenomenon_time_start);
        cbor_i64(&mut buf, self.phenomenon_time_end);

        match self.value {
            Some(v) => cbor_f32(&mut buf, v),
            None => cbor_null(&mut buf),
        }

        match self.min {
            Some(v) => cbor_f32(&mut buf, v),
            None => cbor_null(&mut buf),
        }

        match self.max {
            Some(v) => cbor_f32(&mut buf, v),
            None => cbor_null(&mut buf),
        }

        match self.mean {
            Some(v) => cbor_f32(&mut buf, v),
            None => cbor_null(&mut buf),
        }

        match self.count {
            Some(v) => cbor_uint(&mut buf, v as u64),
            None => cbor_null(&mut buf),
        }

        match self.quality {
            Some(v) => cbor_f32(&mut buf, v),
            None => cbor_null(&mut buf),
        }

        match self.sensor_channel {
            Some(v) => cbor_uint(&mut buf, v as u64),
            None => cbor_null(&mut buf),
        }

        buf
    }
}

#[cfg(feature = "std")]
impl CanonicalCbor for Fact {
    fn to_canonical_cbor_vec(&self) -> Vec<u8> {
        // Array encoding (positional), schema v1:
        // [0] schema_version (uint)
        // [1] pod_id (bstr, 8)
        // [2] fc (uint)
        // [3] ingest_time (i64)
        // [4] pod_time (i64|null)
        // [5] kind (uint)
        // [6] payload (array: [discriminant_uint, data])
        //
        // Payload discriminants:
        //   0 = Env (data is nested EnvFact array)
        //   1 = Custom (data is bstr)
        let mut buf = Vec::new();
        cbor_array_len(&mut buf, 7);

        cbor_uint(&mut buf, SCHEMA_VERSION_FACT);
        cbor_bytes(&mut buf, &self.pod_id.0);
        cbor_uint(&mut buf, self.fc);
        cbor_i64(&mut buf, self.ingest_time);

        match self.pod_time {
            Some(t) => cbor_i64(&mut buf, t),
            None => cbor_null(&mut buf),
        }

        cbor_uint(&mut buf, self.kind as u64);

        // Payload as discriminated array: [discriminant_uint, data]
        // Using uint discriminants (0/1) instead of strings for smaller size
        match &self.payload {
            FactPayload::Env(env) => {
                cbor_array_len(&mut buf, 2);
                cbor_uint(&mut buf, 0); // discriminant: 0 = Env
                // env_bytes already begins with its own array header (schema v1)
                let env_bytes = env.to_canonical_cbor_vec();
                buf.extend_from_slice(&env_bytes);
            }
            FactPayload::Custom(v) => {
                cbor_array_len(&mut buf, 2);
                cbor_uint(&mut buf, 1); // discriminant: 1 = Custom
                cbor_bytes(&mut buf, v.as_slice());
            }
        }

        buf
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FactKind;

    #[test]
    fn canonical_cbor_is_stable_for_envfact() {
        let env = EnvFact::instant(
            crate::types::SampleType::AmbientAirTemperature,
            1_700_000_000,
            25.0,
        );
        let a = env.to_canonical_cbor_vec();
        let b = env.to_canonical_cbor_vec();
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_cbor_is_stable_for_fact_env_payload() {
        let fact = Fact {
            pod_id: crate::types::PodId::from(7u32),
            fc: 1,
            ingest_time: 1_700_000_000,
            pod_time: None,
            kind: FactKind::Env,
            payload: FactPayload::Env(EnvFact::instant(
                crate::types::SampleType::AmbientAirTemperature,
                1_700_000_000,
                25.0,
            )),
        };
        let a = fact.to_canonical_cbor_vec();
        let b = fact.to_canonical_cbor_vec();
        assert_eq!(a, b);
    }
}
