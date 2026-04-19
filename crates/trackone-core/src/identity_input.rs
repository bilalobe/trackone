//! Imported identity and admission input records that enter the TrackOne
//! evidence path.
//!
//! These types support ADR-019 (Pod Provisioning) and ADR-034
//! (Serialization Strategy).
//!
//! Boundary note: these records model external lifecycle/control-plane inputs
//! consumed by TrackOne once telemetry is admitted. They do not make
//! `trackone-core` the owner of onboarding, PKI issuance, or fleet lifecycle
//! workflow.

use crate::types::DeviceId;
use core::fmt;
use serde::{Deserialize, Serialize};

mod signature_array_serde {
    use super::fmt;
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    const SIGNATURE_LEN: usize = 64;

    pub fn serialize<S>(value: &[u8; SIGNATURE_LEN], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_tuple(SIGNATURE_LEN)?;
        for byte in value {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; SIGNATURE_LEN], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SignatureVisitor;

        impl<'de> Visitor<'de> for SignatureVisitor {
            type Value = [u8; SIGNATURE_LEN];

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an array of length {}", SIGNATURE_LEN)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut value = [0u8; SIGNATURE_LEN];
                for (index, slot) in value.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(index, &self))?;
                }
                Ok(value)
            }
        }

        deserializer.deserialize_tuple(SIGNATURE_LEN, SignatureVisitor)
    }
}

/// Provisioning record carried into the evidence path as external identity context.
///
/// This record is created outside TrackOne during manufacturing/provisioning
/// and contains the device's cryptographic identity and firmware attestation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvisioningRecord {
    /// Unique device identifier (8 bytes)
    pub device_id: DeviceId,

    /// Firmware version string (e.g., "v0.1.0-alpha.1")
    pub firmware_version: heapless::String<32>,

    /// SHA-256 hash of the firmware binary
    pub firmware_hash: [u8; 32],

    /// Ed25519 public key for device identity
    pub identity_pubkey: [u8; 32],

    /// Ed25519 signature from manufacturing CA over
    /// (device_id, firmware_hash, identity_pubkey).
    #[serde(with = "signature_array_serde")]
    pub birth_cert_sig: [u8; 64],

    /// Unix timestamp (seconds since epoch) when device was provisioned
    pub provisioned_at: i64,

    /// Optional site/deployment identifier
    pub site_id: Option<heapless::String<32>>,
}

#[cfg(all(test, feature = "postcard"))]
mod tests {
    use super::*;
    use crate::types::PodId;

    #[test]
    fn provisioning_record_roundtrip() {
        let record = ProvisioningRecord {
            device_id: PodId::from(42u32),
            firmware_version: heapless::String::try_from("v0.1.0-alpha.1").unwrap(),
            firmware_hash: [0xAB; 32],
            identity_pubkey: [0xCD; 32],
            birth_cert_sig: [0x56; 64],
            provisioned_at: 1_700_000_000,
            site_id: Some(heapless::String::try_from("test-site").unwrap()),
        };

        // Test postcard serialization roundtrip
        let mut buf = [0u8; 512];
        let bytes = postcard::to_slice(&record, &mut buf).expect("serialize");
        let decoded: ProvisioningRecord = postcard::from_bytes(bytes).expect("deserialize");

        assert_eq!(record, decoded);
    }
}
