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
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

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

    /// Ed25519 signature from manufacturing CA over (device_id, firmware_hash, identity_pubkey)
    /// Uses serde-big-array for [u8; 64] serialization support
    #[serde(with = "BigArray")]
    pub birth_cert_sig: [u8; 64],

    /// Unix timestamp (seconds since epoch) when device was provisioned
    pub provisioned_at: i64,

    /// Optional site/deployment identifier
    pub site_id: Option<heapless::String<32>>,
}

#[cfg(test)]
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
