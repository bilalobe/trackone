//! Provisioning records for TrackOne device identity and chain of trust.
//!
//! These types support ADR-019 (Pod Provisioning) and ADR-034 (Serialization Strategy).

use crate::types::DeviceId;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Provisioning record establishing device identity and chain of trust.
///
/// This record is created during device manufacturing/provisioning and contains
/// the device's cryptographic identity and firmware attestation.
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

/// Policy update message for runtime configuration changes.
///
/// These are signed messages that update device operational parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyUpdate {
    /// Target device (None = broadcast to all devices)
    pub target_device: Option<DeviceId>,

    /// Uplink cadence in seconds (e.g., 21600 = 4 uplinks/day)
    pub uplink_cadence_secs: Option<u32>,

    /// RX window duration in milliseconds
    pub rx_window_ms: Option<u32>,

    /// Unix timestamp when this policy becomes effective
    pub effective_at: i64,

    /// Ed25519 signature from policy authority
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
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

    #[test]
    fn policy_update_roundtrip() {
        let policy = PolicyUpdate {
            target_device: Some(PodId::from(7u32)),
            uplink_cadence_secs: Some(21600),
            rx_window_ms: Some(500),
            effective_at: 1_700_000_000,
            signature: [0xFF; 64],
        };

        let mut buf = [0u8; 256];
        let bytes = postcard::to_slice(&policy, &mut buf).expect("serialize");
        let decoded: PolicyUpdate = postcard::from_bytes(bytes).expect("deserialize");

        assert_eq!(policy, decoded);
    }
}
