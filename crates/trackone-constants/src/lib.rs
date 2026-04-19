#![no_std]

/// Canonical maximum serialized length for a `Fact` in bytes.
///
/// This is a workspace-level policy knob. Consumers should not hardcode
/// their own value; import it from `trackone_constants::MAX_FACT_LEN` (re-exported)
/// or directly from this crate if needed.
pub const MAX_FACT_LEN: usize = 256;

/// AEAD nonce length in bytes (XChaCha20-Poly1305).
pub const AEAD_NONCE_LEN: usize = 24;

/// AEAD authentication tag length in bytes (Poly1305).
pub const AEAD_TAG_LEN: usize = 16;

/// Default timeout for invoking `ots verify` in gateway-side validation.
pub const OTS_VERIFY_TIMEOUT_SECS: u64 = 30;

/// Default pod watchdog timeout in milliseconds.
pub const DEFAULT_WATCHDOG_MS: u32 = 1_000;

/// Active commitment profile identifier for the alpha.15 release line.
pub const COMMITMENT_PROFILE_ID_CANONICAL_CBOR_V1: &str = "trackone-canonical-cbor-v1";

/// Disclosure class for publicly recomputable verification bundles.
pub const DISCLOSURE_CLASS_PUBLIC_RECOMPUTE: &str = "A";

/// Disclosure class for partner-audit verification bundles.
pub const DISCLOSURE_CLASS_PARTNER_AUDIT: &str = "B";

/// Disclosure class for anchor-only verification bundles.
pub const DISCLOSURE_CLASS_ANCHOR_ONLY: &str = "C";

/// Human-readable label for disclosure class `A`.
pub const DISCLOSURE_CLASS_PUBLIC_RECOMPUTE_LABEL: &str = "public-recompute";

/// Human-readable label for disclosure class `B`.
pub const DISCLOSURE_CLASS_PARTNER_AUDIT_LABEL: &str = "partner-audit";

/// Human-readable label for disclosure class `C`.
pub const DISCLOSURE_CLASS_ANCHOR_ONLY_LABEL: &str = "anchor-only-evidence";

/// Active ingest profile identifier for the Rust-native Postcard wire format.
pub const INGEST_PROFILE_RUST_POSTCARD_V1: &str = "rust-postcard-v1";

/// Message type used by the current Rust-native framed fact path.
pub const FRAMED_FACT_MSG_TYPE: u8 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpha14_release_constants_match_manifest_contract() {
        assert_eq!(
            COMMITMENT_PROFILE_ID_CANONICAL_CBOR_V1,
            "trackone-canonical-cbor-v1"
        );
        assert_eq!(DISCLOSURE_CLASS_PUBLIC_RECOMPUTE, "A");
        assert_eq!(DISCLOSURE_CLASS_PARTNER_AUDIT, "B");
        assert_eq!(DISCLOSURE_CLASS_ANCHOR_ONLY, "C");
        assert_eq!(DISCLOSURE_CLASS_PUBLIC_RECOMPUTE_LABEL, "public-recompute");
        assert_eq!(DISCLOSURE_CLASS_PARTNER_AUDIT_LABEL, "partner-audit");
        assert_eq!(DISCLOSURE_CLASS_ANCHOR_ONLY_LABEL, "anchor-only-evidence");
        assert_eq!(INGEST_PROFILE_RUST_POSTCARD_V1, "rust-postcard-v1");
        assert_eq!(FRAMED_FACT_MSG_TYPE, 1);
    }
}
