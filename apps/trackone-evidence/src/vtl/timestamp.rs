//! RFC 3161 policy adaptation at the evidence-verification edge.

use super::{Result, VerifyPolicy, bad};
use trackone_rfc3161::{
    HistoricalValidationArchive, VerificationPolicy, VerifiedTimestamp, verify_response,
};

pub(super) fn verify_timestamp(
    response: &[u8],
    artifact_digest: [u8; 32],
    policy: &VerifyPolicy,
) -> Result<VerifiedTimestamp> {
    let ca_file = policy
        .tsa_ca_file
        .as_ref()
        .ok_or_else(|| bad("RFC 3161 trust anchor is not configured"))?;
    let crls_file = policy
        .tsa_crls_file
        .as_ref()
        .ok_or_else(|| bad("RFC 3161 historical CRL archive is not configured"))?;
    let policy_oid = policy
        .tsa_policy_oid
        .as_ref()
        .ok_or_else(|| bad("RFC 3161 TSA policy OID is not configured"))?;
    let signer_hash = policy
        .tsa_signer_cert_sha256
        .ok_or_else(|| bad("RFC 3161 signer certificate SHA-256 is not configured"))?;
    let verification_policy = VerificationPolicy::new(
        HistoricalValidationArchive {
            trust_anchors_file: ca_file.clone(),
            intermediates_file: policy.tsa_intermediates_file.clone(),
            crls_file: crls_file.clone(),
        },
        policy_oid,
        signer_hash,
    )
    .map_err(|error| bad(error.to_string()))?
    .with_openssl_binary(policy.openssl_binary.clone())
    .with_max_future_skew(policy.max_future_skew);
    verify_response(response, artifact_digest, &verification_policy)
        .map_err(|error| bad(error.to_string()))
}
