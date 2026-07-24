//! Verification of the strict VTL RFC 3161 timestamp profile using the
//! RFC 5816 `SigningCertificateV2` update.
//!
//! The profile produces a signer-identifiable archived timestamp token.
//! Trust, certification-path, and revocation material remain deployment-
//! managed. Historical path validation is evaluated at the signed,
//! TSA-asserted `genTime`; it does not independently establish when the token
//! was first observed or prevent every form of post-compromise backdating.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::asn1::{Any, AnyRef, ObjectIdentifier, OctetString, Uint};
use der::{DateTime, Decode, Encode, Reader, Sequence, Tag, Tagged};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::IssuingDistributionPoint;

const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const ID_AA_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_CE_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const ID_CE_DELTA_CRL_INDICATOR: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.27");
const ID_CE_ISSUING_DISTRIBUTION_POINT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.28");

const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CERTIFICATES: usize = 8;
const MAX_SIGNED_ATTRIBUTES: usize = 32;
const MAX_ARCHIVE_CRLS: usize = 16;
const MAX_SERIAL_BYTES: usize = 20;
const MAX_ARCHIVE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignerCertificateSha256([u8; 32]);

impl SignerCertificateSha256 {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for SignerCertificateSha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for SignerCertificateSha256 {
    type Err = VerificationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(VerificationError::InvalidSignerHash);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let pair =
                std::str::from_utf8(pair).map_err(|_| VerificationError::InvalidSignerHash)?;
            bytes[index] =
                u8::from_str_radix(pair, 16).map_err(|_| VerificationError::InvalidSignerHash)?;
        }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimestampSerialNumber(Uint);

impl TimestampSerialNumber {
    fn new(value: Uint) -> Result<Self, VerificationError> {
        if value.as_bytes().len() > MAX_SERIAL_BYTES {
            return Err(VerificationError::Profile(
                "TSTInfo serialNumber exceeds the VTL 160-bit limit".into(),
            ));
        }
        Ok(Self(value))
    }

    /// Canonical unsigned big-endian magnitude. Zero is returned as `[0]`.
    pub fn as_bytes(&self) -> &[u8] {
        if self.0.as_bytes().is_empty() {
            &[0]
        } else {
            self.0.as_bytes()
        }
    }

    pub fn to_hex(&self) -> String {
        self.as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

impl fmt::Display for TimestampSerialNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimestampAccuracy {
    pub seconds: Option<u64>,
    pub millis: Option<u16>,
    pub micros: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimestampGenerationTime {
    date_time: DateTime,
    fractional_seconds: Option<String>,
}

impl TimestampGenerationTime {
    /// Whole Unix second containing the signed instant.
    ///
    /// Use of the fractional component for OpenSSL validation is handled
    /// internally; callers should use [`Self::to_rfc3339`] when they need the
    /// complete signed value.
    pub fn unix_seconds(&self) -> u64 {
        self.date_time.unix_duration().as_secs()
    }

    fn openssl_attime_bounds(&self) -> (u64, u64) {
        let whole_second = self.unix_seconds();
        let upper_bound = self.fractional_seconds.as_ref().map_or(whole_second, |_| {
            whole_second
                .checked_add(1)
                .expect("DER DateTime range fits in u64 with one-second headroom")
        });
        (whole_second, upper_bound)
    }

    pub fn to_rfc3339(&self) -> String {
        let fractional_seconds = self
            .fractional_seconds
            .as_ref()
            .map_or_else(String::new, |fraction| format!(".{fraction}"));
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{fractional_seconds}Z",
            self.date_time.year(),
            self.date_time.month(),
            self.date_time.day(),
            self.date_time.hour(),
            self.date_time.minutes(),
            self.date_time.seconds()
        )
    }

    fn from_generalized_time_der(value: AnyRef<'_>) -> Result<Self, VerificationError> {
        if value.tag() != Tag::GeneralizedTime {
            return Err(VerificationError::Malformed(
                "TSTInfo genTime is not GeneralizedTime".into(),
            ));
        }
        let encoded = value.value();
        if encoded.len() < 15 || encoded.last() != Some(&b'Z') {
            return Err(VerificationError::Malformed(
                "TSTInfo genTime must include seconds and use UTC Z form".into(),
            ));
        }
        let whole_seconds = &encoded[..14];
        if !whole_seconds.iter().all(u8::is_ascii_digit) {
            return Err(VerificationError::Malformed(
                "TSTInfo genTime contains a non-decimal time component".into(),
            ));
        }
        let component = |range: std::ops::Range<usize>| -> Result<u8, VerificationError> {
            std::str::from_utf8(&whole_seconds[range])
                .ok()
                .and_then(|part| part.parse().ok())
                .ok_or_else(|| VerificationError::Malformed("invalid TSTInfo genTime".into()))
        };
        let year = std::str::from_utf8(&whole_seconds[..4])
            .ok()
            .and_then(|part| part.parse::<u16>().ok())
            .ok_or_else(|| VerificationError::Malformed("invalid TSTInfo genTime year".into()))?;
        let date_time = DateTime::new(
            year,
            component(4..6)?,
            component(6..8)?,
            component(8..10)?,
            component(10..12)?,
            component(12..14)?,
        )
        .map_err(|error| {
            VerificationError::Malformed(format!("invalid TSTInfo genTime: {error}"))
        })?;
        let fractional_seconds = match &encoded[14..encoded.len() - 1] {
            [] => None,
            fraction
                if fraction[0] == b'.'
                    && fraction.len() > 1
                    && fraction[1..].iter().all(u8::is_ascii_digit)
                    && fraction.last() != Some(&b'0') =>
            {
                Some(
                    std::str::from_utf8(&fraction[1..])
                        .expect("ASCII digits are UTF-8")
                        .to_string(),
                )
            }
            _ => {
                return Err(VerificationError::Malformed(
                    "TSTInfo genTime has a non-canonical fractional part".into(),
                ));
            }
        };
        Ok(Self {
            date_time,
            fractional_seconds,
        })
    }
}

impl fmt::Display for TimestampGenerationTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_rfc3339())
    }
}

#[derive(Clone, Debug)]
pub struct HistoricalValidationArchive {
    pub trust_anchors_file: PathBuf,
    pub intermediates_file: Option<PathBuf>,
    pub crls_file: PathBuf,
}

#[derive(Clone, Debug)]
pub struct VerificationPolicy {
    archive: HistoricalValidationMaterial,
    expected_policy_oid: ObjectIdentifier,
    expected_signer_certificate_sha256: SignerCertificateSha256,
    openssl_binary: PathBuf,
    max_response_bytes: usize,
    command_timeout: Duration,
}

#[derive(Clone, Debug)]
struct HistoricalValidationMaterial {
    trust_anchors_pem: Vec<u8>,
    intermediates_pem: Option<Vec<u8>>,
    crls_pem: Vec<u8>,
}

struct HistoricalValidationPaths {
    trust_anchors_file: PathBuf,
    intermediates_file: Option<PathBuf>,
    crls_file: PathBuf,
}

impl VerificationPolicy {
    pub fn new(
        archive: HistoricalValidationArchive,
        expected_policy_oid: &str,
        expected_signer_certificate_sha256: SignerCertificateSha256,
    ) -> Result<Self, VerificationError> {
        let expected_policy_oid =
            expected_policy_oid
                .parse::<ObjectIdentifier>()
                .map_err(|error| {
                    VerificationError::Configuration(format!(
                        "invalid expected TSA policy OID: {error}"
                    ))
                })?;
        let archive = load_archive_configuration(&archive)?;
        Ok(Self {
            archive,
            expected_policy_oid,
            expected_signer_certificate_sha256,
            openssl_binary: PathBuf::from("openssl"),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            command_timeout: DEFAULT_COMMAND_TIMEOUT,
        })
    }

    pub fn with_openssl_binary(mut self, openssl_binary: PathBuf) -> Self {
        self.openssl_binary = openssl_binary;
        self
    }

    pub fn with_limits(mut self, max_response_bytes: usize, command_timeout: Duration) -> Self {
        self.max_response_bytes = max_response_bytes;
        self.command_timeout = command_timeout;
        self
    }

    pub fn expected_policy_oid(&self) -> ObjectIdentifier {
        self.expected_policy_oid
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedTimestamp {
    pub message_imprint: [u8; 32],
    pub policy_oid: ObjectIdentifier,
    pub serial_number: TimestampSerialNumber,
    /// The TSA-signed claimed generation time.
    ///
    /// Historical path evaluation uses this value as its validation instant.
    /// It is not independent proof of when the response was first observed.
    pub generation_time: TimestampGenerationTime,
    pub accuracy: Option<TimestampAccuracy>,
    pub signer_certificate_sha256: SignerCertificateSha256,
}

#[derive(Debug)]
pub enum VerificationError {
    InvalidSignerHash,
    Configuration(String),
    ResponseTooLarge { actual: usize, maximum: usize },
    Malformed(String),
    Status(u8),
    Profile(String),
    PolicyMismatch,
    MessageImprintMismatch,
    SignerCertificateMismatch(String),
    HistoricalValidation(String),
    ProcessTimeout { command: String, timeout: Duration },
    OpenSsl { command: String, diagnostic: String },
    Io(std::io::Error),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignerHash => formatter.write_str(
                "RFC 3161 signer certificate SHA-256 must be 64 lowercase hexadecimal characters",
            ),
            Self::Configuration(message) => {
                write!(formatter, "RFC 3161 policy configuration error: {message}")
            }
            Self::ResponseTooLarge { actual, maximum } => write!(
                formatter,
                "RFC 3161 response is {actual} bytes; maximum is {maximum}"
            ),
            Self::Malformed(message) => write!(formatter, "malformed RFC 3161 response: {message}"),
            Self::Status(status) => write!(
                formatter,
                "VTL requires PKIStatus.granted (0); TSA returned {status}"
            ),
            Self::Profile(message) => write!(
                formatter,
                "RFC 3161 response violates the VTL timestamp profile: {message}"
            ),
            Self::PolicyMismatch => {
                formatter.write_str("RFC 3161 TSA policy OID is not accepted by deployment policy")
            }
            Self::MessageImprintMismatch => {
                formatter.write_str("RFC 3161 SHA-256 message imprint mismatch")
            }
            Self::SignerCertificateMismatch(message) => write!(
                formatter,
                "RFC 5816 signer-certificate binding failed: {message}"
            ),
            Self::HistoricalValidation(message) => write!(
                formatter,
                "historical CRL-based path validation failed: {message}"
            ),
            Self::ProcessTimeout { command, timeout } => write!(
                formatter,
                "{command} exceeded the {} second process timeout",
                timeout.as_secs()
            ),
            Self::OpenSsl {
                command,
                diagnostic,
            } => write!(formatter, "{command} failed: {diagnostic}"),
            Self::Io(error) => write!(formatter, "RFC 3161 verification I/O failed: {error}"),
        }
    }
}

impl std::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for VerificationError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

struct TemporaryDirectory(PathBuf);

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Debug, Sequence)]
struct MessageImprint {
    hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

#[derive(Clone, Debug, Sequence)]
struct SigningCertificateV2 {
    certs: Vec<EssCertIdV2>,
    policies: Option<Any>,
}

#[derive(Clone, Debug, Sequence)]
struct EssCertIdV2 {
    hash_algorithm: Option<x509_cert::spki::AlgorithmIdentifierOwned>,
    cert_hash: OctetString,
    issuer_serial: Option<Any>,
}

#[derive(Clone, Debug, Sequence)]
struct AccuracyAsn1 {
    seconds: Option<u64>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    millis: Option<u16>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    micros: Option<u16>,
}

#[derive(Clone, Debug)]
struct CandidateTimestampFields {
    status: u8,
    policy_oid: ObjectIdentifier,
    message_imprint: MessageImprint,
    serial_number: TimestampSerialNumber,
    claimed_generation_time: TimestampGenerationTime,
    accuracy: Option<TimestampAccuracy>,
    signer_certificate_der: Vec<u8>,
    signer_certificate_sha256: SignerCertificateSha256,
}

pub fn verify_response(
    response_der: &[u8],
    expected_artifact_sha256: [u8; 32],
    policy: &VerificationPolicy,
) -> Result<VerifiedTimestamp, VerificationError> {
    if response_der.len() > policy.max_response_bytes {
        return Err(VerificationError::ResponseTooLarge {
            actual: response_der.len(),
            maximum: policy.max_response_bytes,
        });
    }

    // These fields remain untrusted until OpenSSL validates the token
    // signature. The claimed time is used only to configure historical path
    // evaluation of the same selected signer certificate.
    let candidate = extract_candidate_fields(response_der)?;
    verify_status_and_profile(&candidate, expected_artifact_sha256, policy)?;

    let temporary = create_temporary_directory()?;
    let response_path = temporary.0.join("response.tsr");
    let signer_path = temporary.0.join("signer.pem");
    let archive_paths = materialize_archive(&temporary.0, &policy.archive)?;
    write_private_file(&response_path, response_der)?;
    write_private_file(
        &signer_path,
        pem_encode("CERTIFICATE", &candidate.signer_certificate_der).as_bytes(),
    )?;

    verify_timestamp_with_openssl(
        &response_path,
        expected_artifact_sha256,
        &candidate.claimed_generation_time,
        &archive_paths,
        policy,
    )?;
    validate_historical_archive(&candidate, &signer_path, &archive_paths, policy)?;

    // OpenSSL owns complete CMS/TSP cryptographic validation. This second
    // parse enforces only the narrower VTL representation and policy rules.
    let verified = inspect_verified_response(response_der, expected_artifact_sha256, policy)?;
    if verified.signer_certificate_sha256 != candidate.signer_certificate_sha256
        || verified.generation_time != candidate.claimed_generation_time
        || verified.serial_number != candidate.serial_number
    {
        return Err(VerificationError::Profile(
            "pre-validation and post-validation parsing did not select identical timestamp fields"
                .into(),
        ));
    }
    Ok(verified)
}

fn extract_candidate_fields(
    response_der: &[u8],
) -> Result<CandidateTimestampFields, VerificationError> {
    let response = AnyRef::from_der(response_der).map_err(malformed)?;
    let (status, content_info) = response
        .sequence(|reader| {
            let status_info: AnyRef<'_> = reader.decode()?;
            let status = status_info.sequence(|status_reader| {
                let status: u8 = status_reader.decode()?;
                while !status_reader.is_finished() {
                    let _: AnyRef<'_> = status_reader.decode()?;
                }
                Ok(status)
            })?;
            let content_info: ContentInfo = reader.decode()?;
            if !reader.is_finished() {
                return Err(Tag::Sequence.value_error());
            }
            Ok((status, content_info))
        })
        .map_err(malformed)?;
    if content_info.content_type != ID_SIGNED_DATA {
        return Err(VerificationError::Malformed(
            "timestamp token is not CMS SignedData".into(),
        ));
    }
    let signed_data: SignedData = content_info.content.decode_as().map_err(malformed)?;
    if signed_data.encap_content_info.econtent_type != ID_CT_TST_INFO {
        return Err(VerificationError::Malformed(
            "CMS content is not TSTInfo".into(),
        ));
    }
    if signed_data.signer_infos.0.len() != 1 {
        return Err(VerificationError::Profile(
            "exactly one CMS SignerInfo is required".into(),
        ));
    }
    let certificates = signed_data.certificates.as_ref().ok_or_else(|| {
        VerificationError::Profile(
            "an embedded signer certificate is required (certReq=TRUE)".into(),
        )
    })?;
    if certificates.0.len() > MAX_CERTIFICATES {
        return Err(VerificationError::Profile(format!(
            "CMS certificate count exceeds {MAX_CERTIFICATES}"
        )));
    }
    let signer_info = exactly_one(signed_data.signer_infos.0.iter(), "CMS SignerInfo")?;
    let signer_certificate = exactly_one(
        certificates.0.iter().filter_map(|choice| match choice {
            CertificateChoices::Certificate(certificate)
                if signer_matches_certificate(&signer_info.sid, certificate) =>
            {
                Some(certificate)
            }
            _ => None,
        }),
        "certificate matching CMS SignerIdentifier",
    )?;
    let signer_certificate_der = signer_certificate.to_der().map_err(malformed)?;
    let signer_certificate_sha256 =
        SignerCertificateSha256(Sha256::digest(&signer_certificate_der).into());

    let tst_content = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| VerificationError::Malformed("TSTInfo content is missing".into()))?;
    let tst_octets: OctetString = tst_content.decode_as().map_err(malformed)?;
    let tst_info = AnyRef::from_der(tst_octets.as_bytes()).map_err(malformed)?;
    let (policy_oid, message_imprint, serial_number, claimed_generation_time, accuracy) = tst_info
        .sequence(|reader| {
            let version: u8 = reader.decode()?;
            if version != 1 {
                return Err(Tag::Integer.value_error());
            }
            let policy_oid: ObjectIdentifier = reader.decode()?;
            let message_imprint: MessageImprint = reader.decode()?;
            let serial_number: Uint = reader.decode()?;
            let claimed_generation_time: AnyRef<'_> = reader.decode()?;
            let accuracy = if !reader.is_finished() && reader.peek_tag()? == Tag::Sequence {
                Some(reader.decode::<AccuracyAsn1>()?)
            } else {
                None
            };
            if !reader.is_finished() && reader.peek_tag()? == Tag::Boolean {
                let _: bool = reader.decode()?;
            }
            if !reader.is_finished() && reader.peek_tag()? == Tag::Integer {
                let _: Uint = reader.decode()?;
            }
            let mut trailing_fields = 0;
            while !reader.is_finished() {
                let _: AnyRef<'_> = reader.decode()?;
                trailing_fields += 1;
                if trailing_fields > 2 {
                    return Err(Tag::Sequence.value_error());
                }
            }
            Ok((
                policy_oid,
                message_imprint,
                serial_number,
                claimed_generation_time,
                accuracy,
            ))
        })
        .map_err(malformed)?;

    let serial_number = TimestampSerialNumber::new(serial_number)?;
    let claimed_generation_time =
        TimestampGenerationTime::from_generalized_time_der(claimed_generation_time)?;
    let accuracy = accuracy.map(|value| TimestampAccuracy {
        seconds: value.seconds,
        millis: value.millis,
        micros: value.micros,
    });
    if let Some(value) = accuracy
        && (value.millis.is_some_and(|part| !(1..=999).contains(&part))
            || value.micros.is_some_and(|part| !(1..=999).contains(&part)))
    {
        return Err(VerificationError::Profile(
            "accuracy millis and micros must be in 1..=999".into(),
        ));
    }

    Ok(CandidateTimestampFields {
        status,
        policy_oid,
        message_imprint,
        serial_number,
        claimed_generation_time,
        accuracy,
        signer_certificate_der,
        signer_certificate_sha256,
    })
}

fn verify_status_and_profile(
    candidate: &CandidateTimestampFields,
    expected_artifact_sha256: [u8; 32],
    policy: &VerificationPolicy,
) -> Result<(), VerificationError> {
    if candidate.status != 0 {
        return Err(VerificationError::Status(candidate.status));
    }
    if candidate.policy_oid != policy.expected_policy_oid {
        return Err(VerificationError::PolicyMismatch);
    }
    if candidate.message_imprint.hash_algorithm.oid != ID_SHA256
        || candidate.message_imprint.hashed_message.as_bytes() != expected_artifact_sha256
    {
        return Err(VerificationError::MessageImprintMismatch);
    }
    if candidate.signer_certificate_sha256 != policy.expected_signer_certificate_sha256 {
        return Err(VerificationError::SignerCertificateMismatch(
            "embedded signer certificate does not match the deployment pin".into(),
        ));
    }
    Ok(())
}

fn verify_timestamp_with_openssl(
    response_path: &Path,
    expected_artifact_sha256: [u8; 32],
    claimed_generation_time: &TimestampGenerationTime,
    archive: &HistoricalValidationPaths,
    policy: &VerificationPolicy,
) -> Result<(), VerificationError> {
    let digest = hex_lower(&expected_artifact_sha256);
    // `-attime` accepts integral Unix seconds only. For a fractional genTime,
    // requiring the path to validate at both adjacent whole-second bounds
    // prevents either a just-expired or not-yet-valid certificate from being
    // accepted through truncation. CRL applicability is checked separately
    // below using exact RFC 5280 whole-second boundary comparisons.
    let (lower_bound, upper_bound) = claimed_generation_time.openssl_attime_bounds();
    for at_time in [lower_bound, upper_bound] {
        let at_time = at_time.to_string();
        let mut command = Command::new(&policy.openssl_binary);
        command
            .args(["ts", "-verify", "-in"])
            .arg(response_path)
            .args(["-digest", &digest, "-CAfile"])
            .arg(&archive.trust_anchors_file)
            .args(["-attime", &at_time]);
        if let Some(intermediates) = &archive.intermediates_file {
            command.arg("-untrusted").arg(intermediates);
        }
        let output = run_command(
            command,
            "OpenSSL timestamp verification",
            policy.command_timeout,
        )?;
        require_success("OpenSSL timestamp verification", output)?;
        if lower_bound == upper_bound {
            break;
        }
    }
    Ok(())
}

fn validate_historical_archive(
    candidate: &CandidateTimestampFields,
    signer_path: &Path,
    archive_paths: &HistoricalValidationPaths,
    policy: &VerificationPolicy,
) -> Result<(), VerificationError> {
    let anchors = load_certificates_from_pem(
        &policy.archive.trust_anchors_pem,
        "configured trust anchors",
    )?;
    let intermediates = policy.archive.intermediates_pem.as_ref().map_or_else(
        || Ok(Vec::new()),
        |pem| load_certificates_from_pem(pem, "configured intermediates"),
    )?;
    let crls = load_crls_from_pem(&policy.archive.crls_pem, "configured CRLs")?;
    validate_archive_applicability(
        &candidate.signer_certificate_der,
        &anchors,
        &intermediates,
        &crls,
        &candidate.claimed_generation_time,
    )?;

    let at_time = candidate.claimed_generation_time.unix_seconds().to_string();
    let mut command = Command::new(&policy.openssl_binary);
    command
        .args([
            "verify",
            "-purpose",
            "timestampsign",
            "-attime",
            &at_time,
            "-CAfile",
        ])
        .arg(&archive_paths.trust_anchors_file);
    if let Some(intermediates) = &archive_paths.intermediates_file {
        command.arg("-untrusted").arg(intermediates);
    }
    command
        .arg("-CRLfile")
        .arg(&archive_paths.crls_file)
        .args(["-crl_check_all", "-x509_strict"])
        .arg(signer_path);
    let output = run_command(
        command,
        "OpenSSL historical certificate-path verification",
        policy.command_timeout,
    )?;
    require_success("OpenSSL historical certificate-path verification", output)
        .map_err(|error| VerificationError::HistoricalValidation(error.to_string()))
}

fn validate_archive_applicability(
    signer_der: &[u8],
    anchors: &[Certificate],
    intermediates: &[Certificate],
    crls: &[CertificateList],
    claimed_generation_time: &TimestampGenerationTime,
) -> Result<(), VerificationError> {
    let signer = Certificate::from_der(signer_der).map_err(malformed)?;
    let mut current = signer;
    let mut depth = 0;
    loop {
        depth += 1;
        if depth > MAX_CERTIFICATES {
            return Err(VerificationError::HistoricalValidation(
                "certification path exceeds the profile depth limit".into(),
            ));
        }
        let applicable = crls
            .iter()
            .filter(|crl| crl.tbs_cert_list.issuer == current.tbs_certificate.issuer)
            .collect::<Vec<_>>();
        if applicable.len() != 1 {
            return Err(VerificationError::HistoricalValidation(format!(
                "expected exactly one complete base CRL for non-root certificate issuer; found {}",
                applicable.len()
            )));
        }
        validate_crl_for_certificate(applicable[0], &current, claimed_generation_time)?;

        let issuer_intermediates = intermediates
            .iter()
            .filter(|certificate| {
                certificate.tbs_certificate.subject == current.tbs_certificate.issuer
            })
            .collect::<Vec<_>>();
        let issuer_anchors = anchors
            .iter()
            .filter(|certificate| {
                certificate.tbs_certificate.subject == current.tbs_certificate.issuer
            })
            .collect::<Vec<_>>();
        if issuer_intermediates.len() + issuer_anchors.len() != 1 {
            return Err(VerificationError::HistoricalValidation(
                "certification path is missing or ambiguous in the deployment archive".into(),
            ));
        }
        if issuer_anchors.len() == 1 {
            break;
        }
        current = issuer_intermediates[0].clone();
    }
    Ok(())
}

fn validate_crl_for_certificate(
    crl: &CertificateList,
    certificate: &Certificate,
    claimed_generation_time: &TimestampGenerationTime,
) -> Result<(), VerificationError> {
    if let Some(extensions) = &crl.tbs_cert_list.crl_extensions {
        if extensions
            .iter()
            .any(|extension| extension.extn_id == ID_CE_DELTA_CRL_INDICATOR)
        {
            return Err(VerificationError::HistoricalValidation(
                "delta CRLs are outside the VTL deployment archive profile".into(),
            ));
        }
        if let Some(extension) = extensions
            .iter()
            .find(|extension| extension.extn_id == ID_CE_ISSUING_DISTRIBUTION_POINT)
        {
            let point = IssuingDistributionPoint::from_der(extension.extn_value.as_bytes())
                .map_err(malformed)?;
            if point.indirect_crl {
                return Err(VerificationError::HistoricalValidation(
                    "indirect CRLs are outside the VTL deployment archive profile".into(),
                ));
            }
        }
    }
    let at_time = Duration::from_secs(claimed_generation_time.unix_seconds());
    if crl.tbs_cert_list.this_update.to_unix_duration() > at_time {
        return Err(VerificationError::HistoricalValidation(
            "CRL thisUpdate is later than the TSA-asserted genTime".into(),
        ));
    }
    let next_update = crl.tbs_cert_list.next_update.ok_or_else(|| {
        VerificationError::HistoricalValidation("a historical CRL must include nextUpdate".into())
    })?;
    if next_update.to_unix_duration() <= at_time {
        return Err(VerificationError::HistoricalValidation(
            "CRL does not cover the TSA-asserted genTime".into(),
        ));
    }
    if let Some(revoked) = &crl.tbs_cert_list.revoked_certificates
        && let Some(entry) = revoked
            .iter()
            .find(|entry| entry.serial_number == certificate.tbs_certificate.serial_number)
        && entry.revocation_date.to_unix_duration() <= at_time
    {
        return Err(VerificationError::HistoricalValidation(
            "certificate was revoked at or before the TSA-asserted genTime".into(),
        ));
    }
    Ok(())
}

fn inspect_verified_response(
    response_der: &[u8],
    expected_artifact_sha256: [u8; 32],
    policy: &VerificationPolicy,
) -> Result<VerifiedTimestamp, VerificationError> {
    let candidate = extract_candidate_fields(response_der)?;
    verify_status_and_profile(&candidate, expected_artifact_sha256, policy)?;

    let response = AnyRef::from_der(response_der).map_err(malformed)?;
    let content_info = response
        .sequence(|reader| {
            let _: AnyRef<'_> = reader.decode()?;
            let content_info: ContentInfo = reader.decode()?;
            if !reader.is_finished() {
                return Err(Tag::Sequence.value_error());
            }
            Ok(content_info)
        })
        .map_err(malformed)?;
    let signed_data: SignedData = content_info.content.decode_as().map_err(malformed)?;
    let signer_info = exactly_one(signed_data.signer_infos.0.iter(), "CMS SignerInfo")?;
    let signed_attributes = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| VerificationError::Profile("CMS signed attributes are required".into()))?;
    if signed_attributes.len() > MAX_SIGNED_ATTRIBUTES {
        return Err(VerificationError::Profile(format!(
            "signed-attribute count exceeds {MAX_SIGNED_ATTRIBUTES}"
        )));
    }
    let signing_certificate_attribute = exactly_one(
        signed_attributes
            .iter()
            .filter(|attribute| attribute.oid == ID_AA_SIGNING_CERTIFICATE_V2),
        "SigningCertificateV2 signed attribute",
    )?;
    let attribute_value = exactly_one(
        signing_certificate_attribute.values.iter(),
        "SigningCertificateV2 attribute value",
    )?;
    let signing_certificate_v2: SigningCertificateV2 =
        attribute_value.decode_as().map_err(malformed)?;
    if signing_certificate_v2.certs.len() > MAX_CERTIFICATES {
        return Err(VerificationError::Profile(format!(
            "ESSCertIDv2 count exceeds {MAX_CERTIFICATES}"
        )));
    }
    let first_cert_id = signing_certificate_v2
        .certs
        .first()
        .ok_or_else(|| VerificationError::Profile("ESSCertIDv2 sequence is empty".into()))?;
    if first_cert_id
        .hash_algorithm
        .as_ref()
        .is_some_and(|algorithm| algorithm.oid != ID_SHA256)
    {
        return Err(VerificationError::SignerCertificateMismatch(
            "ESSCertIDv2 uses a non-SHA-256 hash algorithm".into(),
        ));
    }
    if first_cert_id.cert_hash.as_bytes() != candidate.signer_certificate_sha256.as_bytes() {
        return Err(VerificationError::SignerCertificateMismatch(
            "ESSCertIDv2 does not bind the selected CMS signer certificate".into(),
        ));
    }

    Ok(VerifiedTimestamp {
        message_imprint: expected_artifact_sha256,
        policy_oid: candidate.policy_oid,
        serial_number: candidate.serial_number,
        generation_time: candidate.claimed_generation_time.clone(),
        accuracy: candidate.accuracy,
        signer_certificate_sha256: candidate.signer_certificate_sha256,
    })
}

fn load_certificates_from_pem(
    pem: &[u8],
    description: &str,
) -> Result<Vec<Certificate>, VerificationError> {
    decode_pem_blocks(pem, description, "CERTIFICATE", MAX_CERTIFICATES)?
        .into_iter()
        .map(|der| Certificate::from_der(&der).map_err(malformed))
        .collect()
}

fn load_crls_from_pem(
    pem: &[u8],
    description: &str,
) -> Result<Vec<CertificateList>, VerificationError> {
    let values = decode_pem_blocks(pem, description, "X509 CRL", MAX_ARCHIVE_CRLS)?;
    if values.is_empty() {
        return Err(VerificationError::HistoricalValidation(
            "deployment CRL archive is empty".into(),
        ));
    }
    values
        .into_iter()
        .map(|der| CertificateList::from_der(&der).map_err(malformed))
        .collect()
}

fn load_archive_configuration(
    archive: &HistoricalValidationArchive,
) -> Result<HistoricalValidationMaterial, VerificationError> {
    let trust_anchors_pem = read_archive_file(&archive.trust_anchors_file)?;
    let intermediates_pem = archive
        .intermediates_file
        .as_ref()
        .map(|path| read_archive_file(path))
        .transpose()?;
    let crls_pem = read_archive_file(&archive.crls_file)?;
    load_certificates_from_pem(
        &trust_anchors_pem,
        &archive.trust_anchors_file.display().to_string(),
    )
    .map_err(archive_configuration_error)?;
    if let Some(pem) = &intermediates_pem {
        load_certificates_from_pem(
            pem,
            &archive
                .intermediates_file
                .as_ref()
                .expect("PEM and path are present together")
                .display()
                .to_string(),
        )
        .map_err(archive_configuration_error)?;
    }
    let crls = load_crls_from_pem(&crls_pem, &archive.crls_file.display().to_string())
        .map_err(archive_configuration_error)?;
    for crl in &crls {
        if crl.tbs_cert_list.next_update.is_none() {
            return Err(VerificationError::Configuration(format!(
                "historical CRL in {} has no nextUpdate",
                archive.crls_file.display()
            )));
        }
        if let Some(extensions) = &crl.tbs_cert_list.crl_extensions {
            if extensions
                .iter()
                .any(|extension| extension.extn_id == ID_CE_DELTA_CRL_INDICATOR)
            {
                return Err(VerificationError::Configuration(format!(
                    "delta CRLs are outside the VTL deployment archive profile: {}",
                    archive.crls_file.display()
                )));
            }
            if let Some(extension) = extensions
                .iter()
                .find(|extension| extension.extn_id == ID_CE_ISSUING_DISTRIBUTION_POINT)
            {
                let point = IssuingDistributionPoint::from_der(extension.extn_value.as_bytes())
                    .map_err(|error| {
                        VerificationError::Configuration(format!(
                            "invalid issuingDistributionPoint in {}: {error}",
                            archive.crls_file.display()
                        ))
                    })?;
                if point.indirect_crl {
                    return Err(VerificationError::Configuration(format!(
                        "indirect CRLs are outside the VTL deployment archive profile: {}",
                        archive.crls_file.display()
                    )));
                }
            }
        }
    }
    Ok(HistoricalValidationMaterial {
        trust_anchors_pem,
        intermediates_pem,
        crls_pem,
    })
}

fn archive_configuration_error(error: VerificationError) -> VerificationError {
    match error {
        VerificationError::Configuration(_) => error,
        other => VerificationError::Configuration(other.to_string()),
    }
}

fn read_archive_file(path: &Path) -> Result<Vec<u8>, VerificationError> {
    let bytes = fs::read(path).map_err(|error| {
        VerificationError::Configuration(format!(
            "cannot read validation archive file {}: {error}",
            path.display()
        ))
    })?;
    if bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(VerificationError::Configuration(format!(
            "validation archive file {} exceeds {MAX_ARCHIVE_BYTES} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

fn decode_pem_blocks(
    bytes: &[u8],
    description: &str,
    label: &str,
    maximum: usize,
) -> Result<Vec<Vec<u8>>, VerificationError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        VerificationError::Configuration(format!(
            "validation archive {description} is not UTF-8 PEM"
        ))
    })?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut blocks = Vec::new();
    let mut body: Option<String> = None;
    for line in text.lines() {
        if line == begin {
            if body.is_some() {
                return Err(VerificationError::Configuration(format!(
                    "nested PEM block in {description}"
                )));
            }
            body = Some(String::new());
        } else if line == end {
            let encoded = body.take().ok_or_else(|| {
                VerificationError::Configuration(format!(
                    "PEM end marker without begin marker in {description}"
                ))
            })?;
            blocks.push(BASE64.decode(encoded.as_bytes()).map_err(|error| {
                VerificationError::Configuration(format!(
                    "invalid PEM base64 in {description}: {error}"
                ))
            })?);
            if blocks.len() > maximum {
                return Err(VerificationError::Configuration(format!(
                    "{description} contains more than {maximum} {label} blocks"
                )));
            }
        } else if let Some(encoded) = &mut body {
            encoded.push_str(line.trim());
        }
    }
    if body.is_some() {
        return Err(VerificationError::Configuration(format!(
            "unterminated PEM block in {description}"
        )));
    }
    if blocks.is_empty() {
        return Err(VerificationError::Configuration(format!(
            "{description} contains no {label} blocks"
        )));
    }
    Ok(blocks)
}

fn materialize_archive(
    directory: &Path,
    archive: &HistoricalValidationMaterial,
) -> Result<HistoricalValidationPaths, VerificationError> {
    let trust_anchors_file = directory.join("trust-anchors.pem");
    let crls_file = directory.join("crls.pem");
    write_private_file(&trust_anchors_file, &archive.trust_anchors_pem)?;
    write_private_file(&crls_file, &archive.crls_pem)?;
    let intermediates_file = archive
        .intermediates_pem
        .as_ref()
        .map(|pem| {
            let path = directory.join("intermediates.pem");
            write_private_file(&path, pem)?;
            Ok::<PathBuf, VerificationError>(path)
        })
        .transpose()?;
    Ok(HistoricalValidationPaths {
        trust_anchors_file,
        intermediates_file,
        crls_file,
    })
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let encoded = BASE64.encode(der);
    let mut output = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        output.push('\n');
    }
    output.push_str(&format!("-----END {label}-----\n"));
    output
}

fn create_temporary_directory() -> Result<TemporaryDirectory, VerificationError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| VerificationError::Configuration("system time precedes Unix epoch".into()))?
        .as_nanos();
    for attempt in 0..16_u8 {
        let path = std::env::temp_dir().join(format!(
            "trackone-rfc3161-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(TemporaryDirectory(path)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(VerificationError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique RFC 3161 temporary directory",
    )))
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), VerificationError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

fn run_command(
    mut command: Command,
    label: &str,
    timeout: Duration,
) -> Result<Output, VerificationError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output().map_err(Into::into);
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(VerificationError::ProcessTimeout {
                command: label.to_string(),
                timeout,
            });
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn require_success(label: &str, output: Output) -> Result<(), VerificationError> {
    if output.status.success() {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let diagnostic = match (stdout.is_empty(), stderr.is_empty()) {
        (false, false) => format!("stdout: {stdout}; stderr: {stderr}"),
        (false, true) => format!("stdout: {stdout}"),
        (true, false) => format!("stderr: {stderr}"),
        (true, true) => "no diagnostic output".to_string(),
    };
    Err(VerificationError::OpenSsl {
        command: label.to_string(),
        diagnostic,
    })
}

fn malformed(error: der::Error) -> VerificationError {
    VerificationError::Malformed(error.to_string())
}

fn exactly_one<I, T>(mut values: I, label: &str) -> Result<T, VerificationError>
where
    I: Iterator<Item = T>,
{
    let value = values
        .next()
        .ok_or_else(|| VerificationError::Profile(format!("{label} is missing")))?;
    if values.next().is_some() {
        return Err(VerificationError::Profile(format!(
            "more than one {label} is present"
        )));
    }
    Ok(value)
}

fn signer_matches_certificate(identifier: &SignerIdentifier, certificate: &Certificate) -> bool {
    match identifier {
        SignerIdentifier::IssuerAndSerialNumber(value) => {
            value.issuer == certificate.tbs_certificate.issuer
                && value.serial_number == certificate.tbs_certificate.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(identifier) => certificate
            .tbs_certificate
            .extensions
            .iter()
            .flatten()
            .find(|extension| extension.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER)
            .and_then(|extension| {
                x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(
                    extension.extn_value.as_bytes(),
                )
                .ok()
            })
            .is_some_and(|subject_key_id| subject_key_id == *identifier),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::GeneralizedTime;
    use x509_cert::crl::RevokedCert;
    use x509_cert::time::Time;

    const FIXTURE_SIGNER: &str = "14ab98cafe09d9d1d01562af42d69a904b01023d9cd5b03bd07e5779710c8014";
    const FIXTURE_RESPONSE: &[u8] = include_bytes!("../tests/fixtures/response.tsr");
    const FIXTURE_SEGMENT: &[u8] = include_bytes!("../tests/fixtures/segment.cbor");

    fn fixture_policy() -> VerificationPolicy {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        VerificationPolicy::new(
            HistoricalValidationArchive {
                trust_anchors_file: root.join("tsa-root.pem"),
                intermediates_file: None,
                crls_file: root.join("tsa-crls.pem"),
            },
            "1.3.6.1.4.1.55555.1",
            FIXTURE_SIGNER.parse().unwrap(),
        )
        .unwrap()
    }

    fn parse_generation_time(value: &str) -> Result<TimestampGenerationTime, VerificationError> {
        let mut encoded = vec![0x18, u8::try_from(value.len()).unwrap()];
        encoded.extend_from_slice(value.as_bytes());
        TimestampGenerationTime::from_generalized_time_der(AnyRef::from_der(&encoded).unwrap())
    }

    fn x509_time(value: &str) -> Time {
        let timestamp = parse_generation_time(value).unwrap();
        Time::GeneralTime(GeneralizedTime::from_date_time(timestamp.date_time))
    }

    fn fixture_archive_parts() -> (
        CandidateTimestampFields,
        Vec<Certificate>,
        Vec<CertificateList>,
    ) {
        let policy = fixture_policy();
        (
            extract_candidate_fields(FIXTURE_RESPONSE).unwrap(),
            load_certificates_from_pem(&policy.archive.trust_anchors_pem, "fixture anchors")
                .unwrap(),
            load_crls_from_pem(&policy.archive.crls_pem, "fixture CRLs").unwrap(),
        )
    }

    #[test]
    fn signer_hash_is_canonical_lowercase_sha256() {
        let value = "ab2b1301f6fabdb26aad49d3d1e8b3ddeb31db166377cc29c7bf372d718fdc38";
        assert_eq!(
            value
                .parse::<SignerCertificateSha256>()
                .unwrap()
                .to_string(),
            value
        );
        assert!(
            value
                .to_ascii_uppercase()
                .parse::<SignerCertificateSha256>()
                .is_err()
        );
        assert!("00".parse::<SignerCertificateSha256>().is_err());
    }

    #[test]
    fn timestamp_serial_number_is_canonical_unsigned_and_bounded() {
        let zero = TimestampSerialNumber::new(Uint::new(&[0]).unwrap()).unwrap();
        assert_eq!(zero.as_bytes(), &[0]);
        let high_bit = TimestampSerialNumber::new(Uint::new(&[0x80]).unwrap()).unwrap();
        assert_eq!(high_bit.as_bytes(), &[0x80]);
        let maximum = TimestampSerialNumber::new(Uint::new(&[0xff; 20]).unwrap()).unwrap();
        assert_eq!(maximum.as_bytes().len(), 20);
        assert!(TimestampSerialNumber::new(Uint::new(&[1; 21]).unwrap()).is_err());
        assert!(Uint::from_der(&[0x02, 0x01, 0xff]).is_err());
    }

    #[test]
    fn timestamp_generation_time_preserves_canonical_fractional_seconds() {
        let encoded = [
            0x18, 0x11, b'2', b'0', b'2', b'6', b'0', b'7', b'2', b'2', b'2', b'3', b'0', b'4',
            b'1', b'2', b'.', b'5', b'Z',
        ];
        let value = AnyRef::from_der(&encoded).unwrap();
        let timestamp = TimestampGenerationTime::from_generalized_time_der(value).unwrap();
        assert_eq!(timestamp.to_rfc3339(), "2026-07-22T23:04:12.5Z");

        let noncanonical = [
            0x18, 0x12, b'2', b'0', b'2', b'6', b'0', b'7', b'2', b'2', b'2', b'3', b'0', b'4',
            b'1', b'2', b'.', b'5', b'0', b'Z',
        ];
        assert!(
            TimestampGenerationTime::from_generalized_time_der(
                AnyRef::from_der(&noncanonical).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn timestamp_generation_time_accepts_only_rfc3161_utc_canonical_forms() {
        for (encoded, expected) in [
            ("20260722230412Z", "2026-07-22T23:04:12Z"),
            ("20260722230412.05Z", "2026-07-22T23:04:12.05Z"),
        ] {
            assert_eq!(
                parse_generation_time(encoded).unwrap().to_rfc3339(),
                expected
            );
        }

        for encoded in [
            "20260722230412.0Z",
            "20260722230412.500Z",
            "20260722230412,5Z",
            "20260722230412.5+0100",
            "202607222304Z",
            "20260229230412Z",
            "20260228236012Z",
        ] {
            assert!(
                parse_generation_time(encoded).is_err(),
                "unexpectedly accepted {encoded}"
            );
        }
    }

    #[test]
    fn openssl_attime_bounds_preserve_fractional_and_supported_date_edges() {
        assert_eq!(
            parse_generation_time("19700101000000Z")
                .unwrap()
                .openssl_attime_bounds(),
            (0, 0)
        );
        assert_eq!(
            parse_generation_time("20260722230412.05Z")
                .unwrap()
                .openssl_attime_bounds(),
            (1_784_761_452, 1_784_761_453)
        );
        assert_eq!(
            parse_generation_time("99991231235959.9Z")
                .unwrap()
                .openssl_attime_bounds(),
            (253_402_300_799, 253_402_300_800)
        );
    }

    #[test]
    fn crl_coverage_boundaries_are_explicit() {
        let (candidate, _, mut crls) = fixture_archive_parts();
        let signer = Certificate::from_der(&candidate.signer_certificate_der).unwrap();
        let crl = &mut crls[0];

        crl.tbs_cert_list.this_update = x509_time("20260722230412Z");
        crl.tbs_cert_list.next_update = Some(x509_time("20260722230413Z"));
        validate_crl_for_certificate(crl, &signer, &candidate.claimed_generation_time).unwrap();

        crl.tbs_cert_list.next_update = Some(x509_time("20260722230412Z"));
        let error = validate_crl_for_certificate(crl, &signer, &candidate.claimed_generation_time)
            .unwrap_err();
        assert!(error.to_string().contains("does not cover"));

        crl.tbs_cert_list.this_update = x509_time("20260722230413Z");
        crl.tbs_cert_list.next_update = Some(x509_time("20260722230414Z"));
        let error = validate_crl_for_certificate(crl, &signer, &candidate.claimed_generation_time)
            .unwrap_err();
        assert!(error.to_string().contains("thisUpdate"));
    }

    #[test]
    fn crl_revocation_time_is_effective_at_equality() {
        let (candidate, _, crls) = fixture_archive_parts();
        let signer = Certificate::from_der(&candidate.signer_certificate_der).unwrap();
        for (revocation_time, rejected) in [
            ("20260722230411Z", true),
            ("20260722230412Z", true),
            ("20260722230413Z", false),
        ] {
            let mut crl = crls[0].clone();
            crl.tbs_cert_list.revoked_certificates = Some(vec![RevokedCert {
                serial_number: signer.tbs_certificate.serial_number.clone(),
                revocation_date: x509_time(revocation_time),
                crl_entry_extensions: None,
            }]);
            let result =
                validate_crl_for_certificate(&crl, &signer, &candidate.claimed_generation_time);
            assert_eq!(result.is_err(), rejected, "revocation at {revocation_time}");
        }
    }

    #[test]
    fn archive_rejects_duplicate_crls_and_ambiguous_certificate_paths() {
        let (candidate, anchors, crls) = fixture_archive_parts();
        let duplicate_crls = vec![crls[0].clone(), crls[0].clone()];
        let error = validate_archive_applicability(
            &candidate.signer_certificate_der,
            &anchors,
            &[],
            &duplicate_crls,
            &candidate.claimed_generation_time,
        )
        .unwrap_err();
        assert!(error.to_string().contains("found 2"));

        let ambiguous_anchors = vec![anchors[0].clone(), anchors[0].clone()];
        let error = validate_archive_applicability(
            &candidate.signer_certificate_der,
            &ambiguous_anchors,
            &[],
            &crls,
            &candidate.claimed_generation_time,
        )
        .unwrap_err();
        assert!(error.to_string().contains("missing or ambiguous"));
    }

    #[test]
    fn crl_for_an_unused_issuer_does_not_change_the_selected_path() {
        let (candidate, anchors, crls) = fixture_archive_parts();
        let signer = Certificate::from_der(&candidate.signer_certificate_der).unwrap();
        let mut unused_crl = crls[0].clone();
        unused_crl.tbs_cert_list.issuer = signer.tbs_certificate.subject.clone();

        validate_archive_applicability(
            &candidate.signer_certificate_der,
            &anchors,
            &[],
            &[crls[0].clone(), unused_crl],
            &candidate.claimed_generation_time,
        )
        .unwrap();
    }

    #[test]
    fn root_requires_no_crl_but_each_non_root_certificate_does() {
        let (candidate, anchors, crls) = fixture_archive_parts();
        validate_archive_applicability(
            &candidate.signer_certificate_der,
            &anchors,
            &[],
            &crls,
            &candidate.claimed_generation_time,
        )
        .unwrap();

        let error = validate_archive_applicability(
            &candidate.signer_certificate_der,
            &anchors,
            &[],
            &[],
            &candidate.claimed_generation_time,
        )
        .unwrap_err();
        assert!(error.to_string().contains("found 0"));

        // Build a structural two-hop path from the parsed fixture objects.
        // Signature validity remains OpenSSL's responsibility; this isolates
        // the archive walker's `crl_check_all` completeness rule.
        let signer = Certificate::from_der(&candidate.signer_certificate_der).unwrap();
        let mut intermediate = anchors[0].clone();
        intermediate.tbs_certificate.issuer = signer.tbs_certificate.subject.clone();
        let synthetic_anchor = signer;
        let error = validate_archive_applicability(
            &candidate.signer_certificate_der,
            &[synthetic_anchor],
            &[intermediate],
            &crls,
            &candidate.claimed_generation_time,
        )
        .unwrap_err();
        assert!(error.to_string().contains("found 0"));
    }

    #[test]
    fn openssl_rejects_a_crl_with_an_invalid_issuer_signature() {
        let fixture_policy = fixture_policy();
        let root = std::env::temp_dir().join(format!(
            "trackone-rfc3161-invalid-crl-signature-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let anchors_path = root.join("anchors.pem");
        let crls_path = root.join("crls.pem");
        fs::write(&anchors_path, &fixture_policy.archive.trust_anchors_pem).unwrap();

        let mut crl_der = decode_pem_blocks(
            &fixture_policy.archive.crls_pem,
            "fixture CRLs",
            "X509 CRL",
            MAX_ARCHIVE_CRLS,
        )
        .unwrap()
        .remove(0);
        *crl_der.last_mut().unwrap() ^= 1;
        fs::write(&crls_path, pem_encode("X509 CRL", &crl_der)).unwrap();
        let policy = VerificationPolicy::new(
            HistoricalValidationArchive {
                trust_anchors_file: anchors_path,
                intermediates_file: None,
                crls_file: crls_path,
            },
            "1.3.6.1.4.1.55555.1",
            FIXTURE_SIGNER.parse().unwrap(),
        )
        .unwrap();

        let error = verify_response(
            FIXTURE_RESPONSE,
            Sha256::digest(FIXTURE_SEGMENT).into(),
            &policy,
        )
        .unwrap_err();
        assert!(matches!(error, VerificationError::HistoricalValidation(_)));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_policy_oid_is_a_configuration_error() {
        let archive = HistoricalValidationArchive {
            trust_anchors_file: "anchors.pem".into(),
            intermediates_file: None,
            crls_file: "crls.pem".into(),
        };
        let error =
            VerificationPolicy::new(archive, "not-an-oid", "00".repeat(32).parse().unwrap())
                .unwrap_err();
        assert!(matches!(error, VerificationError::Configuration(_)));
    }

    #[test]
    fn crate_owned_fixture_reports_asserted_timestamp_metadata() {
        let verified = verify_response(
            FIXTURE_RESPONSE,
            Sha256::digest(FIXTURE_SEGMENT).into(),
            &fixture_policy(),
        )
        .unwrap();
        assert_eq!(verified.policy_oid.to_string(), "1.3.6.1.4.1.55555.1");
        assert_eq!(verified.serial_number.to_hex(), "1001");
        assert_eq!(
            verified.generation_time.to_rfc3339(),
            "2026-07-22T23:04:12Z"
        );
        assert_eq!(
            verified.accuracy,
            Some(TimestampAccuracy {
                seconds: Some(1),
                millis: None,
                micros: None,
            })
        );
        assert_eq!(
            verified.signer_certificate_sha256.to_string(),
            FIXTURE_SIGNER
        );
    }

    #[test]
    fn policy_owns_one_validated_archive_snapshot() {
        let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let root = std::env::temp_dir().join(format!(
            "trackone-rfc3161-policy-snapshot-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let anchors = root.join("anchors.pem");
        let crls = root.join("crls.pem");
        fs::copy(fixtures.join("tsa-root.pem"), &anchors).unwrap();
        fs::copy(fixtures.join("tsa-crls.pem"), &crls).unwrap();
        let policy = VerificationPolicy::new(
            HistoricalValidationArchive {
                trust_anchors_file: anchors.clone(),
                intermediates_file: None,
                crls_file: crls.clone(),
            },
            "1.3.6.1.4.1.55555.1",
            FIXTURE_SIGNER.parse().unwrap(),
        )
        .unwrap();
        fs::write(anchors, b"changed after policy construction").unwrap();
        fs::write(crls, b"changed after policy construction").unwrap();

        verify_response(
            FIXTURE_RESPONSE,
            Sha256::digest(FIXTURE_SEGMENT).into(),
            &policy,
        )
        .unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn signing_certificate_v2_attribute_is_required_by_profile() {
        const V2_OID_DER: &[u8] = &[
            0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f,
        ];
        let mut response = FIXTURE_RESPONSE.to_vec();
        let offset = response
            .windows(V2_OID_DER.len())
            .position(|window| window == V2_OID_DER)
            .expect("fixture must contain SigningCertificateV2");
        response[offset + V2_OID_DER.len() - 1] = 0x0c;
        let error = inspect_verified_response(
            &response,
            Sha256::digest(FIXTURE_SEGMENT).into(),
            &fixture_policy(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("SigningCertificateV2"));
    }

    #[test]
    fn granted_with_mods_is_outside_the_vtl_profile() {
        let mut response = FIXTURE_RESPONSE.to_vec();
        let marker = [0x30, 0x03, 0x02, 0x01, 0x00];
        let offset = response
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("fixture must contain PKIStatus.granted");
        response[offset + marker.len() - 1] = 1;
        let candidate = extract_candidate_fields(&response).unwrap();
        let error = verify_status_and_profile(
            &candidate,
            Sha256::digest(FIXTURE_SEGMENT).into(),
            &fixture_policy(),
        )
        .unwrap_err();
        assert!(matches!(error, VerificationError::Status(1)));
    }

    #[test]
    fn oversized_response_is_rejected_before_parsing() {
        let policy = fixture_policy().with_limits(16, Duration::from_secs(1));
        let error = verify_response(FIXTURE_RESPONSE, [0; 32], &policy).unwrap_err();
        assert!(matches!(error, VerificationError::ResponseTooLarge { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn external_command_timeout_is_bounded() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 2"]);
        let error = run_command(command, "timeout fixture", Duration::from_millis(20)).unwrap_err();
        assert!(matches!(error, VerificationError::ProcessTimeout { .. }));
    }
}
