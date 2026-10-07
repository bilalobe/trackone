//! Command-line configuration for the evidence binary.

use std::{path::PathBuf, time::Duration};

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use trackone_evidence::{
    EvidenceError, Result,
    vtl::{RemoteOptions, VerificationScope, VerifyPolicy},
};
use trackone_rfc3161::SignerCertificateSha256;

#[derive(Parser)]
#[command(name = "trackone-evidence", version, about, propagate_version = true)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: EvidenceCommand,
}

#[derive(Subcommand)]
pub(crate) enum EvidenceCommand {
    /// Verify a directory, archive, or remote HTTPS evidence bundle
    Verify(VerifyArgs),
    /// Create a deterministic gzip carrier from a verified directory bundle
    Compact(CompactArgs),
}

#[derive(Args)]
#[command(group(ArgGroup::new("input").required(true).multiple(false).args(["root", "archive", "bundle_url"])))]
pub(crate) struct VerifyArgs {
    /// Directory containing segment.verify.json and its artifacts
    #[arg(long, value_name = "DIR")]
    root: Option<PathBuf>,

    /// Deterministic gzip archive to verify
    #[arg(long, value_name = "FILE")]
    archive: Option<PathBuf>,

    /// Absolute HTTPS directory URL of an immutable evidence bundle
    #[arg(long, value_name = "URL", requires_all = ["expected_segment_sha256", "https_ca_file"])]
    bundle_url: Option<String>,

    /// Independently provisioned segment SHA-256, 64 lowercase hex characters
    #[arg(long, value_name = "HEX", requires = "bundle_url", value_parser = parse_expected_segment_sha256)]
    expected_segment_sha256: Option<String>,

    /// HTTPS trust anchors for remote retrieval
    #[arg(long, value_name = "FILE", requires = "bundle_url")]
    https_ca_file: Option<PathBuf>,

    /// Emit the stable JSON verification result
    #[arg(long)]
    pub(crate) json: bool,

    /// Indent JSON output when --json is enabled
    #[arg(long)]
    pub(crate) pretty: bool,

    #[command(flatten)]
    pub(crate) policy: PolicyArgs,
}

pub(crate) enum VerifyInput {
    Directory(PathBuf),
    Archive(PathBuf),
    Remote(RemoteOptions),
}

impl VerifyArgs {
    pub(crate) fn input(&self) -> Result<VerifyInput> {
        match (&self.root, &self.archive, &self.bundle_url) {
            (Some(root), None, None) => Ok(VerifyInput::Directory(root.clone())),
            (None, Some(archive), None) => Ok(VerifyInput::Archive(archive.clone())),
            (None, None, Some(url)) => Ok(VerifyInput::Remote(RemoteOptions::new(
                url,
                self.expected_segment_sha256.as_deref().ok_or_else(|| {
                    EvidenceError::Invalid("--bundle-url requires --expected-segment-sha256".into())
                })?,
                self.https_ca_file.clone().ok_or_else(|| {
                    EvidenceError::Invalid("--bundle-url requires --https-ca-file".into())
                })?,
            ))),
            _ => Err(EvidenceError::Invalid(
                "verify requires exactly one of --root, --archive, or --bundle-url".into(),
            )),
        }
    }
}

#[derive(Args)]
pub(crate) struct CompactArgs {
    /// Directory bundle to verify and compact
    #[arg(long, value_name = "DIR")]
    pub(crate) root: PathBuf,

    /// Destination gzip archive
    #[arg(long, value_name = "FILE")]
    pub(crate) output: PathBuf,

    /// Retain referenced extension artifacts in the carrier
    #[arg(long)]
    pub(crate) include_extensions: bool,

    #[command(flatten)]
    pub(crate) policy: PolicyArgs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
pub(crate) enum ScopeArg {
    /// Recompute all disclosed records
    PublicRecompute,
    /// Recompute selected complete batches
    DisclosedBatchRecompute,
    /// Verify the segment commitment and timestamp without record openings
    AnchorOnly,
}

impl From<ScopeArg> for VerificationScope {
    fn from(scope: ScopeArg) -> Self {
        match scope {
            ScopeArg::PublicRecompute => Self::PublicRecompute,
            ScopeArg::DisclosedBatchRecompute => Self::DisclosedBatchRecompute,
            ScopeArg::AnchorOnly => Self::AnchorOnly,
        }
    }
}

#[derive(Args)]
pub(crate) struct PolicyArgs {
    /// TSA deployment trust anchors in PEM format
    #[arg(long, value_name = "FILE")]
    tsa_ca_file: Option<PathBuf>,

    /// TSA intermediate certificates in PEM format
    #[arg(long, value_name = "FILE")]
    tsa_intermediates_file: Option<PathBuf>,

    /// Retained complete TSA base CRLs in PEM format
    #[arg(long, value_name = "FILE")]
    tsa_crls_file: Option<PathBuf>,

    /// Expected TSA policy OID
    #[arg(long = "tsa-policy", value_name = "OID")]
    tsa_policy_oid: Option<String>,

    /// SHA-256 of the complete DER TSA signer certificate
    #[arg(long, value_name = "HEX")]
    tsa_signer_cert_sha256: Option<SignerCertificateSha256>,

    /// Maximum permitted lead of TSA genTime, in integer seconds
    #[arg(
        long,
        value_name = "N",
        default_value_t = 0,
        allow_negative_numbers = true
    )]
    tsa_max_future_skew_seconds: u64,

    /// Explicit verifier policy identifier
    #[arg(long, value_name = "ID")]
    verifier_policy_id: Option<String>,

    /// Artifact whose digest binds the verifier policy
    #[arg(long, value_name = "FILE")]
    verifier_policy_file: Option<PathBuf>,

    /// Verification scope; defaults to the bundle's claimed disclosure class
    #[arg(long, value_enum)]
    scope: Option<ScopeArg>,

    /// Select a complete batch for disclosed_batch_recompute (repeatable)
    #[arg(long = "batch", value_name = "N", allow_negative_numbers = true)]
    batches: Vec<u64>,

    /// Fail verification if the selected scope does not exercise the claimed scope
    #[arg(long)]
    require_claimed_scope: bool,
}

impl PolicyArgs {
    pub(crate) fn into_policy(self) -> VerifyPolicy {
        VerifyPolicy {
            tsa_ca_file: self.tsa_ca_file,
            tsa_intermediates_file: self.tsa_intermediates_file,
            tsa_crls_file: self.tsa_crls_file,
            tsa_policy_oid: self.tsa_policy_oid,
            tsa_signer_cert_sha256: self.tsa_signer_cert_sha256,
            max_future_skew: Duration::from_secs(self.tsa_max_future_skew_seconds),
            verifier_policy_id: self.verifier_policy_id,
            verifier_policy_artifact: self.verifier_policy_file,
            selected_scope: self.scope.map(VerificationScope::from),
            selected_batches: self.batches.into_iter().collect(),
            require_claimed_scope: self.require_claimed_scope,
            ..VerifyPolicy::baseline()
        }
    }
}

fn parse_expected_segment_sha256(raw: &str) -> std::result::Result<String, String> {
    if raw.len() == 64
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(raw.to_string())
    } else {
        Err("expected segment SHA-256 must be 64 lowercase hexadecimal characters".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, error::ErrorKind};

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn command_schema_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn directory_archive_and_remote_inputs_are_typed() {
        let cli = Cli::try_parse_from(["trackone-evidence", "verify", "--root", "bundle"]).unwrap();
        let EvidenceCommand::Verify(args) = cli.command else {
            panic!("expected verify")
        };
        assert!(
            matches!(args.input().unwrap(), VerifyInput::Directory(path) if path == std::path::Path::new("bundle"))
        );

        let cli =
            Cli::try_parse_from(["trackone-evidence", "verify", "--archive", "bundle.tar.gz"])
                .unwrap();
        let EvidenceCommand::Verify(args) = cli.command else {
            panic!("expected verify")
        };
        assert!(
            matches!(args.input().unwrap(), VerifyInput::Archive(path) if path == std::path::Path::new("bundle.tar.gz"))
        );

        let cli = Cli::try_parse_from([
            "trackone-evidence",
            "verify",
            "--bundle-url",
            "https://example.test/bundle/",
            "--expected-segment-sha256",
            DIGEST,
            "--https-ca-file",
            "https.pem",
        ])
        .unwrap();
        let EvidenceCommand::Verify(args) = cli.command else {
            panic!("expected verify")
        };
        let VerifyInput::Remote(options) = args.input().unwrap() else {
            panic!("expected remote")
        };
        assert_eq!(options.bundle_url, "https://example.test/bundle/");
        assert_eq!(options.expected_segment_sha256, DIGEST);
        assert_eq!(options.https_ca_file, PathBuf::from("https.pem"));
    }

    #[test]
    fn source_and_remote_option_relationships_are_enforced() {
        for extra in [
            vec![],
            vec!["--root", "bundle", "--archive", "bundle.tar.gz"],
            vec!["--bundle-url", "https://example.test/bundle/"],
            vec![
                "--bundle-url",
                "https://example.test/bundle/",
                "--expected-segment-sha256",
                DIGEST,
            ],
            vec![
                "--bundle-url",
                "https://example.test/bundle/",
                "--https-ca-file",
                "https.pem",
            ],
            vec!["--root", "bundle", "--expected-segment-sha256", DIGEST],
            vec!["--archive", "bundle.tar.gz", "--https-ca-file", "https.pem"],
            vec![
                "--root",
                "bundle",
                "--bundle-url",
                "https://example.test/bundle/",
                "--expected-segment-sha256",
                DIGEST,
                "--https-ca-file",
                "https.pem",
            ],
        ] {
            let mut args = vec!["trackone-evidence", "verify"];
            args.extend(extra);
            assert!(Cli::try_parse_from(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn shared_policy_flags_map_identically_for_both_commands() {
        let flags = [
            "--tsa-ca-file",
            "tsa.pem",
            "--tsa-intermediates-file",
            "intermediates.pem",
            "--tsa-crls-file",
            "crls.pem",
            "--tsa-policy",
            "1.2.3.4",
            "--tsa-signer-cert-sha256",
            DIGEST,
            "--tsa-max-future-skew-seconds",
            "5",
            "--verifier-policy-id",
            "test-policy",
            "--verifier-policy-file",
            "policy.json",
            "--scope",
            "disclosed_batch_recompute",
            "--batch",
            "4",
            "--batch",
            "3",
            "--batch",
            "4",
            "--require-claimed-scope",
        ];
        for mut args in [
            vec!["trackone-evidence", "verify", "--root", "bundle"],
            vec![
                "trackone-evidence",
                "compact",
                "--root",
                "bundle",
                "--output",
                "bundle.tar.gz",
            ],
        ] {
            args.extend(flags);
            let policy = match Cli::try_parse_from(args).unwrap().command {
                EvidenceCommand::Verify(args) => args.policy.into_policy(),
                EvidenceCommand::Compact(args) => args.policy.into_policy(),
            };
            assert_eq!(policy.tsa_ca_file, Some(PathBuf::from("tsa.pem")));
            assert_eq!(
                policy.tsa_intermediates_file,
                Some(PathBuf::from("intermediates.pem"))
            );
            assert_eq!(policy.tsa_crls_file, Some(PathBuf::from("crls.pem")));
            assert_eq!(policy.tsa_policy_oid.as_deref(), Some("1.2.3.4"));
            assert_eq!(policy.tsa_signer_cert_sha256.unwrap().to_string(), DIGEST);
            assert_eq!(policy.max_future_skew, Duration::from_secs(5));
            assert_eq!(policy.verifier_policy_id.as_deref(), Some("test-policy"));
            assert_eq!(
                policy.verifier_policy_artifact,
                Some(PathBuf::from("policy.json"))
            );
            assert_eq!(
                policy.selected_scope,
                Some(VerificationScope::DisclosedBatchRecompute)
            );
            assert_eq!(
                policy.selected_batches.into_iter().collect::<Vec<_>>(),
                [3, 4]
            );
            assert!(policy.require_claimed_scope);
            assert_eq!(policy.openssl_binary, PathBuf::from("openssl"));
        }
    }

    #[test]
    fn defaults_and_full_uint64_ranges_are_preserved() {
        let cli = Cli::try_parse_from([
            "trackone-evidence",
            "verify",
            "--root",
            "bundle",
            "--pretty",
        ])
        .unwrap();
        let EvidenceCommand::Verify(args) = cli.command else {
            panic!("expected verify")
        };
        assert!(!args.json);
        assert!(args.pretty);
        let policy = args.policy.into_policy();
        assert_eq!(policy.max_future_skew, Duration::ZERO);
        assert_eq!(policy.selected_scope, None);
        assert!(policy.selected_batches.is_empty());
        assert!(!policy.require_claimed_scope);
        assert!(policy.tsa_ca_file.is_none());
        assert!(policy.tsa_signer_cert_sha256.is_none());
        assert!(policy.verifier_policy_id.is_none());

        let cli = Cli::try_parse_from([
            "trackone-evidence",
            "verify",
            "--root",
            "bundle",
            "--scope",
            "disclosed_batch_recompute",
            "--batch",
            "18446744073709551615",
            "--tsa-max-future-skew-seconds",
            "18446744073709551615",
        ])
        .unwrap();
        let EvidenceCommand::Verify(args) = cli.command else {
            panic!("expected verify")
        };
        let policy = args.policy.into_policy();
        assert_eq!(policy.max_future_skew, Duration::from_secs(u64::MAX));
        assert!(policy.selected_batches.contains(&u64::MAX));
    }

    #[test]
    fn malformed_numeric_scope_and_fingerprint_options_are_usage_errors() {
        for (flag, value) in [
            ("--batch", "-1"),
            ("--batch", "18446744073709551616"),
            ("--tsa-max-future-skew-seconds", "-1"),
            ("--tsa-max-future-skew-seconds", "1.5"),
            ("--scope", "partial_verification"),
            ("--tsa-signer-cert-sha256", "invalid"),
        ] {
            let error = Cli::try_parse_from([
                "trackone-evidence",
                "verify",
                "--root",
                "bundle",
                flag,
                value,
            ])
            .err()
            .expect("malformed option accepted");
            assert!(error.to_string().contains(flag), "{error}");
            assert_eq!(error.exit_code(), 2);
        }
        let error =
            Cli::try_parse_from(["trackone-evidence", "verify", "--root", "bundle", "--typo"])
                .err()
                .unwrap();
        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn remote_digest_rejects_non_canonical_hex() {
        for digest in ["short", &"A".repeat(64), &"g".repeat(64)] {
            let error = Cli::try_parse_from([
                "trackone-evidence",
                "verify",
                "--bundle-url",
                "https://example.test/bundle/",
                "--https-ca-file",
                "https.pem",
                "--expected-segment-sha256",
                digest,
            ])
            .err()
            .unwrap();
            assert!(error.to_string().contains("--expected-segment-sha256"));
        }
    }
}
