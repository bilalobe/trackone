//! Command-line entry point for v2 evidence verification and compaction.

use std::path::PathBuf;
use trackone_evidence::v2::{
    V2VerifyPolicy, compact_v2_bundle, verify_v2_archive, verify_v2_bundle_with_policy,
};

fn usage() -> ! {
    eprintln!(
        "usage:\n  trackone-evidence verify (--root DIR | --archive FILE) [--json] [--pretty] [--tsa-ca-file FILE] [--tsa-intermediates-file FILE] [--tsa-crls-file FILE] [--tsa-policy OID] [--tsa-signer-cert-sha256 HEX] [--allow-missing-tsa] [--verifier-policy-id ID] [--verifier-policy-file FILE]\n  trackone-evidence compact --root DIR --output FILE [--include-extensions] [--tsa-ca-file FILE] [--tsa-intermediates-file FILE] [--tsa-crls-file FILE] [--tsa-policy OID] [--tsa-signer-cert-sha256 HEX] [--allow-missing-tsa] [--verifier-policy-id ID] [--verifier-policy-file FILE]"
    );
    std::process::exit(2);
}

fn take_value(args: &[String], idx: &mut usize, name: &str) -> String {
    *idx += 1;
    args.get(*idx).cloned().unwrap_or_else(|| {
        eprintln!("missing value for {name}");
        usage();
    })
}

fn parse_policy_arg(args: &[String], idx: &mut usize, policy: &mut V2VerifyPolicy) -> bool {
    match args[*idx].as_str() {
        "--tsa-ca-file" => {
            policy.tsa_ca_file = Some(PathBuf::from(take_value(args, idx, "--tsa-ca-file")));
        }
        "--tsa-intermediates-file" => {
            policy.tsa_intermediates_file = Some(PathBuf::from(take_value(
                args,
                idx,
                "--tsa-intermediates-file",
            )));
        }
        "--tsa-crls-file" => {
            policy.tsa_crls_file = Some(PathBuf::from(take_value(args, idx, "--tsa-crls-file")));
        }
        "--tsa-policy" => policy.tsa_policy_oid = Some(take_value(args, idx, "--tsa-policy")),
        "--tsa-signer-cert-sha256" => {
            let raw = take_value(args, idx, "--tsa-signer-cert-sha256");
            policy.tsa_signer_cert_sha256 = Some(raw.parse().unwrap_or_else(|error| {
                eprintln!("invalid --tsa-signer-cert-sha256: {error}");
                usage();
            }));
        }
        "--allow-missing-tsa" => policy.require_tsa = false,
        "--verifier-policy-id" => {
            policy.verifier_policy_id = Some(take_value(args, idx, "--verifier-policy-id"));
        }
        "--verifier-policy-file" => {
            policy.verifier_policy_artifact = Some(PathBuf::from(take_value(
                args,
                idx,
                "--verifier-policy-file",
            )));
        }
        _ => return false,
    }
    true
}

fn run_verify(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut root: Option<PathBuf> = None;
    let mut archive: Option<PathBuf> = None;
    let mut json_mode = false;
    let mut pretty = false;
    let mut policy = V2VerifyPolicy::baseline();
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "--root" => root = Some(PathBuf::from(take_value(args, &mut idx, "--root"))),
            "--archive" => archive = Some(PathBuf::from(take_value(args, &mut idx, "--archive"))),
            "--json" => json_mode = true,
            "--pretty" => pretty = true,
            _ if parse_policy_arg(args, &mut idx, &mut policy) => {}
            _ => usage(),
        }
        idx += 1;
    }
    let summary = match (root, archive) {
        (Some(root), None) => verify_v2_bundle_with_policy(&root, &policy)?,
        (None, Some(archive)) => verify_v2_archive(&archive, &policy)?,
        _ => usage(),
    };
    if json_mode {
        if pretty {
            println!("{}", serde_json::to_string_pretty(&summary)?);
        } else {
            println!("{}", serde_json::to_string(&summary)?);
        }
    } else {
        println!(
            "Disclosure={} Overall={}",
            summary["disclosure_class"], summary["overall"]
        );
    }
    if summary["overall"].as_str() != Some("success") {
        return Err("verification did not succeed".into());
    }
    Ok(())
}

fn run_compact(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut root: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut include_extensions = false;
    let mut policy = V2VerifyPolicy::baseline();
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "--root" => root = Some(PathBuf::from(take_value(args, &mut idx, "--root"))),
            "--output" => output = Some(PathBuf::from(take_value(args, &mut idx, "--output"))),
            "--include-extensions" => include_extensions = true,
            _ if parse_policy_arg(args, &mut idx, &mut policy) => {}
            _ => usage(),
        }
        idx += 1;
    }
    compact_v2_bundle(
        &root.unwrap_or_else(|| usage()),
        &output.unwrap_or_else(|| usage()),
        &policy,
        include_extensions,
    )?;
    Ok(())
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let Some(command) = args.get(1).map(String::as_str) else {
        usage();
    };
    let result = match command {
        "verify" => run_verify(&args[2..]),
        "compact" => run_compact(&args[2..]),
        _ => usage(),
    };
    if let Err(error) = result {
        eprintln!("ERROR: {error}");
        std::process::exit(1);
    }
}
