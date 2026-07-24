//! Command-line entry point for evidence verification and export.

use std::path::PathBuf;
use trackone_evidence::v2::{V2VerifyPolicy, verify_v2_bundle_with_policy};
use trackone_evidence::{ExportOptions, PolicyMode, VerifyOptions, export_bundle, verify_bundle};

fn usage() -> ! {
    eprintln!(
        "usage:\n  trackone-evidence verify --root DIR --facts DIR [--json] [--policy-mode warn|strict] [--disclosure-class A|B|C] [--commitment-profile-id ID] [--require-ots]\n  trackone-evidence verify-v2 --root DIR [--json] [--tsa-ca-file FILE] [--tsa-intermediates-file FILE] [--tsa-crls-file FILE] [--tsa-policy OID] [--tsa-signer-cert-sha256 HEX] [--allow-missing-tsa]\n  trackone-evidence export --pipeline-dir DIR --evidence-repo DIR --site SITE --day YYYY-MM-DD [--include-frames] [--git-commit] [--tag] [--tag-name NAME] [--bundle-out PATH]"
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

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let Some(cmd) = args.get(1).map(String::as_str) else {
        usage();
    };
    let result = match cmd {
        "verify" => run_verify(&args[2..]),
        "verify-v2" => run_verify_v2(&args[2..]),
        "export" => run_export(&args[2..]),
        _ => usage(),
    };
    if let Err(err) = result {
        eprintln!("ERROR: {err}");
        std::process::exit(1);
    }
}

fn run_verify_v2(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut root: Option<PathBuf> = None;
    let mut json_mode = false;
    let mut policy = V2VerifyPolicy::baseline();
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "--root" => root = Some(PathBuf::from(take_value(args, &mut idx, "--root"))),
            "--json" => json_mode = true,
            "--tsa-ca-file" => {
                policy.tsa_ca_file =
                    Some(PathBuf::from(take_value(args, &mut idx, "--tsa-ca-file")))
            }
            "--tsa-intermediates-file" => {
                policy.tsa_intermediates_file = Some(PathBuf::from(take_value(
                    args,
                    &mut idx,
                    "--tsa-intermediates-file",
                )))
            }
            "--tsa-crls-file" => {
                policy.tsa_crls_file =
                    Some(PathBuf::from(take_value(args, &mut idx, "--tsa-crls-file")))
            }
            "--tsa-policy" => {
                policy.tsa_policy_oid = Some(take_value(args, &mut idx, "--tsa-policy"))
            }
            "--tsa-signer-cert-sha256" => {
                policy.tsa_signer_cert_sha256 =
                    Some(take_value(args, &mut idx, "--tsa-signer-cert-sha256").parse()?)
            }
            "--allow-missing-tsa" => policy.require_tsa = false,
            _ => usage(),
        }
        idx += 1;
    }
    let summary = verify_v2_bundle_with_policy(&root.unwrap_or_else(|| usage()), &policy)?;
    if json_mode {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!(
            "Disclosure={} Overall={}",
            summary["disclosure_class"], summary["overall"]
        );
    }
    if summary["overall"].as_str() != Some("success") {
        return Err("v2 verification did not succeed".into());
    }
    Ok(())
}

fn run_verify(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut root: Option<PathBuf> = None;
    let mut facts: Option<PathBuf> = None;
    let mut json_mode = false;
    let mut policy_mode = PolicyMode::Warn;
    let mut disclosure_class = "A".to_string();
    let mut commitment_profile_id =
        trackone_constants::COMMITMENT_PROFILE_ID_CANONICAL_CBOR_V1.to_string();
    let mut require_ots = false;
    let mut allow_placeholder = true;

    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "--root" => root = Some(PathBuf::from(take_value(args, &mut idx, "--root"))),
            "--facts" => facts = Some(PathBuf::from(take_value(args, &mut idx, "--facts"))),
            "--json" => json_mode = true,
            "--policy-mode" => {
                policy_mode = PolicyMode::parse(&take_value(args, &mut idx, "--policy-mode"))?
            }
            "--disclosure-class" => {
                disclosure_class = take_value(args, &mut idx, "--disclosure-class")
            }
            "--commitment-profile-id" => {
                commitment_profile_id = take_value(args, &mut idx, "--commitment-profile-id")
            }
            "--require-ots" => {
                require_ots = true;
                allow_placeholder = false;
            }
            "--allow-placeholder" => allow_placeholder = true,
            _ => usage(),
        }
        idx += 1;
    }

    let summary = verify_bundle(&VerifyOptions {
        root: root.unwrap_or_else(|| usage()),
        facts: facts.unwrap_or_else(|| usage()),
        policy_mode,
        disclosure_class,
        commitment_profile_id,
        require_ots,
        allow_placeholder,
    })?;
    if json_mode {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!(
            "Policy={} Disclosure={} Overall={} RootMatch={} PubliclyRecomputable={} Manifest={}:{}",
            summary["policy"]["mode"].as_str().unwrap_or("warn"),
            summary["verification"]["disclosure_class"]
                .as_str()
                .unwrap_or("A"),
            summary["overall"].as_str().unwrap_or("failed"),
            summary["checks"]["root_match"],
            summary["verification"]["publicly_recomputable"],
            summary["manifest"]["status"].as_str().unwrap_or("missing"),
            summary["manifest"]["source"].as_str().unwrap_or("n/a"),
        );
    }
    if summary["overall"].as_str() != Some("success") {
        return Err(format!(
            "verification summary overall={}",
            summary["overall"].as_str().unwrap_or("failed")
        )
        .into());
    }
    Ok(())
}

fn run_export(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut pipeline_dir: Option<PathBuf> = None;
    let mut evidence_repo: Option<PathBuf> = None;
    let mut site: Option<String> = None;
    let mut day: Option<String> = None;
    let mut include_frames = false;
    let mut git_commit = false;
    let mut sign = false;
    let mut tag = false;
    let mut tag_name: Option<String> = None;
    let mut bundle_out: Option<PathBuf> = None;

    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "--pipeline-dir" => {
                pipeline_dir = Some(PathBuf::from(take_value(args, &mut idx, "--pipeline-dir")))
            }
            "--evidence-repo" => {
                evidence_repo = Some(PathBuf::from(take_value(args, &mut idx, "--evidence-repo")))
            }
            "--site" => site = Some(take_value(args, &mut idx, "--site")),
            "--day" => day = Some(take_value(args, &mut idx, "--day")),
            "--include-frames" => include_frames = true,
            "--git-commit" => git_commit = true,
            "--sign" => sign = true,
            "--tag" => tag = true,
            "--tag-name" => tag_name = Some(take_value(args, &mut idx, "--tag-name")),
            "--bundle-out" => {
                bundle_out = Some(PathBuf::from(take_value(args, &mut idx, "--bundle-out")))
            }
            _ => usage(),
        }
        idx += 1;
    }

    let dest = export_bundle(&ExportOptions {
        pipeline_dir: pipeline_dir.unwrap_or_else(|| usage()),
        evidence_repo: evidence_repo.unwrap_or_else(|| usage()),
        site: site.unwrap_or_else(|| usage()),
        day: day.unwrap_or_else(|| usage()),
        include_frames,
        git_commit,
        sign,
        tag,
        tag_name,
        bundle_out,
    })?;
    println!("{}", dest.display());
    Ok(())
}
