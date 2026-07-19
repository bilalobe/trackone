//! Verified evidence export and repository index updates.

use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

use crate::git_ops::{ensure_git_repo, git, maybe_commit, maybe_tag, tag_name};
use crate::manifest::{
    VerifyManifest, artifact_ref, manifest_policy_mode, read_json, resolve_bundle_path,
    verify_manifest_path, write_json,
};
use crate::policy::{ExportOptions, VerifyOptions};
use crate::verify::{
    local_verification_failure, portable_summary, verification_bundle_from_summary, verify_bundle,
};
use crate::{EvidenceError, Result};

fn copy_file(src: &Path, dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(src, dst)?;
    Ok(())
}

fn copy_dir(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir(&src_path, &dst_path)?;
        } else {
            copy_file(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn find_meta_sidecar(pipeline_dir: &Path, day: &str) -> Result<PathBuf> {
    let meta_name = format!("{day}.ots.meta.json");
    let mut candidates = vec![pipeline_dir.join("day").join(&meta_name)];
    for dir in pipeline_dir.ancestors() {
        candidates.push(dir.join("proofs").join(&meta_name));
    }

    for candidate in candidates {
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(EvidenceError::Invalid(format!(
        "OTS metadata sidecar not found for {day}"
    )))
}

pub fn export_bundle(options: &ExportOptions) -> Result<PathBuf> {
    let manifest_path = verify_manifest_path(&options.pipeline_dir.join("day"), &options.day);
    let manifest: VerifyManifest = read_json(&manifest_path)?;
    if manifest.site != options.site || manifest.date != options.day {
        return Err(EvidenceError::Invalid(
            "verification manifest site/day mismatch".to_string(),
        ));
    }
    let policy_mode = manifest_policy_mode(&manifest)?;
    let verify_options = VerifyOptions {
        root: options.pipeline_dir.clone(),
        facts: options.pipeline_dir.join(&manifest.facts_dir),
        policy_mode,
        disclosure_class: manifest.verification_bundle.disclosure_class.clone(),
        commitment_profile_id: manifest.verification_bundle.commitment_profile_id.clone(),
        require_ots: false,
        allow_placeholder: true,
    };
    let verifier_summary = verify_bundle(&verify_options).map_err(|err| {
        EvidenceError::VerificationFailed(format!(
            "fresh verification failed; refusing to export unverified evidence: {err}"
        ))
    })?;
    if let Some(reason) = local_verification_failure(&verifier_summary) {
        return Err(EvidenceError::VerificationFailed(format!(
            "fresh verification failed; refusing to export unverified evidence: {reason}"
        )));
    }
    if verifier_summary["overall"].as_str() != Some("success") {
        return Err(EvidenceError::VerificationFailed(format!(
            "fresh verification failed; refusing to export unverified evidence: overall-{}",
            verifier_summary["overall"].as_str().unwrap_or("failed")
        )));
    }

    let dest_root = options
        .evidence_repo
        .join("site")
        .join(&options.site)
        .join("day")
        .join(&options.day);
    if dest_root.exists() {
        fs::remove_dir_all(&dest_root)?;
    }
    fs::create_dir_all(&dest_root)?;

    copy_dir(
        &options.pipeline_dir.join(&manifest.facts_dir),
        &dest_root.join("facts"),
    )?;
    for artifact in manifest.artifacts.values() {
        let src = resolve_bundle_path(&options.pipeline_dir, &artifact.path)?;
        copy_file(&src, &dest_root.join(&artifact.path))?;
    }
    let exported_manifest = verify_manifest_path(&dest_root.join("day"), &options.day);
    copy_file(&manifest_path, &exported_manifest)?;

    if options.include_frames {
        let frames = manifest.frames_file.as_deref().ok_or_else(|| {
            EvidenceError::Invalid("verification manifest missing frames_file".to_string())
        })?;
        copy_file(
            &options.pipeline_dir.join(frames),
            &dest_root.join("frames.ndjson"),
        )?;
    }

    let source_meta = find_meta_sidecar(&options.pipeline_dir, &options.day)?;
    let mut meta: Value = read_json(&source_meta)?;
    if let Some(object) = meta.as_object_mut() {
        object.remove("milestone");
        object.insert(
            "artifact".to_string(),
            json!(format!("day/{}.cbor", options.day)),
        );
        object.insert(
            "ots_proof".to_string(),
            json!(format!("day/{}.cbor.ots", options.day)),
        );
    }
    let exported_meta = dest_root
        .join("day")
        .join(format!("{}.ots.meta.json", options.day));
    write_json(&exported_meta, &meta)?;

    let mut exported: Value = read_json(&exported_manifest)?;
    if !options.include_frames {
        exported.as_object_mut().unwrap().remove("frames_file");
    }
    exported["artifacts"]["day_ots_meta"] = artifact_ref(&exported_meta, &dest_root)?;
    exported["verifier"] = portable_summary(&verifier_summary);
    exported["verification_bundle"] =
        verification_bundle_from_summary(&verifier_summary, &manifest.verification_bundle);
    write_json(&exported_manifest, &exported)?;

    update_index(options, &dest_root, &exported_manifest)?;
    if options.git_commit || options.tag || options.bundle_out.is_some() {
        ensure_git_repo(&options.evidence_repo)?;
    }
    if options.git_commit || options.tag || options.bundle_out.is_some() {
        maybe_commit(options)?;
    }
    if options.tag {
        maybe_tag(options)?;
    }
    if let Some(bundle_out) = &options.bundle_out {
        if let Some(parent) = bundle_out.parent() {
            fs::create_dir_all(parent)?;
        }
        git(
            &options.evidence_repo,
            &["bundle", "create", &bundle_out.to_string_lossy(), "--all"],
        )?;
    }
    Ok(dest_root)
}

fn update_index(options: &ExportOptions, bundle_root: &Path, manifest_path: &Path) -> Result<()> {
    let index_path = options.evidence_repo.join("index.json");
    let mut index = if index_path.exists() {
        read_json::<Value>(&index_path)?
    } else {
        json!({"version": 1, "exports": []})
    };
    let exports = index["exports"]
        .as_array_mut()
        .ok_or_else(|| EvidenceError::Invalid("index.json exports must be an array".to_string()))?;
    exports.retain(|item| {
        item.get("site").and_then(Value::as_str) != Some(&options.site)
            || item.get("day").and_then(Value::as_str) != Some(&options.day)
    });
    let mut entry = json!({
        "site": options.site,
        "day": options.day,
        "bundle_root": bundle_root.strip_prefix(&options.evidence_repo).unwrap().to_string_lossy(),
        "manifest": manifest_path.strip_prefix(&options.evidence_repo).unwrap().to_string_lossy(),
        "frames_included": options.include_frames,
    });
    if options.tag {
        entry["tag"] = json!(tag_name(options));
    }
    exports.push(entry);
    exports.sort_by_key(|item| {
        format!(
            "{}:{}",
            item.get("site").and_then(Value::as_str).unwrap_or_default(),
            item.get("day").and_then(Value::as_str).unwrap_or_default()
        )
    });
    write_json(&index_path, &index)
}
