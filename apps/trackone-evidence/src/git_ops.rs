//! Git initialization, commit, tag, and bundle helpers for evidence export.

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::{EvidenceError, ExportOptions, Result};

pub(crate) fn tag_name(options: &ExportOptions) -> String {
    options
        .tag_name
        .clone()
        .unwrap_or_else(|| format!("evidence/{}/{}", options.site, options.day))
}

pub(crate) fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git").args(args).current_dir(repo).output()?;
    if !output.status.success() {
        return Err(EvidenceError::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub(crate) fn ensure_git_repo(repo: &Path) -> Result<()> {
    fs::create_dir_all(repo)?;
    if !repo.join(".git").exists() {
        git(repo, &["init"])?;
    }
    Ok(())
}

pub(crate) fn maybe_commit(options: &ExportOptions) -> Result<()> {
    if git(&options.evidence_repo, &["status", "--short"])?.is_empty() {
        return Ok(());
    }
    git(&options.evidence_repo, &["add", "."])?;
    let message = format!("evidence: {} {}", options.site, options.day);
    if options.sign {
        git(&options.evidence_repo, &["commit", "-S", "-m", &message])?;
    } else {
        git(
            &options.evidence_repo,
            &["-c", "commit.gpgsign=false", "commit", "-m", &message],
        )?;
    }
    Ok(())
}

pub(crate) fn maybe_tag(options: &ExportOptions) -> Result<()> {
    let tag = tag_name(options);
    if !git(&options.evidence_repo, &["tag", "--list", &tag])?.is_empty() {
        return Err(EvidenceError::Git(format!("tag already exists: {tag}")));
    }
    if options.sign {
        git(&options.evidence_repo, &["tag", "-s", &tag, "-m", &tag])?;
    } else {
        git(
            &options.evidence_repo,
            &["-c", "tag.gpgSign=false", "tag", "-a", &tag, "-m", &tag],
        )?;
    }
    Ok(())
}
