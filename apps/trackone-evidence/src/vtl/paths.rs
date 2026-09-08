//! Bounded, portable, race-resistant access to untrusted bundle members.

use super::manifest::ArtifactRef;
use super::{EvidenceError, MAX_ARCHIVE_MEMBER, Result, bad};
use std::fs::File;
use std::io::{Read, Take};
use std::path::{Component, Path};
use trackone_ledger::sha256_hex;

pub(super) fn valid_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub(super) fn parse_uint64(value: &str) -> Option<u64> {
    if value.is_empty()
        || (value != "0"
            && (value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit())))
    {
        return None;
    }
    value.parse().ok()
}

pub(super) fn validate_portable_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains(':')
        || path.chars().any(char::is_control)
        || Path::new(path)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(bad("manifest path is not portable"));
    }
    Ok(())
}

pub(super) fn read_file_bounded(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    read_file_bounded_from(file.take(limit + 1), limit, label)
}

fn read_file_bounded_from(mut input: Take<File>, limit: u64, label: &str) -> Result<Vec<u8>> {
    if input.get_ref().metadata()?.len() > limit {
        return Err(bad(format!("{label} exceeds the configured size limit")));
    }
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(bad(format!("{label} exceeds the configured size limit")));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
pub(super) fn safe_read(root: &Path, relative: &str) -> Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
    validate_portable_path(relative)?;
    let root = File::open(root)?;
    let descriptor = openat2(
        &root,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| bad(format!("cannot safely open artifact {relative}: {error}")))?;
    let file = File::from(descriptor);
    read_file_bounded_from(
        file.take(MAX_ARCHIVE_MEMBER + 1),
        MAX_ARCHIVE_MEMBER,
        "bundle artifact",
    )
}

#[cfg(not(target_os = "linux"))]
pub(super) fn safe_read(_root: &Path, relative: &str) -> Result<Vec<u8>> {
    validate_portable_path(relative)?;
    Err(bad(
        "race-resistant VTL manifest opening is unavailable on this platform",
    ))
}

pub(super) fn referenced_artifact(root: &Path, reference: &ArtifactRef) -> Result<Vec<u8>> {
    if !valid_hex(&reference.sha256, 64) {
        return Err(bad(
            "artifact reference SHA-256 is not lowercase hexadecimal",
        ));
    }
    let bytes = safe_read(root, &reference.path)?;
    if sha256_hex(&bytes) != reference.sha256 {
        return Err(EvidenceError::VerificationFailed(
            "artifact reference digest mismatch".to_string(),
        ));
    }
    Ok(bytes)
}
