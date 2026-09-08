//! Deterministic evidence-carrier writing and bounded archive replay.

use super::paths::{read_file_bounded, validate_portable_path};
use super::{
    MAX_ARCHIVE_MEMBER, MAX_ARCHIVE_MEMBERS, MAX_COMPRESSED_ARCHIVE, MAX_EXPANDED_ARCHIVE, Result,
    VerifyPolicy, bad, verify_bundle_with_policy,
};
use flate2::{Compression, GzBuilder, bufread::GzDecoder};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::Path;

pub(super) fn write_archive(output: &Path, members: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    let gzip = GzBuilder::new()
        .mtime(0)
        .write(File::create(output)?, Compression::best());
    let mut archive = tar::Builder::new(gzip);
    archive.mode(tar::HeaderMode::Deterministic);
    for (path, bytes) in members {
        validate_portable_path(path)?;
        let mut header = tar::Header::new_ustar();
        header.set_size(u64::try_from(bytes.len()).map_err(|_| bad("artifact is too large"))?);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        archive.append_data(&mut header, path, Cursor::new(bytes))?;
    }
    archive.into_inner()?.finish()?;
    Ok(())
}

pub fn verify_archive(path: &Path, policy: &VerifyPolicy) -> Result<Value> {
    if fs::metadata(path)?.len() > MAX_COMPRESSED_ARCHIVE {
        return Err(bad("compressed archive exceeds 64 MiB"));
    }
    let input = read_file_bounded(path, MAX_COMPRESSED_ARCHIVE, "compressed archive")?;
    let mut decoder = GzDecoder::new(Cursor::new(input.as_slice()));
    let mut expanded = Vec::new();
    (&mut decoder)
        .take(MAX_EXPANDED_ARCHIVE + 1)
        .read_to_end(&mut expanded)?;
    if u64::try_from(expanded.len()).unwrap_or(u64::MAX) > MAX_EXPANDED_ARCHIVE {
        return Err(bad("expanded archive exceeds 256 MiB"));
    }
    if decoder.into_inner().position() != input.len() as u64 {
        return Err(bad(
            "compressed archive must contain exactly one gzip member with no trailing bytes",
        ));
    }
    let temporary = tempfile::tempdir()?;
    let mut archive = tar::Archive::new(Cursor::new(expanded));
    let mut paths = BTreeSet::new();
    for (index, entry) in archive.entries()?.enumerate() {
        if index >= MAX_ARCHIVE_MEMBERS {
            return Err(bad("archive contains more than 10000 members"));
        }
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() || entry.size() > MAX_ARCHIVE_MEMBER {
            return Err(bad("archive member is not a bounded regular file"));
        }
        let relative = entry
            .path()?
            .to_str()
            .ok_or_else(|| bad("archive path is not UTF-8"))?
            .to_string();
        validate_portable_path(&relative)?;
        if !paths.insert(relative.clone()) {
            return Err(bad("archive contains a duplicate path"));
        }
        let destination = temporary.path().join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut output = File::create(destination)?;
        std::io::copy(&mut entry, &mut output)?;
        output.flush()?;
    }
    verify_bundle_with_policy(temporary.path(), policy)
}
