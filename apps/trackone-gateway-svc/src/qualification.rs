//! Local controls compiled only into the recovery qualification build.
//!
//! The controller atomically publishes arm.json in a private directory. A
//! matching operation consumes it, reports reached.json, then waits for release
//! or SIGKILL. No network control surface is exposed.

use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

#[derive(Deserialize, Serialize)]
struct Arm {
    boundary: String,
    ledger_id: String,
    key: Option<String>,
    segment_number: Option<u64>,
}

/// Pause a selected operation, with a hard deadline to avoid a forgotten arm.
pub fn hit(boundary: &str, ledger: &str, key: Option<&str>, segment: Option<u64>) {
    let Some(directory) = std::env::var_os("TRACKONE_QUALIFICATION_CONTROL") else {
        return;
    };
    let directory = PathBuf::from(directory);
    let arm_path = directory.join("arm.json");
    let Ok(bytes) = fs::read(&arm_path) else {
        return;
    };
    let arm: Arm = serde_json::from_slice(&bytes).expect("invalid qualification arm");
    if arm.boundary != boundary
        || arm.ledger_id != ledger
        || arm.key.as_deref().is_some_and(|wanted| Some(wanted) != key)
        || arm
            .segment_number
            .is_some_and(|wanted| Some(wanted) != segment)
    {
        return;
    }
    // Only one worker may consume this arm.
    if fs::rename(&arm_path, directory.join("consumed.json")).is_err() {
        return;
    }
    let bytes = serde_json::to_vec(&serde_json::json!({
        "boundary": boundary, "ledger_id": ledger, "key": key,
        "segment_number": segment, "pid": std::process::id(),
    }))
    .expect("qualification event serialization");
    fs::write(directory.join("reached.tmp"), bytes).expect("qualification event write");
    fs::rename(
        directory.join("reached.tmp"),
        directory.join("reached.json"),
    )
    .expect("qualification event publication");
    let deadline = Instant::now() + Duration::from_secs(60);
    while !directory.join("release").exists() {
        assert!(
            Instant::now() < deadline,
            "qualification hook release deadline exceeded"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[derive(Deserialize)]
pub struct ClockOverride {
    pub now_ms: u64,
    pub continuity_id: String,
}

pub fn clock_override() -> Option<ClockOverride> {
    let path = std::env::var_os("TRACKONE_QUALIFICATION_CLOCK")?;
    Some(
        serde_json::from_slice(&fs::read(path).expect("qualification clock read"))
            .expect("invalid qualification clock"),
    )
}
