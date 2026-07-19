//! Durable replay-window state and continuity checks.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::string::String;
use std::vec::Vec;

use crate::RejectReason;

#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayWindow {
    window_size: u64,
    highest_fc_seen: Option<u64>,
    seen: BTreeSet<u64>,
}

/// Complete durable replay state.  Persisting only a high-water mark loses
/// accepted reordered counters and permits replay after a process restart.
#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayWindowSnapshot {
    pub version: u8,
    pub namespace: String,
    pub window_size: u64,
    pub highest_fc_seen: Option<u64>,
    pub seen_fcs: Vec<u64>,
}

#[cfg(feature = "std")]
impl ReplayWindow {
    pub fn new(window_size: u64, highest_fc_seen: Option<u64>) -> Self {
        let mut seen = BTreeSet::new();
        // Compatibility callers that only retained the old high-water state
        // must at least never re-admit that counter after restart.
        if let Some(fc) = highest_fc_seen {
            seen.insert(fc);
        }
        Self {
            window_size,
            highest_fc_seen,
            seen,
        }
    }

    pub fn from_snapshot(snapshot: ReplayWindowSnapshot) -> Result<Self, RejectReason> {
        if snapshot.version != 1 || snapshot.window_size == 0 {
            return Err(RejectReason::ContinuityBreak);
        }
        let mut state = Self {
            window_size: snapshot.window_size,
            highest_fc_seen: snapshot.highest_fc_seen,
            seen: snapshot.seen_fcs.into_iter().collect(),
        };
        if let Some(highest) = state.highest_fc_seen {
            state.seen.insert(highest);
            let lower = highest.saturating_sub(state.window_size);
            if state.seen.iter().any(|fc| *fc < lower || *fc > highest) {
                return Err(RejectReason::ContinuityBreak);
            }
        } else if !state.seen.is_empty() {
            return Err(RejectReason::ContinuityBreak);
        }
        Ok(state)
    }

    pub fn snapshot(&self, namespace: impl Into<String>) -> ReplayWindowSnapshot {
        ReplayWindowSnapshot {
            version: 1,
            namespace: namespace.into(),
            window_size: self.window_size,
            highest_fc_seen: self.highest_fc_seen,
            seen_fcs: self.seen_fcs(),
        }
    }

    pub fn window_size(&self) -> u64 {
        self.window_size
    }

    pub fn highest_fc_seen(&self) -> Option<u64> {
        self.highest_fc_seen
    }

    pub fn seen_fcs(&self) -> Vec<u64> {
        self.seen.iter().copied().collect()
    }

    pub fn check_and_update(&mut self, fc: u64) -> Result<(), RejectReason> {
        let Some(highest) = self.highest_fc_seen else {
            self.highest_fc_seen = Some(fc);
            self.seen.insert(fc);
            return Ok(());
        };

        if self.seen.contains(&fc) {
            return Err(RejectReason::Duplicate);
        }

        if fc < highest && (highest - fc) > self.window_size {
            return Err(RejectReason::OutOfWindow);
        }

        if fc > highest && (fc - highest) > self.window_size {
            return Err(RejectReason::OutOfWindow);
        }

        if fc > highest {
            self.highest_fc_seen = Some(fc);
            let lower_bound = fc.saturating_sub(self.window_size);
            self.seen.retain(|seen_fc| *seen_fc >= lower_bound);
        }

        self.seen.insert(fc);
        Ok(())
    }
}
