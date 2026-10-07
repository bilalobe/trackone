//! Process-local events and cached evidence-pipeline readiness.

use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

pub const SAMPLE_INTERVAL_SECONDS: u64 = 5;
pub const MAX_SAMPLE_AGE_SECONDS: u64 = 15;

pub fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug)]
pub struct PipelineEvents {
    /// A write failure cannot be disproved by a successful read-only probe.
    pub storage_unavailable: AtomicBool,
    pub admission_rejections: AtomicU64,
    pub recovery_events: AtomicU64,
    pub sealing_failures: AtomicU64,
    pub terminal_timestamp_failures: AtomicU64,
    pub process_started_at_unix_seconds: u64,
}

impl Default for PipelineEvents {
    fn default() -> Self {
        Self {
            storage_unavailable: AtomicBool::new(false),
            admission_rejections: AtomicU64::new(0),
            recovery_events: AtomicU64::new(0),
            sealing_failures: AtomicU64::new(0),
            terminal_timestamp_failures: AtomicU64::new(0),
            process_started_at_unix_seconds: epoch_seconds(),
        }
    }
}

impl PipelineEvents {
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "process_started_at_unix_seconds": self.process_started_at_unix_seconds,
            "admission_rejections": self.admission_rejections.load(Ordering::Relaxed),
            "recovery_events": self.recovery_events.load(Ordering::Relaxed),
            "sealing_failures": self.sealing_failures.load(Ordering::Relaxed),
            "terminal_timestamp_failures": self.terminal_timestamp_failures.load(Ordering::Relaxed),
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct CapacityLimits {
    pub max_pending_timestamps: Option<u64>,
    pub max_retained_evidence_bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PipelineStatistics {
    pub pending_timestamp_count: u64,
    pub oldest_pending_timestamp_age_seconds: Option<f64>,
    pub last_successful_timestamp_attachment: Option<String>,
    pub terminal_failed_segment_count: u64,
    pub retrying_timestamp_count: u64,
    pub retained_evidence_bytes: u64,
}

impl CapacityLimits {
    pub fn exhausted(&self, stats: &PipelineStatistics) -> Vec<&'static str> {
        let mut reasons = Vec::new();
        if self
            .max_pending_timestamps
            .is_some_and(|limit| stats.pending_timestamp_count >= limit)
        {
            reasons.push("queue_capacity_exhausted");
        }
        if self
            .max_retained_evidence_bytes
            .is_some_and(|limit| stats.retained_evidence_bytes >= limit)
        {
            reasons.push("storage_capacity_exhausted");
        }
        reasons
    }
}

#[derive(Clone, Debug)]
pub struct ReadinessSample {
    pub database_available: bool,
    pub producer_state: &'static str,
    pub reasons: Vec<&'static str>,
    pub statistics: Option<PipelineStatistics>,
}

pub struct PipelineReadiness {
    sample: Mutex<Option<(Instant, u64, ReadinessSample)>>,
    shutdown: AtomicBool,
    pub limits: CapacityLimits,
}

impl PipelineReadiness {
    pub fn new(limits: CapacityLimits) -> Self {
        Self {
            sample: Mutex::new(None),
            shutdown: AtomicBool::new(false),
            limits,
        }
    }

    pub fn observe(&self, sample: ReadinessSample) {
        *self.sample.lock().unwrap_or_else(|p| p.into_inner()) =
            Some((Instant::now(), epoch_seconds(), sample));
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    pub fn response(&self, events: &PipelineEvents) -> (bool, serde_json::Value) {
        let sample = self
            .sample
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut reasons = Vec::new();
        let mut database_available = None;
        let mut producer_state = "unknown";
        let mut statistics = None;
        let mut observed_at = None;
        if let Some((instant, epoch, sample)) = sample {
            observed_at = Some(epoch);
            if instant.elapsed().as_secs() >= MAX_SAMPLE_AGE_SECONDS {
                reasons.push("observation_stale");
            } else {
                database_available = Some(sample.database_available);
                producer_state = sample.producer_state;
                reasons.extend(sample.reasons);
                statistics = sample.statistics;
            }
        } else {
            reasons.push("observation_unavailable");
        }
        if let Some(stats) = &statistics {
            reasons.extend(self.limits.exhausted(stats));
        }
        if self.shutdown.load(Ordering::Relaxed) {
            reasons.push("shutdown");
        }
        if events.storage_unavailable.load(Ordering::Relaxed) {
            reasons.push("storage_unavailable");
        }
        let ready = reasons.is_empty();
        let degraded = statistics
            .as_ref()
            .map(|s| s.retrying_timestamp_count > 0 || s.terminal_failed_segment_count > 0);
        let pressure = |used: Option<u64>, limit: Option<u64>| {
            serde_json::json!({
                "used": used, "limit": limit,
                "utilization": used.zip(limit).map(|(u,l)| u as f64 / l as f64)
            })
        };
        (
            ready,
            serde_json::json!({
                "ready": ready, "admission_available": ready, "reasons": reasons,
                "database_available": database_available, "producer_state": producer_state,
                "pipeline_degraded": degraded, "observed_at_unix_seconds": observed_at,
                "statistics": statistics,
                "capacity": {
                    "pending_timestamps": pressure(statistics.as_ref().map(|s| s.pending_timestamp_count), self.limits.max_pending_timestamps),
                    "retained_evidence_bytes": pressure(statistics.as_ref().map(|s| s.retained_evidence_bytes), self.limits.max_retained_evidence_bytes)
                },
                "counters": events.snapshot()
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> ReadinessSample {
        ReadinessSample {
            database_available: true,
            producer_state: "ready",
            reasons: vec![],
            statistics: Some(PipelineStatistics {
                pending_timestamp_count: 1,
                retained_evidence_bytes: 10,
                oldest_pending_timestamp_age_seconds: Some(2.0),
                last_successful_timestamp_attachment: None,
                terminal_failed_segment_count: 0,
                retrying_timestamp_count: 0,
            }),
        }
    }

    #[test]
    fn readiness_starts_unknown_and_expires_without_reporting_zero_usage() {
        let readiness = PipelineReadiness::new(CapacityLimits::default());
        let events = PipelineEvents::default();
        let (ready, value) = readiness.response(&events);
        assert!(!ready);
        assert_eq!(value["reasons"][0], "observation_unavailable");
        assert!(value["statistics"].is_null());
        readiness.observe(healthy());
        assert!(readiness.response(&events).0);
        readiness.sample.lock().unwrap().as_mut().unwrap().0 =
            Instant::now() - std::time::Duration::from_secs(MAX_SAMPLE_AGE_SECONDS);
        let (ready, value) = readiness.response(&events);
        assert!(!ready);
        assert_eq!(value["reasons"][0], "observation_stale");
        assert!(value["statistics"].is_null());
        assert!(value["database_available"].is_null());
        assert!(value["capacity"]["pending_timestamps"]["used"].is_null());
    }

    #[test]
    fn degradation_is_ready_but_capacity_and_shutdown_are_unavailable() {
        let readiness = PipelineReadiness::new(CapacityLimits {
            max_pending_timestamps: Some(2),
            max_retained_evidence_bytes: Some(11),
        });
        let events = PipelineEvents::default();
        let mut sample = healthy();
        sample
            .statistics
            .as_mut()
            .unwrap()
            .terminal_failed_segment_count = 3;
        readiness.observe(sample.clone());
        let (ready, value) = readiness.response(&events);
        assert!(ready);
        assert_eq!(value["pipeline_degraded"], true);
        sample.statistics.as_mut().unwrap().pending_timestamp_count = 2;
        sample.statistics.as_mut().unwrap().retained_evidence_bytes = 11;
        readiness.observe(sample);
        let (ready, value) = readiness.response(&events);
        assert!(!ready);
        assert_eq!(
            value["reasons"],
            serde_json::json!(["queue_capacity_exhausted", "storage_capacity_exhausted"])
        );
        readiness.observe(healthy());
        readiness.shutdown();
        assert_eq!(readiness.response(&events).1["reasons"][0], "shutdown");
    }
}
