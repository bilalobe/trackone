//! Tiny stress/validation helpers for firmware bring-up.
//!
//! These helpers are inspired by the legacy `trackone-bench/firmware-rust`
//! prototype. They are intentionally generic so binaries can decide where to
//! place buffers (linker section, `.bss`, etc.).

/// Default guard pattern used for stack high-water mark (HWM) detection.
pub const STACK_GUARD_PATTERN: u8 = 0xAA;

/// Fill a guard region with the sentinel pattern.
pub fn paint_stack_guard(guard: &mut [u8]) {
    for b in guard {
        *b = STACK_GUARD_PATTERN;
    }
}

/// Report from scanning a painted stack guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackGuardReport {
    /// Number of bytes that differ from `STACK_GUARD_PATTERN`.
    pub corrupted: usize,
    /// Number of bytes still equal to `STACK_GUARD_PATTERN`.
    pub remaining: usize,
    /// First index where corruption was observed (if any).
    pub first_corrupted: Option<usize>,
}

impl StackGuardReport {
    pub fn ok(&self) -> bool {
        self.corrupted == 0
    }

    pub fn usage_percent(&self) -> u8 {
        let total = self.corrupted + self.remaining;
        if total == 0 {
            return 0;
        }
        ((self.corrupted * 100) / total).min(100) as u8
    }
}

/// Scan a guard region and return high-water mark information.
pub fn scan_stack_guard(guard: &[u8]) -> StackGuardReport {
    let mut first_corrupted: Option<usize> = None;
    let mut corrupted = 0usize;

    for (i, &b) in guard.iter().enumerate() {
        if b != STACK_GUARD_PATTERN {
            corrupted += 1;
            if first_corrupted.is_none() {
                first_corrupted = Some(i);
            }
        }
    }

    StackGuardReport {
        corrupted,
        remaining: guard.len().saturating_sub(corrupted),
        first_corrupted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_guard_paint_and_scan() {
        let mut guard = [0u8; 16];
        paint_stack_guard(&mut guard);
        let report = scan_stack_guard(&guard);
        assert!(report.ok());
        assert_eq!(report.corrupted, 0);
        assert_eq!(report.remaining, guard.len());
        assert_eq!(report.first_corrupted, None);
        assert_eq!(report.usage_percent(), 0);

        guard[3] = 0x00;
        let report2 = scan_stack_guard(&guard);
        assert!(!report2.ok());
        assert_eq!(report2.corrupted, 1);
        assert_eq!(report2.remaining, guard.len() - 1);
        assert_eq!(report2.first_corrupted, Some(3));
    }
}
