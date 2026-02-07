//! Hardware abstraction traits for pod firmware.
//!
//! This module is dependency-free and intended to stay small. It is inspired by
//! the legacy `trackone-bench/firmware-rust` prototype, but updated to be a
//! stable home for portable firmware-facing interfaces.

/// GPIO output pin trait.
pub trait OutputPin {
    fn set_high(&mut self);
    fn set_low(&mut self);
    fn toggle(&mut self);
    fn is_set_high(&self) -> bool;
}

/// GPIO input pin trait.
pub trait InputPin {
    /// Read pin state (`true` = high).
    fn is_high(&self) -> bool;

    /// Read pin state (`true` = low).
    fn is_low(&self) -> bool {
        !self.is_high()
    }
}

/// Delay provider trait (milliseconds).
pub trait DelayMs {
    fn delay_ms(&mut self, ms: u32);
}

/// Delay provider trait (microseconds).
pub trait DelayUs {
    fn delay_us(&mut self, us: u32);
}

/// Monotonic clock for timestamps.
pub trait MonotonicClock {
    /// Current time in milliseconds since boot.
    fn now_ms(&self) -> u32;
    /// Current time in microseconds since boot.
    fn now_us(&self) -> u64;
}

/// SPI bus trait for radio/sensor communication.
pub trait SpiBus {
    type Error;

    fn transfer(&mut self, read: &mut [u8], write: &[u8]) -> Result<(), Self::Error>;
    fn write(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    fn read(&mut self, data: &mut [u8]) -> Result<(), Self::Error>;
}

/// I2C bus trait for sensors.
pub trait I2cBus {
    type Error;

    fn write(&mut self, addr: u8, data: &[u8]) -> Result<(), Self::Error>;
    fn read(&mut self, addr: u8, data: &mut [u8]) -> Result<(), Self::Error>;
    fn write_read(&mut self, addr: u8, write: &[u8], read: &mut [u8]) -> Result<(), Self::Error>;
}

/// UART/Serial trait for debug or communication.
pub trait Serial {
    type Error;

    fn write(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
    fn available(&self) -> bool;
}

/// Random number generator trait.
pub trait Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]);

    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
}

/// Non-volatile storage trait.
pub trait NvStorage {
    type Error;

    fn read(&self, offset: u32, buf: &mut [u8]) -> Result<(), Self::Error>;
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), Self::Error>;
    fn erase_sector(&mut self, offset: u32) -> Result<(), Self::Error>;
}

/// Power management trait.
pub trait PowerControl {
    fn sleep(&mut self);
    fn deep_sleep(&mut self);
    fn battery_mv(&self) -> Option<u16>;
}

/// Watchdog trait.
pub trait Watchdog {
    fn feed(&mut self);
    fn start(&mut self, timeout_ms: u32);
}

#[cfg(feature = "mock")]
pub mod mock {
    use core::cell::Cell;

    use super::*;

    /// Mock GPIO output pin.
    pub struct MockOutputPin {
        state: Cell<bool>,
        pub name: &'static str,
    }

    impl MockOutputPin {
        pub fn new(name: &'static str) -> Self {
            Self {
                state: Cell::new(false),
                name,
            }
        }
    }

    impl OutputPin for MockOutputPin {
        fn set_high(&mut self) {
            self.state.set(true);
            #[cfg(all(feature = "mock-log", feature = "std"))]
            println!("[MOCK] {} -> HIGH", self.name);
        }

        fn set_low(&mut self) {
            self.state.set(false);
            #[cfg(all(feature = "mock-log", feature = "std"))]
            println!("[MOCK] {} -> LOW", self.name);
        }

        fn toggle(&mut self) {
            self.state.set(!self.state.get());
        }

        fn is_set_high(&self) -> bool {
            self.state.get()
        }
    }

    /// Mock GPIO input pin.
    pub struct MockInputPin {
        state: Cell<bool>,
        pub name: &'static str,
    }

    impl MockInputPin {
        pub fn new(name: &'static str) -> Self {
            Self {
                state: Cell::new(false),
                name,
            }
        }

        pub fn set_state(&self, high: bool) {
            self.state.set(high);
        }
    }

    impl InputPin for MockInputPin {
        fn is_high(&self) -> bool {
            self.state.get()
        }
    }

    /// Mock delay (no-op; uses `std::thread::sleep` when available).
    pub struct MockDelay;

    impl DelayMs for MockDelay {
        fn delay_ms(&mut self, ms: u32) {
            #[cfg(feature = "std")]
            std::thread::sleep(std::time::Duration::from_millis(ms as u64));
            let _ = ms;
        }
    }

    impl DelayUs for MockDelay {
        fn delay_us(&mut self, us: u32) {
            #[cfg(feature = "std")]
            std::thread::sleep(std::time::Duration::from_micros(us as u64));
            let _ = us;
        }
    }

    /// Mock monotonic clock.
    pub struct MockClock {
        #[cfg(feature = "std")]
        start: std::time::Instant,
        #[cfg(not(feature = "std"))]
        ticks: Cell<u64>,
    }

    impl MockClock {
        pub fn new() -> Self {
            Self {
                #[cfg(feature = "std")]
                start: std::time::Instant::now(),
                #[cfg(not(feature = "std"))]
                ticks: Cell::new(0),
            }
        }

        #[cfg(not(feature = "std"))]
        pub fn advance_us(&self, us: u64) {
            self.ticks.set(self.ticks.get() + us);
        }
    }

    impl Default for MockClock {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MonotonicClock for MockClock {
        fn now_ms(&self) -> u32 {
            #[cfg(feature = "std")]
            return self.start.elapsed().as_millis() as u32;
            #[cfg(not(feature = "std"))]
            return (self.ticks.get() / 1000) as u32;
        }

        fn now_us(&self) -> u64 {
            #[cfg(feature = "std")]
            return self.start.elapsed().as_micros() as u64;
            #[cfg(not(feature = "std"))]
            return self.ticks.get();
        }
    }

    /// Mock RNG (insecure; for testing only).
    pub struct MockRng {
        seed: u32,
    }

    impl MockRng {
        pub fn new(seed: u32) -> Self {
            Self { seed }
        }
    }

    impl Default for MockRng {
        fn default() -> Self {
            Self::new(0xDEADBEEF)
        }
    }

    impl Rng for MockRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest.iter_mut() {
                self.seed = self.seed.wrapping_mul(1103515245).wrapping_add(12345);
                *byte = (self.seed >> 16) as u8;
            }
        }
    }

    /// Mock power control.
    pub struct MockPower {
        battery_mv: u16,
    }

    impl MockPower {
        pub fn new(battery_mv: u16) -> Self {
            Self { battery_mv }
        }
    }

    impl Default for MockPower {
        fn default() -> Self {
            Self::new(3300)
        }
    }

    impl PowerControl for MockPower {
        fn sleep(&mut self) {
            #[cfg(all(feature = "mock-log", feature = "std"))]
            println!("[MOCK] Entering sleep mode");
        }

        fn deep_sleep(&mut self) {
            #[cfg(all(feature = "mock-log", feature = "std"))]
            println!("[MOCK] Entering deep sleep");
        }

        fn battery_mv(&self) -> Option<u16> {
            Some(self.battery_mv)
        }
    }
}
