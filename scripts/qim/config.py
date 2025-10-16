"""
QIM-A Configuration and Operating Parameters

Default parameters for QIM-A watermarking tailored to biometric time-series data.
All values based on ADR-007 and empirical bio-signal characteristics.

References:
- ADR-007: QIM-A Watermarking Architecture
- Bio-signal characteristics: fs ~ 2-4 Hz, frequency band ~ 1/200 to 1/10 Hz
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

# ============================================================================
# Operating Parameters
# ============================================================================

# Delta/Sigma ratio: Quantization step size relative to signal standard deviation
# Higher values = more robust, lower capacity
# Lower values = higher capacity, less robust
# Typical range: 0.005-0.02 for bio-signals
DELTA_SIGMA_MIN: Final[float] = 0.005
DELTA_SIGMA_MAX: Final[float] = 0.02
DELTA_SIGMA_DEFAULT: Final[float] = 0.01

# Block size in seconds: Time window for embedding/detection
# Longer blocks = better statistical properties, higher latency
# Shorter blocks = lower latency, less robust
# Typical range: 3-8 seconds for bio-signals
BLOCK_SEC_MIN: Final[int] = 3
BLOCK_SEC_MAX: Final[int] = 8
BLOCK_SEC_DEFAULT: Final[int] = 5

# Sampling frequency (Hz): Expected signal sampling rate
# Typical: 2-4 Hz for low-power bio-telemetry (M#3/M#4)
# Higher frequencies in lab settings: 10-100 Hz
FS_DEFAULT: Final[float] = 2.5  # Hz
FS_MIN: Final[float] = 1.0  # Hz
FS_MAX: Final[float] = 100.0  # Hz

# ============================================================================
# Band-Pass Filter Specifications
# ============================================================================

# Bio-signal frequency band (Hz)
# Typical physiological signals: ~0.005 Hz (1/200 s) to ~0.1 Hz (1/10 s)
# Adjusted for typical bio-telemetry sampling rates
BANDPASS_LOW_HZ: Final[float] = 0.005  # 1/200 Hz (0.005 Hz = 200 second period)
BANDPASS_HIGH_HZ: Final[float] = 0.1  # 1/10 Hz (0.1 Hz = 10 second period)

# Filter order: Butterworth filter order
# Higher order = sharper cutoff, more computation
# Typical: 2-4 for bio-signals
FILTER_ORDER: Final[int] = 3

# ============================================================================
# Detection Thresholds
# ============================================================================

# Bit Error Rate (BER) target: Maximum acceptable error rate
# QIM-A should maintain BER ≤ 5% for authentic signals
BER_TARGET: Final[float] = 0.05  # 5%

# Confidence threshold: Minimum confidence for positive detection
# Based on statistical significance (e.g., p < 0.05)
CONFIDENCE_THRESHOLD: Final[float] = 0.95  # 95% confidence

# Score threshold: Minimum correlation score for positive detection
# Normalized to [0, 1], where 1.0 = perfect match
SCORE_THRESHOLD: Final[float] = 0.7  # 70% correlation


# ============================================================================
# Configuration Dataclass
# ============================================================================


@dataclass(frozen=True)
class QIMConfig:
    """
    Immutable configuration for QIM-A watermarking.

    Attributes:
        delta_sigma: Δ/σ ratio for quantization step computation
        block_sec: Block size in seconds
        fs: Sampling frequency in Hz
        bandpass_low: Low-pass cutoff frequency (Hz)
        bandpass_high: High-pass cutoff frequency (Hz)
        filter_order: Butterworth filter order
        ber_target: Target bit error rate (0-1)
        confidence_threshold: Minimum confidence for detection (0-1)
        score_threshold: Minimum correlation score (0-1)
    """

    delta_sigma: float = DELTA_SIGMA_DEFAULT
    block_sec: int = BLOCK_SEC_DEFAULT
    fs: float = FS_DEFAULT
    bandpass_low: float = BANDPASS_LOW_HZ
    bandpass_high: float = BANDPASS_HIGH_HZ
    filter_order: int = FILTER_ORDER
    ber_target: float = BER_TARGET
    confidence_threshold: float = CONFIDENCE_THRESHOLD
    score_threshold: float = SCORE_THRESHOLD

    def __post_init__(self) -> None:
        """Validate configuration parameters."""
        if not (DELTA_SIGMA_MIN <= self.delta_sigma <= DELTA_SIGMA_MAX):
            raise ValueError(
                f"delta_sigma must be in [{DELTA_SIGMA_MIN}, {DELTA_SIGMA_MAX}]"
            )
        if not (BLOCK_SEC_MIN <= self.block_sec <= BLOCK_SEC_MAX):
            raise ValueError(f"block_sec must be in [{BLOCK_SEC_MIN}, {BLOCK_SEC_MAX}]")
        if not (FS_MIN <= self.fs <= FS_MAX):
            raise ValueError(f"fs must be in [{FS_MIN}, {FS_MAX}]")
        if self.bandpass_low >= self.bandpass_high:
            raise ValueError("bandpass_low must be < bandpass_high")
        if not (0.0 < self.ber_target < 1.0):
            raise ValueError("ber_target must be in (0, 1)")
        if not (0.0 < self.confidence_threshold < 1.0):
            raise ValueError("confidence_threshold must be in (0, 1)")
        if not (0.0 < self.score_threshold < 1.0):
            raise ValueError("score_threshold must be in (0, 1)")

    @property
    def block_samples(self) -> int:
        """Compute number of samples per block."""
        return int(self.block_sec * self.fs)

    @property
    def nyquist_freq(self) -> float:
        """Compute Nyquist frequency (fs/2)."""
        return self.fs / 2.0


# Default configuration instance
DEFAULT_CONFIG: Final[QIMConfig] = QIMConfig()
