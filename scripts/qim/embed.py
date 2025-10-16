"""
QIM-A Embedding Module

Scalar Quantization Index Modulation (QIM) for watermark embedding.
Implements band-pass filtering and lattice-based embedding for biometric
time-series data.

Key Operations:
1. Band-pass filtering (bio frequency band: ~1/200 to 1/10 Hz)
2. Compute Δ from signal σ (standard deviation)
3. Scalar lattice quantization for bit embedding
4. Block-wise processing for robustness

References:
- ADR-007: QIM-A Watermarking Architecture
- Chen & Wornell (2001): Quantization Index Modulation

Note: This is a STUB implementation for M#4 infrastructure setup.
      Full implementation will be added in subsequent milestones.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from numpy.typing import NDArray

    from .config import QIMConfig


def bandpass_filter(
    signal: NDArray[np.float64],
    fs: float,
    low_hz: float,
    high_hz: float,
    order: int = 3,
) -> NDArray[np.float64]:
    """
    Apply Butterworth band-pass filter to signal.

    Filters signal to retain only frequencies in [low_hz, high_hz].
    Typical bio-signal band: ~0.005 Hz to ~0.1 Hz (1/200 to 1/10 Hz).

    Args:
        signal: Input time-series signal (1D array)
        fs: Sampling frequency (Hz)
        low_hz: Low-pass cutoff frequency (Hz)
        high_hz: High-pass cutoff frequency (Hz)
        order: Butterworth filter order (default: 3)

    Returns:
        Filtered signal (same shape as input)

    Raises:
        ValueError: If filter parameters are invalid

    References:
        - scipy.signal.butter
        - ADR-007 Section 3.2 (Signal Preprocessing)
    """
    # Stub implementation - will use scipy.signal.butter + filtfilt in production
    # For now, return original signal (no filtering)
    # TODO(M#5): Implement actual band-pass filtering with scipy
    if low_hz >= high_hz:
        raise ValueError(f"low_hz ({low_hz}) must be < high_hz ({high_hz})")
    if high_hz >= fs / 2.0:
        raise ValueError(f"high_hz ({high_hz}) must be < Nyquist frequency ({fs/2.0})")

    # Stub: return unfiltered signal
    return signal.copy()


def compute_delta(signal: NDArray[np.float64], delta_sigma: float) -> float:
    """
    Compute quantization step size Δ from signal statistics.

    Δ = delta_sigma * σ, where σ is the standard deviation of the signal.
    Typical delta_sigma: 0.005-0.02 for bio-signals.

    Args:
        signal: Input time-series signal (1D array)
        delta_sigma: Δ/σ ratio (dimensionless)

    Returns:
        Quantization step size Δ

    Raises:
        ValueError: If signal is empty or has zero variance

    References:
        - ADR-007 Section 3.3 (Quantization Parameter Selection)
    """
    if signal.size == 0:
        raise ValueError("Signal must not be empty")

    sigma = np.std(signal)
    if sigma == 0.0:
        raise ValueError("Signal has zero variance (cannot compute Δ)")

    delta = delta_sigma * sigma
    return float(delta)


def embed_qim_scalar(
    signal: NDArray[np.float64],
    bits: NDArray[np.uint8],
    config: QIMConfig,
) -> NDArray[np.float64]:
    """
    Embed watermark bits into signal using scalar QIM.

    Processes signal in blocks, embedding one bit per block using
    lattice-based quantization. Blocks are defined by config.block_samples.

    Algorithm (per block):
    1. Extract block of samples
    2. Compute Δ from block statistics
    3. Quantize block centroid to nearest lattice point (even/odd for bit 0/1)
    4. Adjust block samples to match quantized centroid

    Args:
        signal: Input time-series signal (1D array), pre-filtered
        bits: Watermark bits to embed (1D array of 0s and 1s)
        config: QIM configuration (Δ/σ, block size, etc.)

    Returns:
        Watermarked signal (same shape as input)

    Raises:
        ValueError: If signal length < bits length * block_samples

    References:
        - ADR-007 Section 3.4 (QIM Embedding)
        - Chen & Wornell (2001): Dither modulation equations

    Note:
        This is a STUB. Full implementation in M#5.
    """
    block_samples = config.block_samples
    num_bits = len(bits)
    min_samples = num_bits * block_samples

    if signal.size < min_samples:
        raise ValueError(
            f"Signal too short: need {min_samples} samples for {num_bits} bits, "
            f"got {signal.size}"
        )

    # Stub implementation: return original signal (no embedding)
    # TODO(M#5): Implement actual scalar QIM embedding
    watermarked = signal.copy()

    return watermarked


def embed_watermark(
    signal: NDArray[np.float64],
    bits: NDArray[np.uint8],
    config: QIMConfig,
) -> NDArray[np.float64]:
    """
    High-level watermark embedding function.

    Orchestrates the complete embedding pipeline:
    1. Band-pass filtering (remove DC and high-frequency noise)
    2. QIM embedding (scalar lattice quantization)

    Args:
        signal: Input time-series signal (1D array)
        bits: Watermark bits to embed (1D array of 0s and 1s)
        config: QIM configuration

    Returns:
        Watermarked signal (same shape as input)

    Raises:
        ValueError: If signal or bits are invalid

    Example:
        >>> import numpy as np
        >>> from scripts.qim.config import DEFAULT_CONFIG
        >>> signal = np.random.randn(100)
        >>> bits = np.array([0, 1, 0, 1], dtype=np.uint8)
        >>> watermarked = embed_watermark(signal, bits, DEFAULT_CONFIG)
        >>> assert watermarked.shape == signal.shape

    References:
        - ADR-007: Complete QIM-A embedding pipeline
    """
    # Step 1: Band-pass filter
    filtered = bandpass_filter(
        signal,
        config.fs,
        config.bandpass_low,
        config.bandpass_high,
        config.filter_order,
    )

    # Step 2: QIM embedding
    watermarked = embed_qim_scalar(filtered, bits, config)

    return watermarked
