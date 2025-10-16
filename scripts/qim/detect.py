"""
QIM-A Detection Module

Block-wise watermark detection using lattice decision logic.
Extracts embedded bits and computes confidence/correlation scores.

Key Operations:
1. Band-pass filtering (same as embedding)
2. Block-wise lattice decision (even/odd quantization)
3. Confidence scoring (statistical significance)
4. BER computation and thresholding

References:
- ADR-007: QIM-A Watermarking Architecture
- Chen & Wornell (2001): ML detection for QIM

Note: This is a STUB implementation for M#4 infrastructure setup.
      Full implementation will be added in subsequent milestones.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from numpy.typing import NDArray

    from .config import QIMConfig


@dataclass(frozen=True)
class DetectionResult:
    """
    Result of QIM watermark detection.

    Attributes:
        detected_bits: Extracted watermark bits (1D array of 0s and 1s)
        confidence: Overall detection confidence [0, 1]
        score: Correlation score [0, 1] (1.0 = perfect match)
        ber: Bit Error Rate [0, 1] (0.0 = no errors)
        qim_verified: Boolean indicating if watermark is verified
                      (True if BER ≤ target and confidence ≥ threshold)
    """

    detected_bits: NDArray[np.uint8]
    confidence: float
    score: float
    ber: float
    qim_verified: bool

    def to_dict(self) -> dict[str, float | bool]:
        """Convert to dictionary for JSON serialization."""
        return {
            "qim_verified": self.qim_verified,
            "confidence": float(self.confidence),
            "score": float(self.score),
            "ber": float(self.ber),
        }


def detect_qim_scalar(
    signal: NDArray[np.float64],
    num_bits: int,
    config: QIMConfig,
) -> NDArray[np.uint8]:
    """
    Detect watermark bits from signal using scalar QIM.

    Processes signal in blocks, extracting one bit per block using
    lattice decision logic (even/odd quantization).

    Algorithm (per block):
    1. Extract block of samples
    2. Compute Δ from block statistics
    3. Compute block centroid
    4. Quantize centroid to nearest lattice point
    5. Decide bit based on parity (even → 0, odd → 1)

    Args:
        signal: Watermarked time-series signal (1D array), pre-filtered
        num_bits: Number of bits to extract
        config: QIM configuration (Δ/σ, block size, etc.)

    Returns:
        Detected watermark bits (1D array of 0s and 1s)

    Raises:
        ValueError: If signal length < num_bits * block_samples

    References:
        - ADR-007 Section 3.5 (QIM Detection)
        - Chen & Wornell (2001): ML detector equations

    Note:
        This is a STUB. Full implementation in M#5.
    """
    block_samples = config.block_samples
    min_samples = num_bits * block_samples

    if signal.size < min_samples:
        raise ValueError(
            f"Signal too short: need {min_samples} samples for {num_bits} bits, "
            f"got {signal.size}"
        )

    # Stub implementation: return random bits
    # TODO(M#5): Implement actual scalar QIM detection with lattice decision
    detected = np.zeros(num_bits, dtype=np.uint8)

    return detected


def compute_confidence(
    detected_bits: NDArray[np.uint8],
    expected_bits: NDArray[np.uint8] | None,
    signal: NDArray[np.float64],
    config: QIMConfig,
) -> float:
    """
    Compute detection confidence score.

    Confidence is based on:
    - Statistical significance of detected pattern
    - Signal-to-noise ratio (if available)
    - Bit agreement with expected pattern (if provided)

    Args:
        detected_bits: Detected watermark bits
        expected_bits: Expected watermark bits (optional, for validation)
        signal: Input signal (for SNR estimation)
        config: QIM configuration

    Returns:
        Confidence score [0, 1]

    References:
        - ADR-007 Section 3.6 (Confidence Scoring)
    """
    # Stub implementation: return default confidence
    # TODO(M#5): Implement statistical confidence computation
    if expected_bits is not None and len(expected_bits) == len(detected_bits):
        # Compute agreement percentage
        agreement = np.mean(detected_bits == expected_bits)
        return float(agreement)

    # Default confidence when no expected bits
    return config.confidence_threshold


def compute_ber(
    detected_bits: NDArray[np.uint8],
    expected_bits: NDArray[np.uint8],
) -> float:
    """
    Compute Bit Error Rate (BER).

    BER = (number of bit errors) / (total bits)

    Args:
        detected_bits: Detected watermark bits
        expected_bits: Expected watermark bits

    Returns:
        BER [0, 1] (0.0 = no errors, 1.0 = all errors)

    Raises:
        ValueError: If bit arrays have different lengths
    """
    if len(detected_bits) != len(expected_bits):
        raise ValueError(
            f"Bit array length mismatch: {len(detected_bits)} != {len(expected_bits)}"
        )

    errors = np.sum(detected_bits != expected_bits)
    ber = float(errors) / len(detected_bits)
    return ber


def compute_correlation_score(
    signal: NDArray[np.float64],
    reference_signal: NDArray[np.float64],
) -> float:
    """
    Compute correlation score between signal and reference.

    Normalized cross-correlation coefficient [0, 1].

    Args:
        signal: Input signal
        reference_signal: Reference signal (e.g., original unwatermarked)

    Returns:
        Correlation score [0, 1] (1.0 = perfect correlation)

    Raises:
        ValueError: If signals have different lengths
    """
    if signal.size != reference_signal.size:
        raise ValueError(
            f"Signal length mismatch: {signal.size} != {reference_signal.size}"
        )

    # Stub implementation: return default score
    # TODO(M#5): Implement actual cross-correlation computation
    return 0.7  # Default score


def detect_watermark(
    signal: NDArray[np.float64],
    expected_bits: NDArray[np.uint8],
    config: QIMConfig,
) -> DetectionResult:
    """
    High-level watermark detection function.

    Orchestrates the complete detection pipeline:
    1. Band-pass filtering (same as embedding)
    2. QIM detection (scalar lattice decision)
    3. Confidence scoring
    4. BER computation
    5. Verification decision

    Args:
        signal: Watermarked time-series signal (1D array)
        expected_bits: Expected watermark bits (for validation)
        config: QIM configuration

    Returns:
        DetectionResult with extracted bits, confidence, score, BER, and verification status

    Example:
        >>> import numpy as np
        >>> from scripts.qim.config import DEFAULT_CONFIG
        >>> signal = np.random.randn(100)
        >>> expected = np.array([0, 1, 0, 1], dtype=np.uint8)
        >>> result = detect_watermark(signal, expected, DEFAULT_CONFIG)
        >>> assert 0.0 <= result.confidence <= 1.0
        >>> assert 0.0 <= result.ber <= 1.0

    References:
        - ADR-007: Complete QIM-A detection pipeline

    Note:
        Dynamic import is used here to avoid circular dependency issues during
        test imports. In production use, consider restructuring modules to use
        standard imports at module level. This is acceptable for M#4 stubs but
        should be refactored in M#5 when modules are properly packaged.
    """
    # Import here to avoid circular dependency issues
    import importlib.util
    import sys
    from pathlib import Path

    # Load embed module dynamically (TODO: refactor to module-level import in M#5)
    embed_path = Path(__file__).parent / "embed.py"
    embed_spec = importlib.util.spec_from_file_location(
        "qim_embed_internal", str(embed_path)
    )
    if embed_spec and embed_spec.loader:
        embed_module = importlib.util.module_from_spec(embed_spec)
        sys.modules["qim_embed_internal"] = embed_module
        embed_spec.loader.exec_module(embed_module)
        bandpass_filter = embed_module.bandpass_filter
    else:
        raise ImportError("Failed to load embed module")

    # Step 1: Band-pass filter
    filtered = bandpass_filter(
        signal,
        config.fs,
        config.bandpass_low,
        config.bandpass_high,
        config.filter_order,
    )

    # Step 2: QIM detection
    num_bits = len(expected_bits)
    detected_bits = detect_qim_scalar(filtered, num_bits, config)

    # Step 3: Compute metrics
    ber = compute_ber(detected_bits, expected_bits)
    confidence = compute_confidence(detected_bits, expected_bits, signal, config)
    # Stub: Use placeholder score (real correlation with reference signal in M#5)
    score = 0.5  # Placeholder: 50% correlation (neither good nor bad)

    # Step 4: Verification decision
    qim_verified = (ber <= config.ber_target) and (
        confidence >= config.confidence_threshold
    )

    return DetectionResult(
        detected_bits=detected_bits,
        confidence=confidence,
        score=score,
        ber=ber,
        qim_verified=qim_verified,
    )
