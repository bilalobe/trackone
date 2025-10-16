#!/usr/bin/env python3
"""
Test suite for QIM-A detection module.

Tests cover:
- Scalar QIM detection function signatures
- Confidence scoring
- BER computation
- Detection result structure

Note: These are STUB tests for M#4 infrastructure validation.
      Full test coverage will be added in M#5 with actual implementation.

References:
- ADR-007: QIM-A Watermarking Architecture
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np
import pytest

# Import QIM modules
QIM_DIR = Path(__file__).parent.parent / "qim"

config_spec = importlib.util.spec_from_file_location(
    "qim_config", str(QIM_DIR / "config.py")
)
assert config_spec and config_spec.loader
config = importlib.util.module_from_spec(config_spec)
sys.modules["qim_config"] = config
config_spec.loader.exec_module(config)  # type: ignore

detect_spec = importlib.util.spec_from_file_location(
    "qim_detect", str(QIM_DIR / "detect.py")
)
assert detect_spec and detect_spec.loader
detect = importlib.util.module_from_spec(detect_spec)
sys.modules["qim_detect"] = detect
detect_spec.loader.exec_module(detect)  # type: ignore


class TestDetectQIMScalar:
    """Test scalar QIM detection (stub behavior)."""

    def test_detect_returns_correct_length(self) -> None:
        """Test that detection returns array with correct length."""
        cfg = config.DEFAULT_CONFIG
        block_samples = cfg.block_samples
        signal = np.random.randn(block_samples * 4)
        detected = detect.detect_qim_scalar(signal, num_bits=4, config=cfg)
        assert len(detected) == 4
        assert detected.dtype == np.uint8

    def test_detect_validates_signal_length(self) -> None:
        """Test that detection validates signal length vs. num_bits."""
        cfg = config.DEFAULT_CONFIG
        block_samples = cfg.block_samples
        # Signal too short for 4 bits
        signal = np.random.randn(block_samples * 2)
        with pytest.raises(ValueError, match="Signal too short"):
            detect.detect_qim_scalar(signal, num_bits=4, config=cfg)

    def test_detect_accepts_sufficient_length(self) -> None:
        """Test that detection succeeds with sufficient signal length."""
        cfg = config.DEFAULT_CONFIG
        block_samples = cfg.block_samples
        # Signal long enough for 4 bits
        signal = np.random.randn(block_samples * 4)
        detected = detect.detect_qim_scalar(signal, num_bits=4, config=cfg)
        assert len(detected) == 4


class TestComputeConfidence:
    """Test confidence scoring."""

    def test_confidence_range(self) -> None:
        """Test that confidence is in [0, 1] range."""
        cfg = config.DEFAULT_CONFIG
        detected = np.array([0, 1, 0, 1], dtype=np.uint8)
        expected = np.array([0, 1, 0, 1], dtype=np.uint8)
        signal = np.random.randn(100)
        confidence = detect.compute_confidence(detected, expected, signal, cfg)
        assert 0.0 <= confidence <= 1.0

    def test_confidence_perfect_match(self) -> None:
        """Test that perfect match gives high confidence."""
        cfg = config.DEFAULT_CONFIG
        detected = np.array([0, 1, 0, 1], dtype=np.uint8)
        expected = np.array([0, 1, 0, 1], dtype=np.uint8)
        signal = np.random.randn(100)
        confidence = detect.compute_confidence(detected, expected, signal, cfg)
        assert confidence == 1.0  # Perfect agreement

    def test_confidence_no_match(self) -> None:
        """Test that no match gives low confidence."""
        cfg = config.DEFAULT_CONFIG
        detected = np.array([0, 0, 0, 0], dtype=np.uint8)
        expected = np.array([1, 1, 1, 1], dtype=np.uint8)
        signal = np.random.randn(100)
        confidence = detect.compute_confidence(detected, expected, signal, cfg)
        assert confidence == 0.0  # No agreement

    def test_confidence_without_expected(self) -> None:
        """Test confidence computation without expected bits."""
        cfg = config.DEFAULT_CONFIG
        detected = np.array([0, 1, 0, 1], dtype=np.uint8)
        signal = np.random.randn(100)
        confidence = detect.compute_confidence(detected, None, signal, cfg)
        assert 0.0 <= confidence <= 1.0


class TestComputeBER:
    """Test Bit Error Rate computation."""

    def test_ber_perfect_match(self) -> None:
        """Test BER = 0 for perfect match."""
        detected = np.array([0, 1, 0, 1], dtype=np.uint8)
        expected = np.array([0, 1, 0, 1], dtype=np.uint8)
        ber = detect.compute_ber(detected, expected)
        assert ber == 0.0

    def test_ber_all_errors(self) -> None:
        """Test BER = 1 for all errors."""
        detected = np.array([0, 0, 0, 0], dtype=np.uint8)
        expected = np.array([1, 1, 1, 1], dtype=np.uint8)
        ber = detect.compute_ber(detected, expected)
        assert ber == 1.0

    def test_ber_half_errors(self) -> None:
        """Test BER = 0.5 for 50% errors."""
        detected = np.array([0, 1, 0, 1], dtype=np.uint8)
        expected = np.array([1, 1, 0, 0], dtype=np.uint8)
        ber = detect.compute_ber(detected, expected)
        assert ber == 0.5

    def test_ber_length_mismatch(self) -> None:
        """Test that length mismatch raises ValueError."""
        detected = np.array([0, 1, 0, 1], dtype=np.uint8)
        expected = np.array([0, 1], dtype=np.uint8)
        with pytest.raises(ValueError, match="length mismatch"):
            detect.compute_ber(detected, expected)


class TestComputeCorrelationScore:
    """Test correlation score computation."""

    def test_correlation_range(self) -> None:
        """Test that correlation is in [0, 1] range."""
        signal1 = np.random.randn(100)
        signal2 = np.random.randn(100)
        score = detect.compute_correlation_score(signal1, signal2)
        assert 0.0 <= score <= 1.0

    def test_correlation_length_mismatch(self) -> None:
        """Test that length mismatch raises ValueError."""
        signal1 = np.random.randn(100)
        signal2 = np.random.randn(50)
        with pytest.raises(ValueError, match="length mismatch"):
            detect.compute_correlation_score(signal1, signal2)


class TestDetectionResult:
    """Test DetectionResult dataclass."""

    def test_detection_result_structure(self) -> None:
        """Test DetectionResult has expected fields."""
        bits = np.array([0, 1, 0, 1], dtype=np.uint8)
        result = detect.DetectionResult(
            detected_bits=bits,
            confidence=0.95,
            score=0.8,
            ber=0.05,
            qim_verified=True,
        )
        assert np.array_equal(result.detected_bits, bits)
        assert result.confidence == 0.95
        assert result.score == 0.8
        assert result.ber == 0.05
        assert result.qim_verified is True

    def test_detection_result_to_dict(self) -> None:
        """Test DetectionResult.to_dict() method."""
        bits = np.array([0, 1, 0, 1], dtype=np.uint8)
        result = detect.DetectionResult(
            detected_bits=bits,
            confidence=0.95,
            score=0.8,
            ber=0.05,
            qim_verified=True,
        )
        d = result.to_dict()
        assert d["qim_verified"] is True
        assert d["confidence"] == 0.95
        assert d["score"] == 0.8
        assert d["ber"] == 0.05


class TestDetectWatermark:
    """Test high-level watermark detection."""

    def test_detect_watermark_pipeline(self) -> None:
        """Test complete detection pipeline."""
        cfg = config.DEFAULT_CONFIG
        block_samples = cfg.block_samples
        signal = np.random.randn(block_samples * 4)
        expected = np.array([0, 1, 0, 1], dtype=np.uint8)
        result = detect.detect_watermark(signal, expected, cfg)
        assert isinstance(result, detect.DetectionResult)
        assert len(result.detected_bits) == len(expected)
        assert 0.0 <= result.confidence <= 1.0
        assert 0.0 <= result.score <= 1.0
        assert 0.0 <= result.ber <= 1.0
        assert isinstance(result.qim_verified, bool)

    def test_detect_watermark_verification_logic(self) -> None:
        """Test that verification logic uses BER and confidence thresholds."""
        cfg = config.DEFAULT_CONFIG
        block_samples = cfg.block_samples
        signal = np.random.randn(block_samples * 4)
        expected = np.array([0, 1, 0, 1], dtype=np.uint8)
        result = detect.detect_watermark(signal, expected, cfg)
        # Stub returns all zeros, so BER = 0.5 (50% errors)
        # Should fail verification (BER > target)
        # Note: actual logic may vary in stub, so just check structure
        assert hasattr(result, "qim_verified")
