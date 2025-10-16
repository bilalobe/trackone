#!/usr/bin/env python3
"""
Test suite for QIM-A embedding module.

Tests cover:
- Band-pass filtering function signatures
- Delta computation from signal statistics
- Scalar QIM embedding (stub behavior)
- Configuration validation

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
# Note: Dynamic import pattern used here because QIM modules are not part of an installed package.
#       This is acceptable for M#4 stubs. In M#5, consider refactoring to use proper package structure.
QIM_DIR = Path(__file__).parent.parent / "qim"

config_spec = importlib.util.spec_from_file_location(
    "qim_config", str(QIM_DIR / "config.py")
)
assert config_spec and config_spec.loader
config = importlib.util.module_from_spec(config_spec)
sys.modules["qim_config"] = config
config_spec.loader.exec_module(config)  # type: ignore

embed_spec = importlib.util.spec_from_file_location(
    "qim_embed", str(QIM_DIR / "embed.py")
)
assert embed_spec and embed_spec.loader
embed = importlib.util.module_from_spec(embed_spec)
sys.modules["qim_embed"] = embed
embed_spec.loader.exec_module(embed)  # type: ignore


class TestBandpassFilter:
    """Test band-pass filtering function."""

    def test_filter_returns_same_shape(self) -> None:
        """Test that filter returns array with same shape as input."""
        signal = np.random.randn(100)
        filtered = embed.bandpass_filter(
            signal, fs=2.5, low_hz=0.005, high_hz=0.1, order=3
        )
        assert filtered.shape == signal.shape

    def test_filter_validates_cutoff_frequencies(self) -> None:
        """Test that filter validates low_hz < high_hz."""
        signal = np.random.randn(100)
        with pytest.raises(ValueError, match="low_hz .* must be < high_hz"):
            embed.bandpass_filter(signal, fs=2.5, low_hz=0.1, high_hz=0.005, order=3)

    def test_filter_validates_nyquist(self) -> None:
        """Test that filter validates high_hz < Nyquist frequency."""
        signal = np.random.randn(100)
        with pytest.raises(ValueError, match="high_hz .* must be < Nyquist"):
            embed.bandpass_filter(signal, fs=2.5, low_hz=0.005, high_hz=2.0, order=3)


class TestComputeDelta:
    """Test quantization step size computation."""

    def test_compute_delta_positive(self) -> None:
        """Test that delta is positive for non-zero signal."""
        signal = np.random.randn(100)
        delta = embed.compute_delta(signal, delta_sigma=0.01)
        assert delta > 0

    def test_compute_delta_scales_with_sigma(self) -> None:
        """Test that delta scales with signal standard deviation."""
        # Signal with σ ≈ 1.0
        signal1 = np.random.randn(1000)
        delta1 = embed.compute_delta(signal1, delta_sigma=0.01)

        # Signal with σ ≈ 2.0
        signal2 = 2.0 * np.random.randn(1000)
        delta2 = embed.compute_delta(signal2, delta_sigma=0.01)

        # delta2 should be roughly 2x delta1
        assert 1.5 < (delta2 / delta1) < 2.5

    def test_compute_delta_empty_signal(self) -> None:
        """Test that empty signal raises ValueError."""
        signal = np.array([], dtype=np.float64)
        with pytest.raises(ValueError, match="must not be empty"):
            embed.compute_delta(signal, delta_sigma=0.01)

    def test_compute_delta_zero_variance(self) -> None:
        """Test that zero-variance signal raises ValueError."""
        signal = np.ones(100, dtype=np.float64)
        with pytest.raises(ValueError, match="zero variance"):
            embed.compute_delta(signal, delta_sigma=0.01)


class TestEmbedQIMScalar:
    """Test scalar QIM embedding (stub behavior)."""

    def test_embed_returns_same_shape(self) -> None:
        """Test that embedding returns array with same shape as input."""
        cfg = config.DEFAULT_CONFIG
        signal = np.random.randn(100)
        bits = np.array([0, 1, 0, 1], dtype=np.uint8)
        watermarked = embed.embed_qim_scalar(signal, bits, cfg)
        assert watermarked.shape == signal.shape

    def test_embed_validates_signal_length(self) -> None:
        """Test that embedding validates signal length vs. bits."""
        cfg = config.DEFAULT_CONFIG
        block_samples = cfg.block_samples
        # Signal too short for 4 bits
        signal = np.random.randn(block_samples * 2)
        bits = np.array([0, 1, 0, 1], dtype=np.uint8)
        with pytest.raises(ValueError, match="Signal too short"):
            embed.embed_qim_scalar(signal, bits, cfg)

    def test_embed_accepts_sufficient_length(self) -> None:
        """Test that embedding succeeds with sufficient signal length."""
        cfg = config.DEFAULT_CONFIG
        block_samples = cfg.block_samples
        # Signal long enough for 4 bits
        signal = np.random.randn(block_samples * 4)
        bits = np.array([0, 1, 0, 1], dtype=np.uint8)
        watermarked = embed.embed_qim_scalar(signal, bits, cfg)
        assert watermarked.shape == signal.shape


class TestEmbedWatermark:
    """Test high-level watermark embedding."""

    def test_embed_watermark_pipeline(self) -> None:
        """Test complete embedding pipeline."""
        cfg = config.DEFAULT_CONFIG
        block_samples = cfg.block_samples
        signal = np.random.randn(block_samples * 4)
        bits = np.array([0, 1, 0, 1], dtype=np.uint8)
        watermarked = embed.embed_watermark(signal, bits, cfg)
        assert watermarked.shape == signal.shape
        assert watermarked.dtype == np.float64


class TestQIMConfig:
    """Test QIM configuration validation."""

    def test_default_config_valid(self) -> None:
        """Test that default config is valid."""
        cfg = config.DEFAULT_CONFIG
        assert cfg.delta_sigma == config.DELTA_SIGMA_DEFAULT
        assert cfg.block_sec == config.BLOCK_SEC_DEFAULT
        assert cfg.fs == config.FS_DEFAULT

    def test_config_validates_delta_sigma(self) -> None:
        """Test delta_sigma range validation."""
        with pytest.raises(ValueError, match="delta_sigma"):
            config.QIMConfig(delta_sigma=-0.01)  # Negative
        with pytest.raises(ValueError, match="delta_sigma"):
            config.QIMConfig(delta_sigma=0.5)  # Too large

    def test_config_validates_block_sec(self) -> None:
        """Test block_sec range validation."""
        with pytest.raises(ValueError, match="block_sec"):
            config.QIMConfig(block_sec=1)  # Too small
        with pytest.raises(ValueError, match="block_sec"):
            config.QIMConfig(block_sec=20)  # Too large

    def test_config_validates_bandpass(self) -> None:
        """Test bandpass frequency validation."""
        with pytest.raises(ValueError, match="bandpass_low.*<.*bandpass_high"):
            config.QIMConfig(bandpass_low=0.2, bandpass_high=0.1)

    def test_config_block_samples_property(self) -> None:
        """Test block_samples computed property."""
        cfg = config.QIMConfig(block_sec=5, fs=2.5)
        assert cfg.block_samples == 12  # 5 * 2.5 = 12.5 → 12

    def test_config_nyquist_property(self) -> None:
        """Test nyquist_freq computed property."""
        cfg = config.QIMConfig(fs=2.5)
        assert cfg.nyquist_freq == 1.25  # 2.5 / 2
