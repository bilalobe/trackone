"""
QIM-A (Quantization Index Modulation) Watermarking Module

This module implements QIM-A watermarking for biometric time-series data
authentication. QIM provides authenticity verification but is NOT a
cryptographic security mechanism.

Key Components:
- config.py: Operating parameters (Δ/σ, block_sec, filter specs)
- embed.py: Scalar QIM embedding with band-pass filtering
- detect.py: Block-wise detection with lattice decision logic

References:
- ADR-007: QIM-A Watermarking Architecture
- Chen & Wornell (2001): Quantization Index Modulation for Digital Watermarking
- Bio-signal frequency band: ~1/200 to 1/10 Hz (typical for physiological signals)

Trust Boundary:
- QIM operates in the authenticity layer, separate from cryptographic primitives
- Used for detecting tampering/corruption in time-series data
- NOT a replacement for AEAD encryption (XChaCha20-Poly1305)

Version: M#4+ (0.0.1-m4)
Status: Development (stubs)
"""

from __future__ import annotations

__version__ = "0.0.1-m4"
__all__ = ["config", "embed", "detect"]
