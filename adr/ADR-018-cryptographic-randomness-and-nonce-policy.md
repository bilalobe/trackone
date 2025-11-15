# ADR-018: Cryptographic randomness and nonce policy

- Status: Accepted
- Date: 2025-11-09
- Related: `ADR-001-primitives-x25519-hkdf-xchacha.md`, `ADR-006-forward-only-schema-and-salt8.md`, `ADR-005-pynacl-migration.md`, `ADR-011-benchmarking-strategy.md`, `ADR-017-rust-core-and-pyo3-integration.md`

## Context

Project components produce keys, salts, and AEAD nonces for telemetry framing, OTS anchoring, and data protection. Non-CSPRNG APIs (e.g., `.rand()`, `random`, `numpy.random`) are deterministic and predictable, leading to nonce reuse and weak salts. We need a uniform, reviewable policy across Python (primary) and Rust (core via `pyo3`), on Linux.

## Decision

- Only OS-backed CSPRNGs are allowed for cryptographic randomness.
  - Python: `secrets` and `os.urandom`.
  - Rust: `getrandom`/`rand_core::OsRng`; libsodium `randombytes_*` where applicable.
- Prohibited sources in production: `random`, `numpy.random`, time-seeded PRNGs, LCG/Mersenne Twister, ad-hoc mixers.
- AEAD nonce policy:
  - AES-GCM: 12-byte nonces from CSPRNG; must be unique per key.
  - ChaCha20-Poly1305: 12-byte nonces from CSPRNG; must be unique per key.
  - XChaCha20-Poly1305: 24-byte nonces from CSPRNG; uniqueness strongly recommended; random 24 bytes acceptable.
- Salt policy:
  - Default: 16–32 random bytes from CSPRNG (store as needed).
  - Physical entropy (e.g., Physarum) may be hashed into salts for research, with domain separation and documented pipelines; do not feed raw noise directly.
- Determinism in tests:
  - Use explicit test stubs/fakes; never seed CSPRNGs. No deterministic seeding in production.
- Reseeding:
  - Rely on OS CSPRNG; do not implement custom DRBGs or entropy daemons in process.
- Sizes under PQ considerations:
  - Symmetric keys and hashes remain strong with doubled sizes; continue AES-256, SHA-256/512, XChaCha20-Poly1305.

## Rationale

- `.rand()`-style APIs are predictable and state-recoverable; low bits often biased.
- OS CSPRNGs provide forward/backward secrecy and high entropy.
- Clear nonce rules prevent catastrophic AEAD failures from reuse.
- Keeps parity across Python and Rust while aligning with `ADR-001` primitives and `ADR-006` salt usage.

## Consequences

- Minor refactors to replace non-CSPRNG calls.
- Introduces a central helper to avoid misuse and reduce duplication.
- Tests must adopt fakes for determinism.

## Migration plan

- Replace all uses of `random`, `numpy.random`, and ad-hoc RNGs in crypto contexts.
- Centralize randomness via `crypto_rng.py` (Python) and `OsRng` (Rust core).
- Workspace search (case insensitive):
  - `\brandom\.(rand|randint|choice|random|seed)\b`
  - `\bnumpy\.random\b|\bnp\.random\b`
  - `\burandom\(` (ensure wrapped in helper)
  - `\bnonce\b|\bsalt\b` (audit generation sites)
- Add pre-commit or Bandit rule to flag prohibited APIs.

## Security notes

- Nonce reuse with AES-GCM/ChaCha20-Poly1305 is catastrophic; enforce uniqueness per key.
- Do not log or expose key material; salts may be stored but must not be derived from secrets.
- Physical entropy pipelines must hash inputs and bind context metadata.

## References

- NIST SP 800-90A Rev.1; RFC 5116 AEAD; libsodium `randombytes`; NaCl/`PyNaCl` docs; discussion on `.rand()` predictability.

## Appendix: Python helper

Explanation: Minimal, testable helpers for CSPRNG bytes, salts, and nonces with explicit sizes and types. Provides an optional test fake for deterministic unit tests. Use everywhere instead of ad-hoc randomness.

```python
# python
# File: `crypto_rng.py`
# Purpose: Centralized cryptographic randomness, salts, and nonces (Python).
# Policy: Only OS-backed CSPRNG; never use `random`/`numpy.random` for crypto.

from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, ContextManager, Optional
from contextlib import contextmanager
from secrets import token_bytes
import os
from unittest.mock import patch

# Sizes
SALT16 = 16
SALT32 = 32
NONCE_GCM_12 = 12  # AES-GCM / ChaCha20-Poly1305
NONCE_XCHACHA20_24 = 24  # XChaCha20-Poly1305


def rand_bytes(n: int) -> bytes:
    """
    Returns 'n' cryptographically secure random bytes from the OS CSPRNG.
    """
    if not isinstance(n, int) or n <= 0:
        raise ValueError("n must be a positive int")
    # secrets.token_bytes delegates to os.urandom and may use stronger sources
    return token_bytes(n)


def salt16() -> bytes:
    """Returns a 16-byte salt."""
    return rand_bytes(SALT16)


def salt32() -> bytes:
    """Returns a 32-byte salt."""
    return rand_bytes(SALT32)


def gcm_nonce12() -> bytes:
    """Returns a 12-byte nonce for AES-GCM / ChaCha20-Poly1305 (unique per key)."""
    return rand_bytes(NONCE_GCM_12)


def xchacha_nonce24() -> bytes:
    """Returns a 24-byte nonce for XChaCha20-Poly1305."""
    return rand_bytes(NONCE_XCHACHA20_24)


# Optional: hash physical entropy into a salt (research contexts only).
def salt_from_physical(samples: bytes, context_tag: bytes = b"") -> bytes:
    """
    Hashes physical entropy samples into a 16-byte salt with domain separation.
    'samples' must already be sanitized (no secrets). Use for reproducible pipelines.
    """
    import hashlib

    if not isinstance(samples, (bytes, bytearray)):
        raise ValueError("samples must be bytes")
    h = hashlib.sha256()
    h.update(b"salt:v1:")
    h.update(context_tag or b"")
    h.update(bytes(samples))
    return h.digest()[:SALT16]


# Test-only deterministic fake (never use in production).
@dataclass
class _DeterministicRng:
    buf: bytearray

    def __call__(self, n: int) -> bytes:
        if n > len(self.buf):
            raise RuntimeError("DeterministicRng buffer underrun")
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out


@contextmanager
def use_test_rng(fake_bytes: bytes) -> ContextManager[None]:
    """
    Context manager to temporarily override `secrets.token_bytes` for deterministic tests.

    Example:
        with use_test_rng(b"\xaa"*64):
            assert salt16() == b"\xaa"*16
    """
    if not isinstance(fake_bytes, (bytes, bytearray)):
        raise ValueError("fake_bytes must be bytes")
    rng = _DeterministicRng(bytearray(fake_bytes))
    # Use unittest.mock.patch to avoid modifying global module state directly.
    with patch("secrets.token_bytes", new=rng):
        yield


# Minimal self-test (run manually)
if __name__ == "__main__":  # pragma: no cover
    s16, s32 = salt16(), salt32()
    n12, n24 = gcm_nonce12(), xchacha_nonce24()
    assert len(s16) == 16 and len(s32) == 32
    assert len(n12) == 12 and len(n24) == 24
    with use_test_rng(b"\x00" * 64):
        assert salt16() == b"\x00" * 16
        assert gcm_nonce12() == b"\x00" * 12
    print("crypto_rng OK")
```
