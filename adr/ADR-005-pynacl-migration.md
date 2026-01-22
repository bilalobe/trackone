# ADR-005: Migrate to PyNaCl for All Cryptographic Primitives

**Status**: Accepted (Completed 2025-10-12; updated 2026-01-22)
**Date**: 2025-10-12
**Deciders**: BILAL
**Context**: Evaluate consolidating cryptographic dependencies from `cryptography` + `pynacl` to `pynacl` only.

## Context and Problem Statement

Previously, the project used two cryptographic libraries:

- **`cryptography`**: ChaCha20-Poly1305 (96-bit nonce), X25519, HKDF-SHA256, Ed25519
- **`pynacl`**: XChaCha20-Poly1305 (192-bit nonce) only

This split introduced:

1. **Dependency bloat**: Two libraries for similar primitives
1. **API inconsistency**: Different calling conventions
1. **Maintenance overhead**: Two security update streams

## Decision Drivers

- **Simplicity**: Single dependency for all crypto operations
- **Performance**: libsodium (PyNaCl) is highly optimized
- **Features**: PyNaCl offers additional primitives (sealed boxes, password hashing, etc.)
- **API clarity**: PyNaCl has a cleaner, more Pythonic API
- **Ecosystem**: libsodium is battle-tested and widely deployed

## Decision

**Accepted and Implemented**: Migrate to PyNaCl Only

All cryptographic primitives now use PyNaCl (libsodium bindings):

- X25519: `nacl.public.PrivateKey` / `nacl.public.Box`
- HKDF: `nacl.bindings.crypto_kdf_hkdf_sha256_*`
- ChaCha20-Poly1305: `nacl.bindings.crypto_aead_chacha20poly1305_ietf_*`
- XChaCha20-Poly1305: `nacl.bindings.crypto_aead_xchacha20poly1305_ietf_*`
- Ed25519: `nacl.signing.SigningKey` / `nacl.signing.VerifyKey`

## Implementation Summary (Completed 2025-10-12)

### Files Modified

1. **crypto_utils.py** - Complete rewrite using PyNaCl APIs
1. **frame_verifier.py** - Updated AEAD decryption to use `nacl.bindings`
1. **pod_sim.py** - Updated AEAD encryption to use `nacl.bindings`
1. **gen_aead_vector.py** - Regenerated deterministic test vectors with PyNaCl
1. **test_crypto_impl.py** - Updated to use `nacl.exceptions.CryptoError` / `BadSignatureError`
1. **test_crypto_vectors.py** - Updated AEAD verification to use PyNaCl
1. **pyproject.toml** - `cryptography` removed; `pynacl` is the sole crypto runtime dependency
1. **uv.lock** – lockfile committed for deterministic dependency resolution (CI/Dependabot)

> Note: Historically, this ADR referred to updating `requirements.txt`. As of 2026-01-22, TrackOne uses `pyproject.toml` + `uv.lock` as the authoritative dependency source of truth, and root `requirements*.txt` files were removed to avoid drift.

### Test Vectors

- ✅ Regenerated `toolset/unified/crypto_test_vectors.json` with PyNaCl
- ✅ All deterministic AEAD vectors now use PyNaCl encryption
- ✅ Backward compatibility maintained (same nonce/AAD/plaintext format)

### Exception Handling

- Before: `Exception` (generic)
- After:
  - `nacl.exceptions.CryptoError` for AEAD failures
  - `nacl.exceptions.BadSignatureError` for signature verification failures

## Migration Verification

All tests pass successfully:

```bash
pytest -q
# Expected: 69+ passed, 0 failed
```

Test coverage includes:

- X25519 key exchange and shared secret agreement
- HKDF deterministic derivation and domain separation
- ChaCha20-Poly1305 (96-bit) round-trip and tamper detection
- XChaCha20-Poly1305 (192-bit) round-trip and tamper detection
- Ed25519 signing/verification and tamper detection
- Deterministic AEAD vectors match exactly
- End-to-end framed telemetry pipeline (pod_sim → frame_verifier)

## Consequences

### Positive

- **Single crypto dependency**: Only `pynacl` provides TrackOne cryptographic primitives
- **Deterministic installs**: dependency versions are locked via `uv.lock` and installed through `pyproject.toml` extras in CI/tox
- **Better performance**: libsodium is faster than OpenSSL for these primitives
- **Cleaner API**: Consistent patterns across all crypto operations
- **Future-proof**: Access to modern crypto primitives ready when needed
- **Smaller binary**: One C library (libsodium) vs OpenSSL components
- **Better exceptions**: Specific exception types for different failure modes

### Neutral

- **One-time migration cost**: ~3 hours (completed)
- **Test vectors changed**: Regenerated, documented in git history

### Negative

- None observed; migration successful without issues

## API Comparison

| Primitive         | Before (`cryptography`)                | After (PyNaCl)                                              |
| ----------------- | -------------------------------------- | ----------------------------------------------------------- |
| X25519            | `x25519.X25519PrivateKey.generate()`   | `nacl.public.PrivateKey.generate()`                         |
| HKDF              | `HKDF(algorithm=SHA256)`               | `nacl.bindings.crypto_kdf_hkdf_sha256_*`                    |
| ChaCha20-Poly1305 | `ChaCha20Poly1305(key).encrypt()`      | `nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt()` |
| Ed25519           | `ed25519.Ed25519PrivateKey.generate()` | `nacl.signing.SigningKey.generate()`                        |

PyNaCl API is more explicit and consistent, with all parameters clearly specified.

## References

- [PyNaCl Documentation](https://pynacl.readthedocs.io/)
- [libsodium Documentation](https://doc.libsodium.org/)
- ADR-001: Cryptographic Primitives and Framing (updated to reflect PyNaCl)

## Notes

- PyNaCl's `SecretBox` uses XChaCha20-Poly1305 by default (24-byte nonce)
- For ChaCha20-Poly1305 (12-byte nonce), use `nacl.bindings.crypto_aead_chacha20poly1305_ietf_*`
- Migration preserved all existing nonce/AAD construction logic
- No changes required to frame format or wire protocol
- Dependency management is lockfile-first:
  - Source of truth: `pyproject.toml` (+ committed `uv.lock`)
  - Optional interoperability: `make export-requirements` writes pinned, lock-derived `out/requirements*.txt`
  - This avoids maintaining handwritten requirements files that can drift from the actual package metadata.

## Status

**Migration Complete**: All components migrated, tests passing, documentation updated.
