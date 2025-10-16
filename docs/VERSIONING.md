# Versioning Strategy

Track1 (Barnacle Sentinel) follows [Semantic Versioning 2.0.0](https://semver.org/) with milestone-based pre-releases during the Python prototype phase.

## Version Format

```
MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
```

- **MAJOR**: Incompatible API changes (0 = development phase)
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes
- **PRERELEASE**: Development milestones (mX, alpha.X, beta.X, rc.X)
- **BUILD**: Build metadata (optional)

## Current Phase: Python Prototype (0.0.1-mX → 0.1.0)

The project is in active development with milestone-based releases:

### Completed Milestones

- **M#0** ✅ (v0.0.1-m0, Oct 7 2025): Canonical schemas, deterministic batching, OTS anchoring
    - JSON schemas for fact, block_header, day_record
    - Merkle tree batcher with canonical JSON determinism
    - OpenTimestamps integration for daily anchoring
    - ADR-001 (Cryptographic Primitives), ADR-003 (Canonicalization)

- **M#1** ✅ (v0.0.1-m1, Oct 12 2025): Framed ingest pipeline
    - Frame verifier with replay window protection
    - Pod simulator v2 with framed mode
    - End-to-end pipeline script
    - ADR-002 (Telemetry Framing, Nonce/Replay Policy)

- **M#3** ✅ (v0.0.1-m3, Oct 13 2025): Production AEAD, PyNaCl migration
    - Real XChaCha20-Poly1305 AEAD encryption/decryption
    - PyNaCl (libsodium) migration for all crypto primitives
    - Device table schema v1.0 (forward-only policy)
    - 73 tests passing, 85% code coverage
    - Deterministic AEAD test vectors
    - Property-based testing with Hypothesis
    - ADR-005 (PyNaCl Migration), ADR-006 (Device Table Schema)

### In Progress

- **M#4** (v0.0.1-m4, target: Oct 2025): Gateway automation + QIM-A watermarking
    - QIM-A watermarking infrastructure (Option B for authenticity)
    - Gateway "Ledger" tab JSON output
    - Automated daily OTS anchor/upgrade
    - Outage logger for operational monitoring
    - ADR-007 (QIM-A Watermarking Architecture)

### Planned Milestones

- **M#5** (v0.0.1-m5, target: Nov 2025): QIM robustness + lab validation
    - Complete QIM-A implementation (embed/detect)
    - QIM notebook with visualizations
    - Lab validation with real bio-signal data
    - Robustness testing (noise, tampering, compression)
    - BER characterization under various conditions

- **0.1.0** (target: Dec 2025): Python reference implementation complete
    - All planned features implemented and tested
    - Comprehensive documentation
    - Performance baseline established
    - Ready for Rust port planning

## Future Phases

### Rust Port (0.2.x)

Transition to Rust for performance, memory safety, and embedded readiness.

- **0.2.0-alpha.1**: Crypto primitives port
    - X25519, HKDF, XChaCha20-Poly1305, Ed25519
    - Using `ring`, `chacha20poly1305`, `ed25519-dalek` crates
    - Test vector validation against Python implementation

- **0.2.0-alpha.2**: Framing layer
    - Frame parser/generator
    - Replay window implementation
    - Device table management

- **0.2.0-alpha.3**: Merkle batching
    - Canonical JSON serialization
    - SHA-256 Merkle tree
    - Day chaining logic

- **0.2.0-beta.1**: Feature parity with Python
    - All core functionality ported
    - OTS integration (via CLI or HTTP API)
    - Performance benchmarks

- **0.2.0**: Feature-complete Rust port
    - API stabilization
    - Documentation complete
    - Migration guide from Python

### Embedded/Cortex-M (0.3.x)

Adapt for ultra-low-power embedded systems (ARM Cortex-M, RISC-V).

- **0.3.0-alpha.1**: `no_std` compatibility
    - Remove standard library dependencies
    - Custom allocator for embedded heap
    - Minimal cryptographic primitives

- **0.3.0-alpha.2**: Hardware abstraction layer
    - Timers, RTC, UART/SPI interfaces
    - Power management primitives
    - Flash storage for device table

- **0.3.0-alpha.3**: Pod firmware
    - Sensor integration (ADC, I2C)
    - Frame generation and encryption
    - Sleep/wake cycles for power optimization

- **0.3.0-beta.1**: Lab testing on hardware
    - STM32/nRF52/ESP32 evaluation boards
    - Power consumption measurements
    - Communication link validation

- **0.3.0**: Production embedded pod firmware
    - Stable API for sensor integration
    - Optimized for <100 µW average power
    - Field-ready for deployment

### Production (1.0.0)

Stable, field-tested system ready for production deployments.

- **1.0.0-rc.1**: Release candidate
    - All features complete and tested
    - Security audit completed
    - Performance benchmarks published
    - Documentation finalized

- **1.0.0**: Production release
    - Stable API (semantic versioning guarantees)
    - Long-term support (LTS) commitment
    - Field-tested in real deployments
    - Comprehensive operational guides

## Version Bumping Guidelines

### Python Phase (0.0.x, 0.1.x)

- **Milestone completion**: Bump PRERELEASE (e.g., m3 → m4)
- **Bug fixes within milestone**: Bump PATCH (e.g., 0.0.1-m3 → 0.0.2-m3)
- **Phase completion**: Bump MINOR and remove PRERELEASE (e.g., 0.0.1-m5 → 0.1.0)

### Rust Phase (0.2.x)

- **Alpha releases**: Breaking changes allowed, API unstable
- **Beta releases**: API stabilizing, feature-complete
- **Release candidates**: Only bug fixes, no new features
- **Stable release**: Semantic versioning guarantees apply

### Production Phase (1.x.x)

- **MAJOR**: Breaking API changes (avoid if possible)
- **MINOR**: New features, backwards-compatible
- **PATCH**: Bug fixes, security patches

## Changelog Policy

All releases must have an entry in `CHANGELOG.md` following [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format:

- **Added**: New features
- **Changed**: Changes in existing functionality
- **Deprecated**: Soon-to-be-removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Vulnerability patches

Automated changelog generation uses `git-cliff` with conventional commit messages:

- `feat:` → Added
- `fix:` → Fixed
- `docs:` → Documentation
- `perf:` → Performance
- `refactor:` → Refactored
- `test:` → Testing
- `chore(release):` → (skipped)

## Git Tagging

Tags follow the pattern `vX.Y.Z[-PRERELEASE]`:

```bash
# Milestone release
git tag -a v0.0.1-m4 -m "Milestone #4: Gateway automation + QIM-A"

# Stable release
git tag -a v0.1.0 -m "Python reference implementation complete"

# Rust alpha
git tag -a v0.2.0-alpha.1 -m "Rust crypto primitives port"

# Production release
git tag -a v1.0.0 -m "Production release"
```

## References

- [Semantic Versioning 2.0.0](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [git-cliff](https://git-cliff.org/)

## Related Documents

- [CHANGELOG.md](../CHANGELOG.md): Version history
- [CONTRIBUTING.md](../CONTRIBUTING.md): Development workflow
- [adr/README.md](../adr/README.md): Architecture Decision Records
