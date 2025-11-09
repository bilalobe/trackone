# ADR-008: Milestone M#4 Completion and OTS Verification Workflow

**Status:** Accepted
**Date:** 2025-10-22
**Milestone:** M#4

## Context

Milestone M#4 represents the completion of the core OpenTimestamps (OTS) verification workflow and comprehensive test coverage for the Track1 gateway pipeline. Building on ADR-003 (daily OTS anchoring) and ADR-007 (headers-only verification policy), M#4 demonstrates end-to-end production verification against the Bitcoin blockchain.

Prior milestones established:

- **M#1**: Cryptographic primitives and framing (X25519, HKDF, XChaCha20-Poly1305)
- **M#2**: Telemetry framing and replay protection
- **M#3**: PyNaCl migration, device table schema, real AEAD encryption
- **M#4**: OTS proof verification finalized with Bitcoin anchoring confirmed

## Decision

### 1. Production OTS Proof Verification

We have successfully anchored a production day blob to the Bitcoin blockchain and verified the complete workflow:

**Anchored Artifact:**

- File: `out/site_demo/day/2025-10-07.bin`
- SHA256: `4778cddcf437f0b0ac8cd62fef3b89909bd6f4a8fd9590ac6e4a70e4fded5f60`
- OTS Proof: `out/site_demo/day/2025-10-07.bin.ots`

**Bitcoin Attestation:**

- Block Height: **919384**
- Block Hash: `00000000000000000000b36d7b88a2e781f65619746bc238d4cfde8555f13733`
- Block Time: October 16, 2025 (IST)
- Merkle Root: `166c8fe05f6071d8a29145c4e52c039159c699f3278c45d1c3107503b59c8047`

**Verification Metadata:**

- Location: `proofs/2025-10-07.ots.meta.json`
- Contains: Block height, hash, merkleroot, artifact SHA256, timestamp
- Purpose: Enables reproducible verification by third parties

### 2. Enhanced verify_cli.py

The verification CLI now handles both test and production scenarios:

**Test Environment Support:**

- Recognizes `OTS_PROOF_PLACEHOLDER` text files in test suites
- Allows test pipelines to run without OTS binary dependency
- Returns success (exit code 0) for placeholder proofs in test context

**Production Verification:**

- Invokes `ots verify` for real binary OTS proofs
- Validates against local Bitcoin Core node (headers-only mode per ADR-007)
- Returns appropriate exit codes:
  - 0: Success (root matches and OTS verified)
  - 1: Block header not found or invalid
  - 2: Merkle root mismatch
  - 3: OTS proof file not found
  - 4: OTS proof verification failed (e.g., pending or incomplete)

**Verification Steps:**

1. Recompute Merkle root from canonical fact files
1. Compare against authoritative block header
1. Verify OTS proof anchors the day.bin blob
1. Confirm Bitcoin block header contains the attestation

### 3. Git LFS for OTS Proofs

To prevent repository bloat from binary OTS proof files:

**Configuration:** `.gitattributes`

```
*.ots filter=lfs diff=lfs merge=lfs -text
```

**Rationale:**

- OTS proofs are binary files (typically 1-10 KB)
- Accumulate daily; would grow the repository over time
- Git LFS stores large files externally while keeping repo lightweight
- Proof metadata in `.ots.meta.json` provides verification details without LFS dependency

### 4. Comprehensive Test Coverage Expansion

M#4 dramatically expanded test coverage to ensure production readiness:

**Test Suite Growth:**

- Tests: 73 → 151 (107% increase)
- Coverage: 68% → 85% (17 percentage points)
- New test modules: 3 (`test_ots_anchor.py`, `test_pod_sim.py`, `test_edge_cases.py`)

**Coverage by Module:**

| Module              | M#3 Coverage | M#4 Coverage | Improvement |
| ------------------- | ------------ | ------------ | ----------- |
| `ots_anchor.py`     | 0%           | 95%          | +95%        |
| `pod_sim.py`        | 26%          | 81%          | +55%        |
| `crypto_utils.py`   | 97%          | 97%          | Stable      |
| `merkle_batcher.py` | 90%          | 90%          | Stable      |
| `frame_verifier.py` | 79%          | 82%          | +3%         |
| `verify_cli.py`     | 75%          | 78%          | +3%         |

**New Test Coverage:**

*test_ots_anchor.py (10 tests):*

- OTS stamping with real `ots` binary
- Fallback to placeholder when OTS unavailable
- Error handling (OSError, PermissionError, CalledProcessError)
- CLI argument parsing and file path handling
- Real OTS integration tests (marked `@pytest.mark.real_ots`)

*test_pod_sim.py (31 tests):*

- Fact generation and TLV encoding
- Nonce construction (salt8 + counter)
- Device table schema validation
- CLI workflow with multiple pods
- Timestamp format validation (ISO 8601)
- Property-based tests with Hypothesis

*test_edge_cases.py (27 tests):*

- Merkle root computation edge cases (empty, single, odd count)
- Canonical JSON determinism
- Schema validation for blocks and day records
- Day chaining logic
- Error paths in verify_cli

**Test Infrastructure:**

- Centralized fixtures in `conftest.py`
- Parametrized tests for comprehensive coverage
- Shared gateway module loading fixture
- Sample workspace and device table fixtures

### 5. Real OTS Integration Tests

Added optional slow tests that exercise real OTS client:

**Environment:**

- Tests marked with `@pytest.mark.real_ots` and `@pytest.mark.slow`
- Enabled via `RUN_REAL_OTS=1` environment variable
- Requires `ots` binary on PATH or via `OTS_BIN` variable

**Test Coverage:**

- `test_real_ots_stamp_writes_non_placeholder`: Verifies real OTS stamping produces binary proof (not placeholder)
- `test_verify_cli_with_real_ots`: End-to-end stamping workflow verification

**Important Note:**
Real OTS tests do NOT attempt immediate verification because:

- Freshly stamped OTS proofs are "pending" (incomplete)
- Proofs require Bitcoin block confirmations (hours to days)
- Tests verify that stamping works and creates valid proof structure
- Actual verification must wait for blockchain confirmation

**Running Real OTS Tests:**

```bash
RUN_REAL_OTS=1 make test-ots-real
```

### 6. Documentation Updates

**LaTeX Report (`src/main.tex`):**

- Results section includes M#4 verification details
- Documents Bitcoin block 919384 attestation
- Includes proof metadata and verification commands

**README.md:**

- "What's New in M#4" section
- OTS verification instructions with Bitcoin Core
- Test coverage table updated
- Proof metadata reference

**CHANGELOG.md:**

- Detailed M#4 release notes (v0.0.1-m4)
- All new features, changes, and fixes documented
- Test coverage improvements highlighted

## Consequences

### Positive

**Production Readiness:**

- Demonstrated end-to-end workflow with real Bitcoin anchoring
- Proof verifiable by any third party with Bitcoin Core node
- No dependency on centralized services for verification

**Comprehensive Testing:**

- 85% coverage across gateway and pod_sim modules
- 151 tests covering normal paths, edge cases, and error handling
- Test infrastructure supports both mock and real OTS workflows

**Developer Experience:**

- Tests run fast by default (placeholders)
- Optional slow tests for real OTS validation
- Clear separation between CI and production verification

**Auditability:**

- Proof metadata enables reproducible verification
- Git LFS keeps repository size manageable
- Documentation provides clear verification instructions

### Negative / Trade-offs

**OTS Timing Complexity:**

- Developers must understand pending vs. confirmed proofs
- Cannot immediately verify freshly stamped proofs
- Test suite cannot fully verify real OTS workflow without waiting

**Infrastructure Requirements:**

- Production verification requires Bitcoin Core node
- Headers-only mode still needs ~10-20 minutes initial sync
- CI caching required for reasonable performance

**Git LFS Dependency:**

- Teams must have Git LFS installed
- Additional configuration for clones
- Potential for LFS storage costs (though proofs are small)

## Implementation Details

### Verification Workflow

**Local Verification:**

```bash
# Verify OTS proof
ots verify out/site_demo/day/2025-10-07.bin.ots

# Confirm Bitcoin block contains attestation
bitcoin-cli getblockheader $(bitcoin-cli getblockhash 919384) | jq -r .merkleroot
# 166c8fe05f6071d8a29145c4e52c039159c699f3278c45d1c3107503b59c8047

# Run end-to-end verifier
python scripts/gateway/verify_cli.py --root out/site_demo --facts out/site_demo/facts
# OK: root matches and OTS verified
```

**CI Workflow:**

- Tests use placeholder proofs by default (fast)
- Optional real OTS tests run when `RUN_REAL_OTS=1`
- Production verification runs separately with Bitcoin Core cache

### Test Organization

**Quick Tests (default):**

```bash
make test        # Core tests (~1s)
make test-all    # All tests with placeholders (~1-2s)
```

**Real OTS Tests:**

```bash
RUN_REAL_OTS=1 make test-ots-real  # Requires ots binary (~5s)
```

**Coverage Reports:**

```bash
make coverage    # Generate HTML coverage report
```

## Alternatives Considered

**Immediate OTS Verification in Tests:**

- Rejected: Cannot verify pending proofs without waiting hours/days
- Current approach: Test stamping process, defer verification

**Full Bitcoin Node in CI:**

- Rejected: Too heavy (ADR-007)
- Current approach: Headers-only with caching

**No Git LFS:**

- Rejected: Would bloat repository over time
- Current approach: LFS for binary proofs, JSON metadata in repo

**Third-party Block Explorers Only:**

- Rejected: Weakens trust model (ADR-007)
- Current approach: Local Bitcoin Core verification

## Testing & Validation

**Acceptance Criteria (All Met):**

- ✅ Production day blob successfully anchored to Bitcoin block 919384
- ✅ Proof metadata captured and stored
- ✅ verify_cli.py successfully validates proof against local Bitcoin Core
- ✅ Test suite expanded to 151 tests with 85% coverage
- ✅ All modules have >75% coverage
- ✅ Git LFS configured for .ots files
- ✅ Documentation updated (README, CHANGELOG, LaTeX report)
- ✅ Real OTS integration tests pass when enabled
- ✅ Test suite passes with placeholder proofs (fast CI)

**Test Results:**

- 158 total tests passing (151 main + 2 real OTS + 5 other)
- 2 tests skipped (require specific environment)
- 0 failures
- Test execution time: ~1.1s (placeholders), ~5.7s (real OTS)

## Future Work

**M#5 Candidates:**

- Automated daily OTS anchor/upgrade workflow
- Gateway "Ledger" tab with JSON output
- Outage logger for monitoring
- Multi-day batch verification
- OTS proof upgrade automation (weekly cron)
- Enhanced proof metadata (git commit, build info)

## References

- ADR-003: Canonicalization, Merkle Policy, and Daily OTS Anchoring
- ADR-007: OTS Verification in CI and Bitcoin Headers Policy
- OpenTimestamps: https://opentimestamps.org/
- Bitcoin Block 919384: https://blockstream.info/block/00000000000000000000b36d7b88a2e781f65619746bc238d4cfde8555f13733
- Proof Metadata: `proofs/2025-10-07.ots.meta.json`
