# Makefile for Track1 — Ultra-Low-Power, Verifiable Telemetry
# Forward-only development (v1.0)

SHELL := /bin/bash
.SHELLFLAGS := -c
.ONESHELL:

# Configuration (can be overridden)
SITE ?= an-001
DATE ?= 2025-10-07
DEVICE ?= pod-003
COUNT ?= 10
OUT_DIR ?= out/site_demo

# Targets
.PHONY: help install run test test-verbose test-cov clean tag lint format lint-fix dev-setup gen-vectors sec-scan bench build-native e2e pipeline-quick sha-verify ots-verify-strict test-one

help: ## Show this help message
	@echo "Track1 Make Targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	@echo "[make] Installing dependencies..."
	pip install -r requirements.txt
	@echo "[make] ✓ Dependencies installed"

dev-setup: ## Install development dependencies (includes linting tools)
	@echo "[make] Installing development dependencies..."
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	@echo "[make] ✓ Development environment ready"

run: ## Run end-to-end pipeline (framed ingest with XChaCha20-Poly1305)
	@echo "[make] Running end-to-end pipeline via tox..."
	tox -e pipeline && echo "[make] ✓ Pipeline completed successfully" || (echo "[make] ✗ Pipeline failed" && exit 1)

gen-vectors: ## Generate deterministic AEAD test vectors
	@echo "[make] Generating deterministic AEAD vectors..."
	python scripts/dev/gen_aead_vector.py
	@echo "[make] ✓ Vectors generated"

test: ## Run all tests with pytest
	@echo "[make] Running tests..."
	pytest -q
	@echo "[make] ✓ All tests passed"

# Run all tests unfiltered (clear any addopts in pyproject)
.PHONY: test-all
test-all: ## Run all tests (disable config filters)
	@echo "[make] Running all tests (no filters)..."
	pytest -o addopts='' -q
	@echo "[make] ✓ All tests passed"

# OTS-focused test suites
.PHONY: test-ots-fast test-ots-real

test-ots-fast: ## Run OTS tests (deterministic, no real ots invocation)
	@echo "[make] Running OTS fast tests (no real ots)..."
	pytest -o addopts='' -q \
	  tests/unit/test_ots_anchor.py \
	  tests/integration/test_verify_cli_ots.py \
	  tests/integration/test_verify_cli_main.py
	@echo "[make] ✓ OTS fast tests passed"

test-ots-real: ## Run real OTS integration tests (requires RUN_REAL_OTS=1 and 'ots' installed)
	@echo "[make] Running real OTS integration tests..."
	@if [ "$$RUN_REAL_OTS" != "1" ]; then \
		echo "[WARN] RUN_REAL_OTS=1 not set; skipping real OTS tests."; \
		exit 0; \
	fi
	@if ! command -v ots >/dev/null 2>&1; then \
		echo "[ERROR] 'ots' binary not found in PATH"; \
		exit 1; \
	fi
	pytest -o addopts='' -m real_ots -q tests/integration/test_ots_real.py
	@echo "[make] ✓ Real OTS tests completed"

test-verbose: ## Run tests with verbose output
	@echo "[make] Running tests (verbose)..."
	pytest -v

# Tox-backed shortcuts
.PHONY: tox-all tox-test tox-lint tox-type tox-readme tox-precommit tox-security tox-cov

tox-all: ## Run all default tox environments (parallel if possible)
	tox -p auto

tox-test: ## Run tests on supported Pythons via tox (py312, py313, py314)
	tox -p auto -e py312,py313,py314

tox-lint: ## Run linting via tox
	tox -e lint

tox-type: ## Run mypy type-checks via tox
	tox -e type

tox-readme: ## Run README/ADR checks via tox (mdformat, ADR index)
	tox -e readme

tox-precommit: ## Run all pre-commit hooks via tox
	tox -e precommit

tox-security: ## Run security scans via tox (bandit + pip-audit)
	tox -e security

tox-cov: ## Generate coverage HTML/XML via tox coverage env
	tox -e coverage

clean: ## Remove build artifacts and output directories
	@echo "[make] Cleaning build artifacts..."
	rm -rf out/
	rm -rf __pycache__
	rm -rf scripts/**/__pycache__
	rm -rf .pytest_cache
	rm -rf .hypothesis
	rm -rf htmlcov/
	rm -rf .coverage
	rm -f src/*.aux src/*.log src/*.out src/*.toc src/*.bbl src/*.blg
	@echo "[make] ✓ Cleaned"

clean-all: clean ## Remove all build artifacts including .ruff_cache
	@echo "[make] Deep cleaning..."
	rm -rf .ruff_cache
	rm -rf .mypy_cache
	@echo "[make] ✓ Deep clean complete"

tag: ## Create and push git tag: make tag TAG=vX.Y.Z
	@if [ -z "$(TAG)" ]; then \
		echo "[ERROR] Usage: make tag TAG=v1.0.0"; \
		exit 1; \
	fi
	@echo "[make] Creating and pushing tag: $(TAG)"
	git tag -a $(TAG) -m "Release $(TAG)"
	git push origin $(TAG)
	@echo "[make] ✓ Tag $(TAG) created and pushed"

lint: ## Run basic Python linting (if ruff/black available)
	@echo "[make] Running linting..."
	@if command -v ruff >/dev/null 2>&1; then \
		ruff check scripts/; \
	else \
		echo "[make] ruff not installed, skipping. Install with: pip install ruff"; \
	fi
	@if command -v black >/dev/null 2>&1; then \
		black --check scripts/; \
	else \
		echo "[make] black not installed, skipping. Install with: pip install black"; \
	fi

format: ## Auto-format code with black
	@echo "[make] Auto-formatting code..."
	@if command -v black >/dev/null 2>&1; then \
		black scripts/; \
	else \
		echo "[ERROR] black not installed. Install with: pip install black"; \
		exit 1; \
	fi
	@echo "[make] ✓ Code formatted"

lint-fix: ## Run ruff with auto-fix
	@echo "[make] Running ruff with auto-fix..."
	@if command -v ruff >/dev/null 2>&1; then \
		ruff check scripts/ --fix; \
		echo "[make] ✓ Linting issues fixed"; \
	else \
		echo "[ERROR] ruff not installed. Install with: pip install ruff"; \
		exit 1; \
	fi

check: ## Run linting, typing, and README checks (tox)
	tox -e lint,type,readme
	@echo "[make] ✓ All checks passed"

ci: ## Run full CI checks locally (tox)
	tox -p auto
	@echo "[make] ✓ CI checks passed"

sec-scan: ## Run security scans (tox)
	$(MAKE) tox-security
	@echo "[make] ✓ Security scans completed"

bench: ## Run pytest-benchmark suite and save baseline to out/benchmarks/
	@echo "[make] Running benchmarks via tox..."
	mkdir -p out/benchmarks
	tox -e bench || (echo "[make] ✗ Benchmarks failed" && exit 1)
	@cp .benchmarks/baseline.json out/benchmarks/baseline.json >/dev/null 2>&1 || true
	@echo "[make] ✓ Benchmarks completed and baseline saved to out/benchmarks/baseline.json"

.PHONY: watch
watch: ## Watch for file changes and re-run tests (requires pytest-watch)
	@echo "[make] Watching for changes (Ctrl+C to stop)..."
	@if command -v ptw >/dev/null 2>&1; then \
		ptw scripts/ --; \
	else \
		echo "[ERROR] pytest-watch not installed. Install with: pip install pytest-watch"; \
		exit 1; \
	fi

.PHONY: e2e
e2e: ## Run full end-to-end: pipeline → sha → ots (non-strict by default)
	@echo "[make] Running e2e via tox (non-strict)..."
	STRICT_VERIFY=$${STRICT_VERIFY:-0} STRICT_SHA=$${STRICT_SHA:-1} RUN_BITCOIND=$${RUN_BITCOIND:-1} SQUASH_BAK=$${SQUASH_BAK:-1} OUT_DIR=$(OUT_DIR)/day tox -e e2e
	@echo "[make] ✓ e2e completed"

.PHONY: pipeline-quick
pipeline-quick: ## Run pipeline only via tox
	@echo "[make] Running pipeline via tox..."
	tox -e pipeline
	@echo "[make] ✓ Pipeline done"

.PHONY: sha-verify
sha-verify: ## Run SHA verification via tox (STRICT_SHA=1 to enforce JSON declared hashes)
	@echo "[make] Running SHA verification via tox..."
	STRICT_SHA=$${STRICT_SHA:-0} OUT_DIR=$(OUT_DIR)/day tox -e sha
	@echo "[make] ✓ SHA verify done"

.PHONY: ots-verify-strict
ots-verify-strict: ## Run OTS verification in strict mode (requires bitcoind)
	@echo "[make] Running OTS verification (strict)..."
	STRICT_VERIFY=1 RUN_BITCOIND=$${RUN_BITCOIND:-1} OUT_DIR=$(OUT_DIR)/day tox -e ots
	@echo "[make] ✓ OTS strict verify done"

.PHONY: test-one
test-one: ## Run a single test or selection quickly: make test-one TEST="tests/unit/crypto/test_hkdf.py::TestHKDF::test_deterministic_derivation -q"
	@echo "[make] Running one-shot test via tox..."
	@if [ -z "$$TEST" ]; then \
		echo "[ERROR] Provide TEST=... (e.g., TEST=tests/unit/crypto/test_hkdf.py::TestHKDF::test_deterministic_derivation)"; \
		exit 1; \
	fi
	tox -e one -- $$TEST
	@echo "[make] ✓ One-shot test done"

.PHONY: ots-verify
ots-verify: ## Verify OTS proofs locally (uses headers-only bitcoind; STRICT_VERIFY=0 by default)
	@echo "[make] Verifying OTS proofs via tox..."
	STRICT_VERIFY=$${STRICT_VERIFY:0} TIMEOUT_SECS=$${TIMEOUT_SECS:-600} OUT_DIR=$(OUT_DIR)/day tox -e ots
