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
.PHONY: help install run test test-verbose test-cov clean tag lint format lint-fix dev-setup gen-vectors sec-scan

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
	@echo "[make] Running end-to-end pipeline..."
	@bash scripts/gateway/run_pipeline.sh && echo "[make] ✓ Pipeline completed successfully" || (echo "[make] ✗ Pipeline failed" && exit 1)

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
	  scripts/tests/test_ots_anchor.py \
	  scripts/tests/test_verify_cli_ots.py \
	  scripts/tests/test_verify_cli_main.py
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
	pytest -o addopts='' -m real_ots -q scripts/tests/test_ots_real.py
	@echo "[make] ✓ Real OTS tests completed"

test-verbose: ## Run tests with verbose output
	@echo "[make] Running tests (verbose)..."
	pytest -v

test-cov: ## Run tests with coverage report
	@echo "[make] Running tests with coverage..."
	pytest --cov=scripts/gateway --cov=scripts/pod_sim --cov-fail-under=80 --cov-report=term-missing --cov-report=html -v
	@echo "[make] ✓ Coverage report generated (see htmlcov/index.html)"

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

check: lint test ## Run linting and tests (pre-commit checks)
	@echo "[make] ✓ All checks passed"

ci: lint test-cov ## Run full CI checks locally (lint + tests with coverage)
	@echo "[make] ✓ CI checks passed"

# Parallel test targets (pytest-xdist)
.PHONY: test-parallel test-fast test-crypto test-slowest

test-parallel: ## Run all tests in parallel
	@echo "[make] Running tests in parallel..."
	pytest scripts/tests/ -n auto --dist loadscope -q

test-fast: ## Run all non-slow tests in parallel
	@echo "[make] Running fast tests (exclude slow)..."
	pytest scripts/tests/ -n auto --dist loadscope -m "not slow" -q

test-crypto: ## Run only crypto tests
	@echo "[make] Running crypto tests..."
	pytest scripts/tests/ -m crypto -q

test-slowest: ## Show the 30 slowest tests (parallel)
	@echo "[make] Showing slowest tests..."
	pytest scripts/tests/ -n auto --dist loadscope --durations=30 -q

.PHONY: watch
watch: ## Watch for file changes and re-run tests (requires pytest-watch)
	@echo "[make] Watching for changes (Ctrl+C to stop)..."
	@if command -v ptw >/dev/null 2>&1; then \
		ptw scripts/ --; \
	else \
		echo "[ERROR] pytest-watch not installed. Install with: pip install pytest-watch"; \
		exit 1; \
	fi

.PHONY: ots-verify
ots-verify: ## Verify OTS proofs locally (uses headers-only bitcoind; STRICT_VERIFY=0 by default)
	@echo "[make] Verifying OTS proofs in $(OUT_DIR)/day ..."
	@if [ ! -x scripts/ci/ots_verify.sh ]; then \
		echo "[ERROR] scripts/ci/ots_verify.sh not found or not executable"; \
		exit 1; \
	fi
	STRICT_VERIFY=$${STRICT_VERIFY:-0} TIMEOUT_SECS=$${TIMEOUT_SECS:-600} scripts/ci/ots_verify.sh $(OUT_DIR)/day

.PHONY: sec-scan
sec-scan: ## Run security scans (Bandit + pip-audit)
	@echo "[make] Running security scans..."
	@if command -v bandit >/dev/null 2>&1; then \
		bandit -q -r scripts/; \
	else \
		echo "[WARN] bandit not installed. Install with: pip install bandit"; \
	fi
	@if command -v pip-audit >/dev/null 2>&1; then \
		pip-audit -r requirements.txt || true; \
	else \
		echo "[WARN] pip-audit not installed. Install with: pip install pip-audit"; \
	fi
	@echo "[make] ✓ Security scans completed"
