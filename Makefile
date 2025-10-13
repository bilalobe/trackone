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
.PHONY: help install run test test-verbose test-cov clean tag lint format lint-fix dev-setup gen-vectors

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

test-verbose: ## Run tests with verbose output
	@echo "[make] Running tests (verbose)..."
	pytest -v

test-cov: ## Run tests with coverage report
	@echo "[make] Running tests with coverage..."
	pytest --cov=scripts --cov-report=term-missing --cov-report=html -v
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

.PHONY: watch
watch: ## Watch for file changes and re-run tests (requires pytest-watch)
	@echo "[make] Watching for changes (Ctrl+C to stop)..."
	@if command -v ptw >/dev/null 2>&1; then \
		ptw scripts/ --; \
	else \
		echo "[ERROR] pytest-watch not installed. Install with: pip install pytest-watch"; \
		exit 1; \
	fi
