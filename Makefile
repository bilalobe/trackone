# Makefile for Track1 — Ultra-Low-Power, Verifiable Telemetry
# Milestone-agnostic targets for development and testing

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
.PHONY: help run run-m1 run-m0 run-examples test clean tag tag-m1 lint

help: ## Show this help message
	@echo "Track1 Make Targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

run: run-m1 ## Run M#1 pipeline (framed ingest, default)

run-m1: ## M#1: pod_sim --framed -> frame_verifier -> merkle_batcher -> ots_anchor -> verify_cli
	@echo "[make] Running M#1 end-to-end pipeline..."
	@bash scripts/gateway/run_pipeline.sh && echo "[make] ✓ M#1 pipeline completed successfully" || (echo "[make] ✗ M#1 pipeline failed" && exit 1)

run-m0: run-examples ## M#0: Batch example facts -> anchor -> verify (alias)

run-examples: ## M#0: examples -> batch -> anchor -> verify
	@echo "[make] Running M#0 example pipeline..."
	python scripts/gateway/merkle_batcher.py \
		--facts toolset/unified/examples \
		--out $(OUT_DIR) \
		--site $(SITE) \
		--date $(DATE) \
		--validate-schemas
	python scripts/gateway/ots_anchor.py $(OUT_DIR)/day/$(DATE).bin
	python scripts/gateway/verify_cli.py --root $(OUT_DIR)
	@echo "[make] ✓ M#0 pipeline completed successfully"

test: ## Run all tests with pytest
	@echo "[make] Running tests..."
	pytest -q
	@echo "[make] ✓ All tests passed"

test-verbose: ## Run tests with verbose output
	@echo "[make] Running tests (verbose)..."
	pytest -v

clean: ## Remove build artifacts and output directories
	@echo "[make] Cleaning build artifacts..."
	rm -rf out/
	rm -rf __pycache__
	rm -rf scripts/**/__pycache__
	rm -rf .pytest_cache
	rm -f src/*.aux src/*.log src/*.out src/*.toc src/*.bbl src/*.blg
	@echo "[make] ✓ Cleaned"

tag: ## Create and push git tag: make tag TAG=vX.Y.Z
	@if [ -z "$(TAG)" ]; then \
		echo "[ERROR] Usage: make tag TAG=v0.0.1-m1"; \
		exit 1; \
	fi
	@echo "[make] Creating and pushing tag: $(TAG)"
	git tag -a $(TAG) -m "Release $(TAG)"
	git push origin $(TAG)
	@echo "[make] ✓ Tag $(TAG) created and pushed"

tag-m1: ## Quick tag for M#1: v0.0.1-m1
	$(MAKE) tag TAG=v0.0.1-m1

lint: ## Run basic Python linting (if ruff/black available)
	@echo "[make] Running linting..."
	@if command -v ruff >/dev/null 2>&1; then \
		ruff check scripts/ || true; \
	else \
		echo "[make] ruff not installed, skipping"; \
	fi
	@if command -v black >/dev/null 2>&1; then \
		black --check scripts/ || true; \
	else \
		echo "[make] black not installed, skipping"; \
	fi

.DEFAULT_GOAL := help
