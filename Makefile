# Use bash for shell commands so `set -o pipefail` is available
SHELL := /bin/bash

.PHONY: help run run-framed run-examples run-m1 run-m0 clean tag tag-m1

# Python interpreter
PY ?= python3

# Pipeline mode: 'framed' (full pipeline) or 'examples' (M#0 path)
# Usage: make run MODE=examples
MODE ?= framed

# Default site/date/output for the pipeline
SITE ?= an-001
DAY ?= 2025-10-07
ROOT ?= out/site_demo
FRAMES := $(ROOT)/frames.ndjson
FACTS := $(ROOT)/facts
PLAIN_FACTS := $(ROOT)/plain_facts
DEVICE_TABLE := $(ROOT)/device_table.json

# Pod simulator knobs
DEVICE_ID ?= pod-001
COUNT ?= 10
SLEEP ?= 0

# Schema validation toggle
VALIDATE_SCHEMAS ?= true

help: ## Show help for Makefile targets
	@grep -E '^[a-zA-Z0-9_.-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "} {printf "%-20s %s\n", $$1, $$2}'

# Top-level run delegates to a mode-specific target
run: ## Run pipeline (MODE=framed|examples) - default MODE=framed
ifeq ($(MODE),examples)
	@$(MAKE) run-examples
else
	@$(MAKE) run-framed
endif

# Framed pipeline (Milestone-1 style): pod_sim --framed -> frame_verifier -> merkle_batcher -> ots_anchor -> verify_cli
run-framed: ## Run framed ingest pipeline
	@set -euo pipefail; \
	rm -rf "$(ROOT)"; \
	mkdir -p "$(ROOT)"; \
	$(PY) scripts/pod_sim/pod_sim.py --device-id "$(DEVICE_ID)" --count "$(COUNT)" --sleep "$(SLEEP)" --framed --out "$(FRAMES)" --facts-out "$(PLAIN_FACTS)"; \
	$(PY) scripts/gateway/frame_verifier.py --in "$(FRAMES)" --out-facts "$(FACTS)" --device-table "$(DEVICE_TABLE)" --window 64; \
	$(PY) scripts/gateway/merkle_batcher.py --facts "$(FACTS)" --out "$(ROOT)" --site "$(SITE)" --date "$(DAY)" $(if $(filter true,$(VALIDATE_SCHEMAS)),--validate-schemas,); \
	$(PY) scripts/gateway/ots_anchor.py "$(ROOT)/day/$(DAY).bin"; \
	$(PY) scripts/gateway/verify_cli.py --root "$(ROOT)" --facts "$(FACTS)"

# Examples-only pipeline (Milestone-0): use bundled example facts
run-examples: ## Run examples pipeline (use packaged example facts)
	@set -euo pipefail; \
	rm -rf "$(ROOT)"; \
	mkdir -p "$(ROOT)"; \
	$(PY) scripts/gateway/merkle_batcher.py --facts toolset/unified/examples --out "$(ROOT)" --site "$(SITE)" --date "$(DAY)" $(if $(filter true,$(VALIDATE_SCHEMAS)),--validate-schemas,); \
	$(PY) scripts/gateway/ots_anchor.py "$(ROOT)/day/$(DAY).bin"; \
	$(PY) scripts/gateway/verify_cli.py --root "$(ROOT)"

# Backwards-compatible aliases
run-m1: ## Alias for legacy M#1 run
	@$(MAKE) run-framed

run-m0: ## Alias for legacy M#0 run
	@$(MAKE) run-examples

# Tagging helpers
TAG ?= v0.0.1-m1

tag: ## Create and push git tag: make tag TAG=vX.Y.Z-<suffix>
	@git tag -a "$(TAG)" -m "Release $(TAG)" && git push origin "$(TAG)"

# Convenience: tag current commit as v0.0.1-m1
tag-m1: TAG := v0.0.1-m1
tag-m1: tag

clean: ## Remove generated out/site_demo directory
	rm -rf out/site_demo
