.PHONY: run run-m1 run-examples run-m0 clean tag tag-m1

# Python interpreter
PY ?= python3

# Default site/date/output for the framed ingest pipeline
SITE ?= an-001
DAY ?= 2025-10-07
ROOT ?= out/site_demo
FRAMES := $(ROOT)/frames.ndjson
FACTS := $(ROOT)/facts
DEVICE_TABLE := $(ROOT)/device_table.json

# Milestone 1: framed ingest pipeline
run: ## M#1: pod_sim --framed -> frame_verifier -> merkle_batcher -> ots_anchor -> verify_cli
	@set -euo pipefail; \
	rm -rf "$(ROOT)"; \
	mkdir -p "$(ROOT)"; \
	$(PY) scripts/pod_sim/pod_sim.py --device-id pod-001 --count 10 --framed --out "$(FRAMES)" --facts-out "$(ROOT)/plain_facts"; \
	$(PY) scripts/gateway/frame_verifier.py --in "$(FRAMES)" --out-facts "$(FACTS)" --device-table "$(DEVICE_TABLE)" --window 64; \
	$(PY) scripts/gateway/merkle_batcher.py --facts "$(FACTS)" --out "$(ROOT)" --site "$(SITE)" --date "$(DAY)" --validate-schemas; \
	$(PY) scripts/gateway/ots_anchor.py "$(ROOT)/day/$(DAY).bin"; \
	$(PY) scripts/gateway/verify_cli.py --root "$(ROOT)" --facts "$(FACTS)"

# Alias for milestone 1
run-m1: run

# Milestone 0: batch bundled example facts -> anchor -> verify
run-examples: ## M#0: examples -> batch -> anchor -> verify
	@set -euo pipefail; \
	rm -rf "$(ROOT)"; \
	mkdir -p "$(ROOT)"; \
	$(PY) scripts/gateway/merkle_batcher.py --facts toolset/unified/examples --out "$(ROOT)" --site "$(SITE)" --date "$(DAY)" --validate-schemas; \
	$(PY) scripts/gateway/ots_anchor.py "$(ROOT)/day/$(DAY).bin"; \
	$(PY) scripts/gateway/verify_cli.py --root "$(ROOT)"

# Alias for milestone 0
run-m0: run-examples

# Tagging helpers
TAG ?= v0.0.1-m1

tag: ## Create and push git tag: make tag TAG=vX.Y.Z-<suffix>
	@git tag -a "$(TAG)" -m "Release $(TAG)" && git push origin "$(TAG)"

# Convenience: tag current commit as v0.0.1-m1
tag-m1: TAG := v0.0.1-m1
tag-m1: tag

clean:
	rm -rf out/site_demo
