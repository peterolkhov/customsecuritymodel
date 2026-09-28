PYTHON ?= python3
COMPANY ?= acme
SCAN ?= demo/fixtures/acme/report.json

.PHONY: help selftest train adapter adapter-dry brain-selftest \
	company-onboard company-demo company-selftest

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

selftest: ## offline check of every module — must pass with no keys, no network
	$(PYTHON) river/train.py --self-test
	$(PYTHON) memory/brain.py --self-test

brain-selftest: ## offline check of the GBrain findings brain
	$(PYTHON) memory/brain.py --self-test

train: ## real River training run (needs .env: RIVER_API_KEY, RIVER_BASE_MODEL)
	$(PYTHON) river/train.py --pairs $(PAIRS) --live

adapter: ## probe reports -> data/out/pairs.jsonl (falls back to the example fixture)
	$(PYTHON) data/build_pairs.py

adapter-dry: ## manifest-only dry run of the adapter
	$(PYTHON) data/build_pairs.py --dry-run

company-onboard: ## company flow: scan -> pairs -> brain -> suite  (COMPANY=acme SCAN=path)
	$(PYTHON) company/run.py onboard --company $(COMPANY) --scan $(SCAN)

company-demo: ## offline end-to-end demo on the acme fixture (no keys)
	$(PYTHON) company/run.py demo

company-selftest: ## offline check of the company orchestrator
	$(PYTHON) company/run.py selftest
