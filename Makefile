SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

UV    ?= uv
RUFF  ?= ruff
PY    ?= python

DEVICES ?= configs/devices.yaml
ATTACKS ?= configs/attacks.yaml
DURATION ?= 28800
SAFE_PERIOD ?= 900

.PHONY: help sync lint format check test run sample build clean

help: ## Show targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

sync: ## Install/sync deps (including dev group)
	$(UV) sync --dev

format: ## Format code
	$(UV) run $(RUFF) format .

check: ## Lint (no fixes)
	$(UV) run $(RUFF) check .

lint: ## Format + lint with fixes
	$(UV) run $(RUFF) format .
	$(UV) run $(RUFF) check . --fix

test: ## Run tests
	$(UV) run pytest -q

build: ## Build sdist/wheel
	$(UV) build

clean: ## Remove build artifacts
	rm -rf dist build *.egg-info
	
preflight: ## Build + run twine metadata checks
	$(UV) build
	$(UV) tool run twine check dist/*

run: ## Run CAPEX with default configs
	$(UV) run python -m capex \
		--devices $(DEVICES) \
		--attacks $(ATTACKS) \
		--duration-seconds $(DURATION) \
		--safe-period-seconds $(SAFE_PERIOD)

run.dry: ## Validate config and print execution plan
	$(UV) run python -m capex \
		--dry-run \
		--devices $(DEVICES) \
		--attacks $(ATTACKS) \
		--duration-seconds $(DURATION) \
		--safe-period-seconds $(SAFE_PERIOD)

flows: ## Convert PCAPs in data/raw to CSVs in data/flows
	./scripts/run_flows.sh

deps.check: ## Checks dependencies
	$(UV) run deptry .