# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Mantis — Autonomous Vulnerability Discovery Harness
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# Description: Build & automation helpers for the vuln-harness project
# Usage: run `make` or `make help` to view available targets
#
# help: Mantis — Autonomous Vulnerability Discovery Harness
#
# ───────���──────────────────────────────────────────────────────────────────
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# =============================================================================
# DYNAMIC HELP
# =============================================================================
.DEFAULT_GOAL := help
.PHONY: help
help:
	@grep "^# help:" Makefile | grep -v grep | sed 's/# help: //' | sed 's/# help://'

# =============================================================================
# help:
# help: SETUP
# help: install          - Install all dependencies via uv
# help: build-worker     - Build the ASAN worker Docker image
# help: services         - Start Redis and Postgres (docker-compose)
# help: services-down    - Stop Redis and Postgres
# =============================================================================

.PHONY: install build-worker services services-down

install:
	uv sync

build-worker:
	cd worker && docker build -t vuln-harness-worker:latest .

services:
	POSTGRES_PASSWORD=testpass docker compose up -d

services-down:
	docker compose down

# =============================================================================
# help:
# help: QUALITY
# help: check            - Run all quality checks (lint + format-check + test)
# help: ci               - Run lint + format-check + test (mirrors CI pipeline)
# help: lint             - Run ruff linter on all Python source
# help: format           - Auto-format code and fix lint issues
# help: format-check     - Check formatting without modifying files
# help: pre-commit       - Run all pre-commit hooks against all files
# =============================================================================

.PHONY: check ci lint format format-check pre-commit

check: lint format-check test

ci: lint format-check test

lint:
	uv run ruff check harness/ worker/ tests/

format:
	uv run ruff format harness/ worker/ tests/
	uv run ruff check --fix harness/ worker/ tests/

format-check:
	uv run ruff format --check harness/ worker/ tests/

pre-commit:
	uv run pre-commit run --all-files

# =============================================================================
# help:
# help: TESTING
# help: test             - Run unit tests with coverage
# help: test-all         - Run all tests including integration (needs Redis)
# help: test-verbose     - Run unit tests with verbose output
# help: coverage         - Run tests and generate HTML coverage report
# =============================================================================

.PHONY: test test-all test-verbose coverage

test:
	uv run pytest --ignore=tests/integration

test-all:
	uv run pytest

test-verbose:
	uv run pytest --ignore=tests/integration -v --tb=short

coverage:
	uv run pytest --ignore=tests/integration \
		--cov=harness --cov-report=html --cov-report=term
	@echo "HTML report: htmlcov/index.html"

# =============================================================================
# help:
# help: SCANNING
# help: rank             - Rank files in the default target (harness.yaml)
# help: scan             - Run the full vulnerability scan pipeline
# help: build-target     - Pre-compile target with ASAN for binary reuse
# =============================================================================

.PHONY: rank scan build-target

rank:
	uv run vuln-harness rank --config harness.yaml

scan:
	uv run vuln-harness run --config harness.yaml

build-target:
	uv run vuln-harness build --config harness.yaml

# =============================================================================
# help:
# help: CLEANUP
# help: clean            - Remove build and cache artifacts
# =============================================================================

.PHONY: clean

clean:
	rm -rf .ruff_cache .pytest_cache .mypy_cache .coverage htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
