# ===============================================================
# Mantis (vuln-harness) — Development Makefile
# ===============================================================
#
# Usage:
#   make help          Show available targets
#   make install       Install all dependencies via uv
#   make test          Run unit tests with coverage
#   make lint          Run ruff linter
#   make format        Auto-format code with ruff
#   make pre-commit    Run all pre-commit hooks
#   make build-worker  Build the Docker worker image
#   make clean         Remove build/cache artifacts
# ---------------------------------------------------------------

.DEFAULT_GOAL := help
.PHONY: help install test lint format pre-commit clean build-worker services services-down

# ---------------------------------------------------------------
# Help
# ---------------------------------------------------------------
help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

# ---------------------------------------------------------------
# Setup
# ---------------------------------------------------------------
install: ## Install dependencies via uv
	uv sync

# ---------------------------------------------------------------
# Testing
# ---------------------------------------------------------------
test: ## Run unit tests with coverage (excludes integration tests)
	uv run pytest --ignore=tests/integration

# ---------------------------------------------------------------
# Linting & Formatting
# ---------------------------------------------------------------
lint: ## Run ruff linter on all Python source
	uv run ruff check harness/ worker/ tests/

format: ## Auto-format code and fix lint issues
	uv run ruff format harness/ worker/ tests/
	uv run ruff check --fix harness/ worker/ tests/

# ---------------------------------------------------------------
# Pre-commit
# ---------------------------------------------------------------
pre-commit: ## Run all pre-commit hooks against all files
	uv run pre-commit run --all-files

# ---------------------------------------------------------------
# Docker
# ---------------------------------------------------------------
build-worker: ## Build the ASAN worker Docker image
	cd worker && docker build -t vuln-harness-worker:latest .

services: ## Start Redis and Postgres via docker-compose
	POSTGRES_PASSWORD=testpass docker compose up -d

services-down: ## Stop Redis and Postgres
	docker compose down

# ---------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------
clean: ## Remove build and cache artifacts
	rm -rf .ruff_cache .pytest_cache .mypy_cache .coverage htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
