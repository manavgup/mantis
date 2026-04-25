.PHONY: install test lint format pre-commit clean build-worker

install:
	uv sync

test:
	uv run pytest

lint:
	uv run ruff check harness/ worker/ tests/

format:
	uv run ruff format harness/ worker/ tests/
	uv run ruff check --fix harness/ worker/ tests/

pre-commit:
	uv run pre-commit run --all-files

clean:
	rm -rf .ruff_cache .pytest_cache .mypy_cache .coverage htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

build-worker:
	cd worker && docker build -t vuln-harness-worker:latest .
