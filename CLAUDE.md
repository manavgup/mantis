# CLAUDE.md

Guidelines for AI coding assistants working with this repository.

## Project Overview

Mantis (vuln-harness) is an autonomous defensive security research tool that finds, validates, and reports vulnerabilities in open-source C/C++ software. It uses a litellm-based ReAct agent loop inside isolated Docker containers with AddressSanitizer-instrumented binaries.

## Project Structure

```
harness/            # Python orchestrator (cli, config, ranking, parsing, validation)
worker/             # Inside-container agent (ReAct loop, tools, prompts)
  agent/            # litellm-based agent loop (loop.py, tools.py, run.py)
  prompts/          # Jinja2 prompt templates
tests/
  unit/             # Unit tests (no external services needed)
  integration/      # Integration tests (require Redis, Docker)
  fixtures/         # Sample ASAN output, agent responses
migrations/         # Alembic database migrations
runs/               # Scan output directories (gitignored except examples)
```

## Development Commands

```bash
make install        # Install dependencies
make test           # Run unit tests with coverage
make lint           # Run ruff linter
make format         # Auto-format with ruff
make check          # All quality checks (lint + format-check + test)
make pre-commit     # Run all pre-commit hooks
make services       # Start Redis + Postgres
make build-worker   # Build Docker worker image
```

## Key Architecture Decisions

- **litellm for all LLM calls**: Both orchestrator and worker use litellm — no direct Anthropic SDK dependency. Models are configurable via YAML.
- **Static ranker as default**: Free, instant regex-based file ranking. LLM ranking is an alternative.
- **Build once, scan many**: ASAN binaries are compiled once and mounted read-only into all worker containers.
- **SHA-3 audit log**: Every action is logged before execution with a hash-chained JSONL format.
- **Encryption at rest**: Findings stored with AES-256-GCM in Postgres.

## Testing

- Unit tests: `make test` (no external services needed)
- Integration tests: `make test-all` (requires Redis and Docker via `make services`)
- Coverage: infrastructure modules (cli, dispatcher, queue, models) are omitted from coverage as they require integration tests

## Code Style

- Formatter/linter: ruff (line-length=120, rules: E, F, I, W)
- Pre-commit hooks enforce formatting, linting, and AI artifact detection
- Python 3.12+, async/await patterns throughout
