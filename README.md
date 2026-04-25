# Mantis — Autonomous Vulnerability Discovery Harness

An autonomous defensive security research tool that finds, validates, and reports vulnerabilities in open-source C/C++ software. It uses a litellm-based ReAct agent loop as the agentic runtime inside isolated Docker containers, following the five-stage Anthropic methodology: file-ranking pre-pass, parallel isolated worker containers with AddressSanitizer verification, PoC generation, and validation agent filtering. The agent loop is provider-agnostic — any litellm-compatible model (Anthropic, OpenAI, Google, Ollama, etc.) works out of the box.

Built for enterprise use in regulated industries. Satisfies NIST frameworks and applicable regulatory requirements with a tamper-evident SHA-3 hash-chained audit log.

## Prerequisites

- **Docker** (with buildx) — for worker containers and local Redis/Postgres
- **Python 3.12+** — orchestrator language
- **uv** — Python package manager (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- **LLM provider API key** — at least one of `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`, etc. (any litellm-supported provider)
- **Kubernetes** — for production deployment (optional for local dev)

## Local quickstart

```bash
# 1. Clone and install dependencies
git clone <repo-url> && cd vuln-harness
uv sync

# 2. Start Redis and Postgres
cp .env.example .env  # edit with real POSTGRES_PASSWORD
docker compose up -d

# 3. Run database migrations
POSTGRES_PASSWORD=<password> uv run alembic upgrade head

# 4. Configure your target
cp harness.yaml.example harness.yaml
# Edit harness.yaml: set repo_url, binary_name, project_name, etc.

# 5. Run the full pipeline
# Set your LLM provider API key:
export ANTHROPIC_API_KEY=sk-ant-...    # for Anthropic models
# — or —
export OPENAI_API_KEY=sk-...           # for OpenAI models

# Override models via env vars (no YAML changes needed):
# export WORKER_MODEL=openai/gpt-4o
# export RANKING_MODEL=openai/gpt-4o
# export VALIDATION_MODEL=openai/gpt-4o

export FINDINGS_ENC_KEY=$(python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())")
vuln-harness run --config harness.yaml
```

## Architecture overview

The harness operates as a five-stage pipeline managed by a Python asyncio orchestrator:

1. **File ranking** — Static regex-based ranker scores source files 1-5 by vulnerability likelihood (default, free, instant). LLM-based ranking available as an alternative via `ranking_strategy: llm` in config.
2. **Job dispatch** — Redis priority queue feeds parallel Docker containers (default 4, production 50)
3. **Worker containers** — litellm-based ReAct agent loop analyzes one file per container with ASAN-instrumented binaries. Target binaries are auto-built once before dispatch; pre-compiled binaries are reused across all workers.
4. **ASAN parser** — Extracts crash metadata, assigns severity tier (1-5), estimates CVSS
5. **Validation agent** — Separate LLM call via litellm filters false positives before human review

Results flow into an encrypted Postgres findings store. Every action is logged to the SHA-3 hash-chained audit JSONL before any subsequent step. See `01-constitution.md` and `02-specification.md` for full details.

## Validated findings

The harness has been validated against giflib 5.1.4 (a known-vulnerable release), successfully discovering 3 vulnerabilities:

| # | Type | Location | Severity | CVE |
|---|------|----------|----------|-----|
| 1 | heap-buffer-overflow (READ) | `util/gif2rgb.c:293` | Tier 3, CVSS 6.2 | CVE-2016-3977 |
| 2 | stack-buffer-overflow (WRITE) | `util/gifbuild.c:242` | Tier 4, CVSS 8.2 | — |
| 3 | heap-buffer-underflow (READ) | `lib/gifalloc.c:148` | Tier 3, CVSS 6.2 | — |

All findings were validated by the validation agent and confirmed with AddressSanitizer output. See `FINDING_001_giflib_5_1_4.md` for full details including reproduction steps and candidate patches.

## Model configuration

All config fields can be overridden via environment variables — no YAML changes needed. Env vars take precedence over YAML values.

```bash
# Switch to OpenAI
export OPENAI_API_KEY=sk-...
export WORKER_MODEL=openai/gpt-4o
export RANKING_MODEL=openai/gpt-4o
export VALIDATION_MODEL=openai/gpt-4o
vuln-harness run --config harness.yaml

# Switch to Ollama (local)
export WORKER_MODEL=ollama/llama3
export RANKING_MODEL=ollama/llama3
export VALIDATION_MODEL=ollama/llama3
vuln-harness run --config harness.yaml
```

The YAML configs default to Anthropic models, but any [litellm-supported provider](https://docs.litellm.ai/docs/providers) works. Any field in `harness/config.py` can be overridden by setting an env var with the matching name.

## Constitution summary

- **P1 — Isolation is absolute**: One permitted egress: the configured LLM provider API endpoint(s). No inter-container comms.
- **P2 — Human review before external action**: No finding leaves the system without explicit human sign-off.
- **P3 — Every action logged before execution**: Synchronous, hash-chained, tamper-evident audit JSONL.
- **P4 — No credential persistence in images**: Secrets injected via env vars at runtime only.
- **P5 — Containers are ephemeral**: Created fresh per job, destroyed after result collection.
- **P6 — Cost tracked in real time**: Per-run and per-day spend limits enforced by the dispatcher.
- **P7 — System never decides severity alone**: CVSS is an estimate; human confirms or overrides.
- **P8 — Exploit code is contained**: Encrypted at rest, never in plaintext outside containers.

## CLI reference

```bash
# Pre-compile target with ASAN (binaries reused across workers)
vuln-harness build --config harness.yaml

# Full pipeline (auto-builds, then dispatches workers)
vuln-harness run --config harness.yaml

# Use pre-compiled binaries from a previous build
vuln-harness run --config harness.yaml --bin-dir runs/<run-id>/bin

# Stage 1 only: rank files by vulnerability likelihood
vuln-harness rank --config harness.yaml

# List findings awaiting human review
vuln-harness review --run-id <uuid>

# Record human sign-off on a finding
vuln-harness approve --finding-id <uuid> --reviewer "Name" --cvss 7.5 --approve-disclosure

# Verify audit log hash chain integrity
vuln-harness audit-verify --run-id <uuid>

# Print cost breakdown for a run
vuln-harness cost --run-id <uuid>
```

## Development

### Setup

```bash
make install          # install dependencies via uv
make build-worker     # build the Docker worker image
```

### Quality checks

```bash
make test             # run unit tests with coverage
make lint             # ruff check
make format           # ruff format + fix
make pre-commit       # run all pre-commit hooks
```

### Pre-commit hooks

Install hooks locally:

```bash
uv run pre-commit install
```

Hooks run automatically on commit: ruff check/format, trailing whitespace, YAML/TOML validation, large file detection, AI artifact detection.

### CI

All PRs to main run:
- **Pre-commit** — all hooks
- **Lint** — ruff check + format check
- **Tests** — pytest with coverage gate (50% overall; ~84% on unit-testable code)

## Moving to production

**Kubernetes deployment**: Replace Docker with Kubernetes Jobs. Worker containers become Jobs with resource limits enforced by the cluster. The `harness.yaml` `max_parallel_workers` maps to Job parallelism. Use Kubernetes Secrets for API keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.) and `FINDINGS_ENC_KEY`.

**Network policy**: Replace the `scripts/setup-network.sh` iptables rules with Kubernetes NetworkPolicy objects. The policy allows egress only to the configured LLM provider endpoint(s) and denies all inter-pod communication. This is the production equivalent of the Docker bridge network isolation.

**Governance integration**: The audit JSONL format and SHA-3 hash chain are designed for direct ingestion by governance platforms. Integration is a one-day task: POST each audit entry to the governance endpoint after the local write succeeds. The hash chain provides tamper evidence; the governance platform provides retention, search, and compliance reporting.

## Cost expectations

- **File ranking**: Free with static ranker (default). ~$0.10-0.30 per batch of 200 files with LLM ranking.
- **Worker container**: ~$1-5 per file depending on turn count and model
- **Validation**: ~$0.05-0.15 per finding (single API call)
- **10-file scan**: ~$10-50 total depending on complexity and model choice
- **Full project scan (100 files)**: ~$100-500; use `max_files_to_scan` and `max_run_spend_usd` to control

Costs vary by provider and model. Use a smaller model (e.g. `anthropic/claude-sonnet-4-6` or `openai/gpt-4o-mini`) in `harness.yaml` to reduce per-file cost at the expense of some analysis depth.
