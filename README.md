# IBM Enterprise Vulnerability Harness (vuln-harness)

An autonomous defensive security research tool that finds, validates, and reports vulnerabilities in open-source C/C++ software. It uses a litellm-based ReAct agent loop inside isolated Docker containers, making it provider-agnostic (supports Anthropic, OpenAI, Ollama, and any provider litellm supports). The pipeline follows a five-stage methodology: file-ranking pre-pass, parallel isolated worker containers with AddressSanitizer verification, PoC generation, and validation agent filtering.

Built for enterprise use in regulated industries including financial services and federal government. Satisfies NIST frameworks, applicable regulatory requirements, and IBM security standards with a tamper-evident SHA-3 hash-chained audit log designed for watsonx.governance ingestion.

## Prerequisites

- **Docker** (with buildx) — for worker containers and local Redis/Postgres
- **Python 3.12+** — orchestrator language
- **uv** — Python package manager (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- **LLM provider API key** — e.g. `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or whichever env var your chosen provider requires (see [litellm provider docs](https://docs.litellm.ai/docs/providers))
- **OpenShift / IBM Cloud Code Engine** — for production deployment (optional for local dev)

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
# Set the API key for your chosen LLM provider:
export ANTHROPIC_API_KEY=sk-ant-...   # if using Anthropic
# export OPENAI_API_KEY=sk-...        # if using OpenAI
# Model is configurable in harness.yaml (e.g. worker_model, ranker_model)
export FINDINGS_ENC_KEY=$(python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())")
vuln-harness run --config harness.yaml
```

## Architecture overview

The harness operates as a five-stage pipeline managed by a Python asyncio orchestrator:

1. **File ranking** — Static regex-based ranker scores source files 1-5 by vulnerability likelihood (free, instant, no LLM call required). LLM-based ranking via litellm is available as an alternative.
2. **Job dispatch** — Redis priority queue feeds parallel Docker containers (default 4, production 50). The orchestrator auto-runs `build` before dispatch to pre-compile ASAN-instrumented binaries, which are reused across workers.
3. **Worker containers** — litellm-based ReAct agent loop analyzes one file per container with ASAN-instrumented binaries
4. **ASAN parser** — Extracts crash metadata, assigns severity tier (1-5), estimates CVSS
5. **Validation agent** — Separate LLM call via litellm filters false positives before human review

Results flow into an encrypted Postgres findings store. Every action is logged to the SHA-3 hash-chained audit JSONL before any subsequent step. See `01-constitution.md` and `02-specification.md` for full details.

## Constitution summary

- **P1 — Isolation is absolute**: One permitted egress: the configured LLM provider's API endpoint. No inter-container comms.
- **P2 — Human review before external action**: No finding leaves the system without explicit human sign-off.
- **P3 — Every action logged before execution**: Synchronous, hash-chained, tamper-evident audit JSONL.
- **P4 — No credential persistence in images**: Secrets injected via env vars at runtime only.
- **P5 — Containers are ephemeral**: Created fresh per job, destroyed after result collection.
- **P6 — Cost tracked in real time**: Per-run and per-day spend limits enforced by the dispatcher.
- **P7 — System never decides severity alone**: CVSS is an estimate; human confirms or overrides.
- **P8 — Exploit code is contained**: Encrypted at rest, never in plaintext outside containers.

## CLI reference

```bash
# Full pipeline run
vuln-harness run --config harness.yaml

# Stage 1 only: rank files by vulnerability likelihood
vuln-harness rank --config harness.yaml

# List findings awaiting human review
vuln-harness review --run-id <uuid>

# Record human sign-off on a finding
vuln-harness approve --finding-id <uuid> --reviewer "Name" --cvss 7.5 --approve-disclosure

# Verify audit log hash chain integrity
vuln-harness audit-verify --run-id <uuid>

# Pre-compile target with ASAN (reused across workers)
vuln-harness build --config harness.yaml

# Print cost breakdown for a run
vuln-harness cost --run-id <uuid>
```

## Moving to production

**OpenShift deployment**: Replace Docker with OpenShift container runtime. Worker containers become OpenShift Jobs with resource limits enforced by the cluster. The `harness.yaml` `max_parallel_workers` maps to Job parallelism. Use OpenShift Secrets for your LLM provider API key (e.g. `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) and `FINDINGS_ENC_KEY`.

**Network policy**: Replace the `scripts/setup-network.sh` iptables rules with OpenShift NetworkPolicy objects. The policy allows egress only to your configured LLM provider's API endpoint (e.g. `api.anthropic.com:443`, `api.openai.com:443`) and denies all inter-pod communication. This is the production equivalent of the Docker bridge network isolation.

**watsonx.governance integration**: The audit JSONL format and SHA-3 hash chain are designed for direct ingestion by watsonx.governance. Integration is a one-day task: POST each audit entry to the governance endpoint after the local write succeeds. The hash chain provides tamper evidence; watsonx.governance provides retention, search, and compliance reporting.

## Cost expectations

- **File ranking**: ~$0.10-0.30 per batch of 200 files (single API call)
- **Worker container**: ~$1-5 per file depending on turn count and model (claude-opus-4-6). Costs vary by provider and model.
- **Validation**: ~$0.05-0.15 per finding (single API call)
- **10-file scan**: ~$10-50 total depending on complexity and model choice
- **Full project scan (100 files)**: ~$100-500; use `max_files_to_scan` and `max_run_spend_usd` to control

Cost estimates above are based on Anthropic Claude pricing; costs vary by provider and model. Use `worker_model` in `harness.yaml` to select a cheaper model (e.g. `claude-sonnet-4-6`, or an OpenAI/Ollama model) at the expense of some analysis depth.
