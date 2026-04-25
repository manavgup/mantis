# Technical Plan
# Mantis — Autonomous Vulnerability Discovery Harness

## Repository layout

```
vuln-harness/
├── specs/                          # This directory — do not modify during implementation
│   ├── 01-constitution.md
│   ├── 02-specification.md
│   ├── 03-plan.md
│   └── 04-tasks.md
│
├── harness/                        # Python orchestrator package
│   ├── __init__.py
│   ├── config.py                   # Loads and validates harness.yaml
│   ├── ranker.py                   # Stage 1: file ranking via Messages API
│   ├── queue.py                    # Stage 2: Redis job queue management
│   ├── dispatcher.py               # Stage 2: container dispatch and lifecycle
│   ├── parser.py                   # Stage 4: ASAN output parser and triage
│   ├── validator.py                # Stage 5: validation agent via Messages API
│   ├── audit.py                    # Audit log writer (SHA-3 chained JSONL)
│   ├── findings.py                 # Findings store (Postgres) and report generator
│   ├── crypto.py                   # AES-256-GCM encrypt/decrypt for findings store
│   └── cli.py                      # CLI entry point (click)
│
├── worker/                         # Docker worker image
│   ├── Dockerfile
│   ├── entrypoint.sh               # Compiles target, invokes claude
│   └── prompts/
│       ├── worker-system.txt       # System prompt (verbatim from spec)
│       └── worker-task.txt.j2      # Jinja2 template for per-job task prompt
│
├── migrations/                     # Alembic DB migrations
│   └── versions/
│       └── 001_initial_schema.py
│
├── tests/
│   ├── unit/
│   │   ├── test_ranker.py
│   │   ├── test_parser.py
│   │   ├── test_validator.py
│   │   ├── test_audit.py
│   │   └── test_crypto.py
│   ├── integration/
│   │   ├── test_queue.py           # Requires Redis
│   │   └── test_dispatcher.py     # Requires Docker
│   └── fixtures/
│       ├── sample_asan_output.txt
│       └── sample_agent_response.json
│
├── harness.yaml.example            # Template config — copy to harness.yaml
├── docker-compose.yml              # Local dev: Redis + Postgres + harness
├── pyproject.toml                  # uv-managed, Python 3.12+
├── .env.example
└── README.md
```

---

## Component design

### `harness/config.py`

Uses `pydantic-settings` to load and validate `harness.yaml`. All fields typed. Raises on missing required fields. Provides a `Config` singleton accessed by all other modules. Validates that `ANTHROPIC_API_KEY` and `FINDINGS_ENC_KEY` env vars are present at startup — fail fast before any work begins.

```python
class Config(BaseSettings):
    repo_url: str
    repo_commit: str = "main"
    binary_name: str
    project_name: str
    project_description: str
    exclude_patterns: list[str] = []
    max_files_to_scan: int | None = None
    ranking_model: str = "claude-opus-4-6"
    worker_model: str = "claude-opus-4-6"
    validation_model: str = "claude-opus-4-6"
    max_turns_per_worker: int = 50
    max_parallel_workers: int = 4
    max_run_spend_usd: float = 100.0
    max_day_spend_usd: float = 500.0
    worker_image: str = "vuln-harness-worker:latest"
    container_timeout_seconds: int = 1800
    worker_memory_gb: int = 4
    worker_cpus: int = 2
    redis_url: str = "redis://localhost:6379"
    postgres_url: str
    run_output_dir: Path = Path("./runs")
    findings_encryption_key_env: str = "FINDINGS_ENC_KEY"
    anthropic_api_key: str = Field(alias="ANTHROPIC_API_KEY")
    findings_enc_key: str = Field(alias="FINDINGS_ENC_KEY")
```

### `harness/ranker.py`

Direct `anthropic` SDK call — not Claude Code. Uses `client.messages.create`. Batches up to 200 file paths per call. Returns `list[RankedFile]`. Writes result to `{run_dir}/file_rankings.json`. Logs the API call (model, input tokens, output tokens, cost) to audit log before returning.

Key function signature:
```python
async def rank_files(
    run_id: str,
    repo_path: Path,
    config: Config,
    audit: AuditLog,
) -> list[RankedFile]:
```

### `harness/queue.py`

Redis-backed job queue. Uses `redis.asyncio`. Exposes:
```python
async def enqueue_jobs(run_id: str, ranked_files: list[RankedFile]) -> int
async def dequeue_job(run_id: str) -> Job | None          # highest priority first
async def update_job_status(job_id: str, status: str, **kwargs) -> None
async def get_run_spend(run_id: str) -> float
async def increment_spend(run_id: str, amount: float) -> float
async def get_queue_depth(run_id: str) -> int
```

### `harness/dispatcher.py`

Asyncio-based dispatcher. Maintains a semaphore of size `max_parallel_workers`. For each dispatched job:
1. Writes `job_dispatch` audit event
2. Runs `docker run` via `asyncio.create_subprocess_exec`
3. Waits for container exit or timeout (SIGKILL on timeout)
4. Collects stdout (agent JSON) and stderr (ASAN output, build output)
5. Writes `container_exit` audit event
6. Calls `parser.parse_result(stdout, stderr)` → structured finding
7. Calls `validator.validate(finding)` → validation verdict
8. Writes finding to Postgres via `findings.store()`
9. Increments spend counter
10. Continues to next job

The dispatcher loop runs until queue is empty or spend limit is hit.

### `harness/parser.py`

Pure Python, no external calls. Parses the JSON blob from Claude Code's `--output-format json` output. Extracts ASAN crash metadata using regex patterns against `asan_output` field. Assigns severity tier per taxonomy in spec. Computes CVSS estimate heuristic.

ASAN output patterns to extract:
```python
ASAN_PATTERNS = {
    "heap-buffer-overflow":  r"ERROR: AddressSanitizer: heap-buffer-overflow",
    "stack-buffer-overflow": r"ERROR: AddressSanitizer: stack-buffer-overflow",
    "use-after-free":        r"ERROR: AddressSanitizer: heap-use-after-free",
    "use-after-return":      r"ERROR: AddressSanitizer: stack-use-after-return",
    "null-dereference":      r"ERROR: AddressSanitizer: null-dereference",
    "memory-leak":           r"ERROR: LeakSanitizer: detected memory leaks",
    "global-buffer-overflow":r"ERROR: AddressSanitizer: global-buffer-overflow",
}
READ_WRITE_PATTERN = r"(READ|WRITE) of size \d+"
LOCATION_PATTERN   = r"in (\w+) ([^\s]+):(\d+)"
```

### `harness/validator.py`

Direct `anthropic` SDK call. Single `messages.create` per finding. Returns `ValidationResult`. Logs the call to audit log. Routes finding to appropriate queue based on verdict.

### `harness/audit.py`

The most critical module for compliance. Writes append-only JSONL with SHA-3 hash chaining. Synchronous writes only (never async — we cannot risk a log entry being skipped). Exposes:

```python
class AuditLog:
    def __init__(self, path: Path): ...

    def write(self,
        run_id: str,
        event_type: str,
        actor: str,
        payload: dict,
        job_id: str | None = None,
    ) -> str:  # returns this_hash
```

Each `write()` call:
1. Reads last line's `this_hash` (or `"genesis"` for first entry)
2. Constructs entry dict with `seq`, `ts`, `run_id`, `job_id`, `event_type`, `actor`, `payload`, `prev_hash`
3. Computes `this_hash = sha3_256(json.dumps(entry, sort_keys=True))`
4. Adds `this_hash` to entry
5. Writes line atomically using `fcntl.flock` to prevent concurrent corruption
6. Returns `this_hash`

### `harness/crypto.py`

AES-256-GCM encryption for findings store. Key loaded from env at startup. Exposes:
```python
def encrypt(plaintext: str, key: bytes) -> bytes   # returns nonce + ciphertext
def decrypt(ciphertext: bytes, key: bytes) -> str
```

Uses `cryptography` library. Nonce is random 12 bytes prepended to ciphertext. Never reuse nonces.

### `harness/findings.py`

Postgres via `asyncpg`. Manages `runs`, `jobs`, `findings` tables. Generates the markdown human-review report per finding. Report template is a Jinja2 template matching the format in the spec.

### `harness/cli.py`

Click-based CLI. Entry points:

```
vuln-harness run --config harness.yaml        # full pipeline run
vuln-harness rank --config harness.yaml       # stage 1 only, print ranked files
vuln-harness review --run-id <uuid>           # list findings awaiting review
vuln-harness approve --finding-id <uuid> \
  --reviewer "Name" \
  --cvss 7.5 \
  --approve-disclosure                        # record human sign-off
vuln-harness audit-verify --run-id <uuid>    # verify hash chain integrity
vuln-harness cost --run-id <uuid>            # print cost breakdown
```

---

## Worker Dockerfile

```dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV NODE_VERSION=20

RUN apt-get update && apt-get install -y \
    clang \
    lldb \
    gdb \
    valgrind \
    build-essential \
    cmake \
    autoconf \
    automake \
    libtool \
    pkg-config \
    git \
    python3.12 \
    python3-pip \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Node.js (required by Claude Code)
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Claude Code CLI — installed at build time, no credential needed
RUN npm install -g @anthropic-ai/claude-code

# Create non-root user
RUN useradd -m -u 1000 researcher
USER researcher
WORKDIR /workspace

# Prompts mounted at runtime
COPY --chown=researcher:researcher prompts/ /prompts/
COPY --chown=researcher:researcher entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
```

---

## Docker network setup (local dev)

```bash
# Create isolated bridge network
docker network create \
  --driver bridge \
  --opt com.docker.network.bridge.name=vulnharness0 \
  vuln-harness-net

# Block all outbound from this network except api.anthropic.com
# (Run as root on the Docker host)
BRIDGE_IF="vulnharness0"
iptables -I FORWARD -i $BRIDGE_IF -j DROP
iptables -I FORWARD -i $BRIDGE_IF -d $(dig +short api.anthropic.com | head -1) -p tcp --dport 443 -j ACCEPT
```

For local development, a simpler alternative: skip `--network vuln-harness-net` and use `--network host` only during initial testing to verify the agent loop works, then add network isolation before any real target scanning.

---

## `docker-compose.yml` (local dev)

```yaml
version: "3.9"
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    command: redis-server --save 60 1

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: vulnharness
      POSTGRES_USER: harness
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    ports:
      - "5432:5432"
    volumes:
      - pg-data:/var/lib/postgresql/data

volumes:
  redis-data:
  pg-data:
```

---

## `pyproject.toml`

```toml
[project]
name = "vuln-harness"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "anthropic>=0.49.0",
    "click>=8.1",
    "pydantic>=2.0",
    "pydantic-settings>=2.0",
    "redis[asyncio]>=5.0",
    "asyncpg>=0.29",
    "alembic>=1.13",
    "cryptography>=42.0",
    "jinja2>=3.1",
    "pyyaml>=6.0",
    "httpx>=0.27",
    "python-dotenv>=1.0",
]

[project.scripts]
vuln-harness = "harness.cli:cli"

[tool.uv]
dev-dependencies = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "pytest-mock>=3.12",
    "ruff>=0.4",
    "mypy>=1.9",
]
```

---

## Key technical decisions and rationale

**Why Claude Code CLI (`claude -p`) not the Agent SDK directly?**
The Anthropic red team explicitly used Claude Code. It provides the full agentic loop — tool execution, multi-turn reasoning, shell access — with battle-tested prompt caching and compaction built in. The Agent SDK is lower-level and would require reimplementing what Claude Code already handles. Use the same tool Anthropic used.

**Why asyncio for the orchestrator?**
Container dispatch is I/O-bound, not CPU-bound. We're waiting for containers to finish, not computing. `asyncio` with a semaphore gives clean concurrency control without threading complexity.

**Why Redis for the queue?**
Fast, simple, supports atomic operations needed for spend tracking (`INCRBYFLOAT`). Sorted sets give us priority ordering for free. Easy to replace with Postgres in production if Redis is unavailable.

**Why synchronous writes for the audit log?**
An async audit log can lose entries if the process crashes between the write being scheduled and executed. For a compliance artifact, synchronous write + fsync is required. The performance cost is acceptable — we're not logging thousands of events per second.

**Why AES-256-GCM for exploit storage?**
Exploit reproduction commands and patches are sensitive — they could enable attacks if leaked. GCM provides both encryption and authentication. Key lives in env, never in the database.

**Why build the target binary outside the container?**
Actually we build inside the container (in entrypoint.sh) because the ASAN-instrumented binary must match the container's clang version exactly. The source is mounted read-only; the build artifacts go to /workspace which is tmpfs.

**Why `--output-format json` for Claude Code?**
Gives us structured, parseable output from the agent's final turn. We still capture stderr for raw ASAN output which the agent may not have included verbatim in its JSON.
