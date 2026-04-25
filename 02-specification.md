# Specification
# Mantis — Autonomous Vulnerability Discovery Harness

## Overview

The harness operates as a pipeline of five stages executed by a Python orchestrator. The orchestrator manages a job queue and dispatches isolated Docker containers. Each container runs a Python ReAct agent loop (powered by litellm) against a single file of the target codebase. Results flow back to the orchestrator, through a validation agent, into an audit-logged findings store, and finally into a human-review package.

```
Target repo
    │
    ▼
[Stage 1] File-ranking agent          ← litellm.acompletion(), no container
    │  sorted priority queue
    ▼
[Stage 2] Job queue + dispatcher      ← Redis queue, N parallel containers
    │
    ▼
[Stage 3] Worker containers (×N)      ← Python ReAct loop + litellm, ASAN verifier
    │  raw findings (JSON)
    ▼
[Stage 4] ASAN parser + triage        ← extracts crash metadata, severity tier
    │  structured findings
    ▼
[Stage 5] Validation agent            ← litellm.acompletion(), filters noise
    │  validated findings
    ▼
Human-review package                  ← markdown report per finding
    │
    ▼ (human sign-off required)
Disclosure / patch / regulatory output
```

---

## Stage 1 — File-ranking pre-pass

### Purpose
Prioritize which files to scan first. A 500-file repo should have its highest-risk files scanned before any budget is spent on constant-definition headers or auto-generated code.

### Inputs
- Path to cloned target repository on local filesystem
- List of all files with extensions `.c`, `.cpp`, `.h`, `.cc` (recursively enumerated)
- Configurable exclusion patterns (e.g. `*/test/*`, `*/vendor/*`, `*_generated.*`)

### Process
Single `litellm.acompletion()` API call. Not a container. Model: configurable, default `anthropic/claude-opus-4-6`. The prompt presents a batch of up to 200 file paths at once and asks the model to score each 1–5:

```
Score: 1 — constants, generated code, no logic
Score: 2 — utility functions, low attack surface
Score: 3 — internal data processing, moderate surface
Score: 4 — parses external input, manages memory, handles auth
Score: 5 — network I/O, file parsing of untrusted data, memory allocators, crypto
```

If the repo has >200 files, batch into multiple calls. Collect all scores, sort descending by score, break ties alphabetically. Write sorted list to `{run_dir}/file_rankings.json`.

### Outputs
```json
{
  "run_id": "uuid4",
  "repo": "https://github.com/...",
  "commit": "sha",
  "ranked_files": [
    {"path": "src/parser.c", "score": 5, "reason": "parses untrusted network data"},
    {"path": "src/alloc.c",  "score": 4, "reason": "custom memory allocator"},
    ...
  ],
  "total_files": 312,
  "excluded": 47,
  "ranked": 265,
  "ranking_cost_usd": 0.12
}
```

### Error handling
- If the API call fails, retry up to 3 times with exponential backoff
- If a file path score is missing from the response, default score to 3 and log a warning
- If the entire ranking call fails after retries, abort the run with a clear error message

---

## Stage 2 — Job queue and dispatcher

### Purpose
Feed worker containers from the priority queue, respect concurrency limits, track spend, handle failures.

### Job queue schema (Redis)
Each job is a Redis hash keyed by `job:{run_id}:{job_id}`:
```
file_path        string   absolute path to target file
run_id           string   uuid4
job_id           string   uuid4
status           string   pending | running | done | failed | timeout
priority_score   int      1–5 from ranking stage
container_id     string   Docker container ID (set when dispatched)
started_at       datetime
completed_at     datetime
cost_usd         float    filled on completion
result_path      string   path to output JSONL (filled on completion)
error            string   error message if failed
```

Sorted set `queue:{run_id}` holds job_ids sorted by priority_score descending.

### Dispatcher behavior
- Poll `queue:{run_id}` for pending jobs
- Enforce `MAX_PARALLEL_WORKERS` (default: 4 locally, 50 in production)
- Before dispatching each job, check running spend total against `MAX_RUN_SPEND_USD`
- If spend limit reached, pause dispatch and emit a warning; do not cancel running containers
- Dispatch = `docker run` with all required flags (see Stage 3 for full flags)
- On container exit, collect stdout/stderr, update job record, write result file
- Retry failed containers once (different random seed in prompt); if second attempt fails, mark job `failed` and continue

### Spend tracking
- Maintain a Redis key `spend:{run_id}` as a running float sum
- Update atomically after each container completes using INCRBYFLOAT
- Write spend snapshot to audit log every 60 seconds during active runs

---

## Stage 3 — Worker containers

### Container image specification

Base image: `ubuntu:22.04`

Required packages installed at image build time (not at runtime):
```
clang                    # compiler with ASAN support
lldb                     # debugger for agent
gdb                      # alternate debugger
valgrind                 # memory analysis (slower but deeper)
build-essential          # make, cmake, autoconf etc
git                      # for any submodule operations on source
python3.12               # for helper scripts
libasan6                 # AddressSanitizer runtime
litellm                  # provider-agnostic LLM API (installed via pip)
```

Agent code installed at image build time:
```dockerfile
COPY agent/ /agent/
RUN pip install --no-cache-dir -r /agent/requirements.txt
```

The target project source is volume-mounted at runtime, not baked into the image. The target binary is compiled at container startup by an entrypoint script before the agent is invoked.

### Entrypoint script (`entrypoint.sh`)

Runs inside the container before the agent:
1. `cd /target && git submodule update --init --recursive` (if applicable)
2. Compile with ASAN: `CC=clang CFLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer" ./configure --disable-shared && make -j$(nproc)`
3. If compilation fails, write a failed-compilation result to stdout as JSON and exit 1
4. Set `ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:print_stacktrace=1`
5. Invoke the agent (see below)

### Agent loop invocation

```bash
python3 /agent/run.py
```

Environment variables:
- `MODEL` — litellm model string (e.g., `anthropic/claude-opus-4-6`, `openai/gpt-4o`)
- `MAX_TURNS` — max agent iterations (default 50)
- `TASK_PROMPT` — rendered task prompt

The agent loop (`/agent/loop.py`) implements a standard ReAct pattern:
1. Call `litellm.completion(model=MODEL, messages=..., tools=..., tool_choice="auto")`
2. If response contains tool_calls: execute each tool, append results, loop
3. If no tool_calls: extract final JSON verdict from response

### Worker system prompt (`worker-system.txt`)

```
You are a security vulnerability researcher operating inside an isolated container.
Your goal is to find real, exploitable security vulnerabilities in the target software.

Rules:
- You have bash access. Use it freely to read code, compile, run the binary, inspect crashes.
- The binary at /target/bin/ is compiled with AddressSanitizer. ASAN output on stderr indicates real memory safety bugs.
- Do not attempt to make network connections. The container has no internet access.
- Do not write files outside /workspace/. Do not modify source files under /target/src/.
- If you find a vulnerability, produce a minimal proof-of-concept that reliably triggers the ASAN crash.
- If after thorough investigation you find no vulnerability in your assigned file, say so clearly.
- Your output will be parsed as JSON. Always end with a valid JSON object matching the schema below.

Output schema:
{
  "verdict": "found" | "not_found" | "inconclusive",
  "vuln_type": string | null,        // e.g. "heap-buffer-overflow", "use-after-free"
  "file": string | null,             // affected source file path
  "line": integer | null,            // affected line number
  "function": string | null,         // affected function name
  "description": string,             // plain English explanation of the bug
  "reproduction": string | null,     // exact bash command(s) to reproduce the crash
  "asan_output": string | null,      // verbatim ASAN crash output
  "candidate_patch": string | null,  // suggested fix as a unified diff
  "confidence": "high" | "medium" | "low",
  "reasoning": string                // your step-by-step reasoning
}
```

### Worker task prompt (`worker-task.txt`)

Generated per job by the orchestrator:
```
Your assigned file is: {file_path}

The target project is: {project_name} ({project_description})
The ASAN-instrumented binary is at: /target/bin/{binary_name}

Focus your analysis on {file_path}. Read it carefully. Form hypotheses about
memory safety vulnerabilities — buffer overflows, use-after-free, integer
overflows leading to bad allocation sizes, format string bugs, or similar.

Test your hypotheses by running the binary with crafted inputs. Use GDB or LLDB
if you need to inspect execution state. Read ASAN output carefully — it tells
you exactly what went wrong and where.

Work methodically. If one hypothesis fails, try the next. You have {max_turns}
turns. Use them.
```

### Docker run flags

```bash
docker run \
  --rm \
  --name "worker-{job_id}" \
  --network vuln-harness-net \           # custom bridge network with egress rules
  --memory "4g" \
  --memory-swap "4g" \                   # no swap
  --cpus "2" \
  --read-only \                          # root filesystem read-only
  --tmpfs /tmp:size=512m \
  --tmpfs /workspace:size=1g \
  -v "{repo_path}:/target/src:ro" \      # source read-only
  -v "{binary_path}:/target/bin:ro" \    # pre-compiled binary read-only
  -v "{prompts_path}:/prompts:ro" \
  # Provider API keys are passed through from orchestrator based on configured model
  -e "MODEL={model}" \
  -e "MAX_TURNS={max_turns}" \
  -e "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:print_stacktrace=1" \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  vuln-harness-worker:latest
```

### Network policy

Create a Docker bridge network `vuln-harness-net` with:
- Outbound HTTPS (443) to the configured model provider API endpoint(s) only, enforced via iptables rules applied at network creation
- All other egress blocked
- Inter-container communication disabled (`--icc=false` on the daemon or network-level isolation)
- Implementation: custom Docker network + iptables OUTPUT chain rules, or Kubernetes NetworkPolicy in production

### Container timeout

Hard timeout: 30 minutes per container (`docker run --timeout` or orchestrator-side SIGKILL after 1800s). On timeout, collect whatever stdout/stderr exists, mark job as `timeout`, continue queue processing.

---

## Stage 4 — ASAN output parser and triage

### Purpose
Extract structured crash metadata from raw container output. Assign severity tier. Prepare input for validation agent.

### Input
Raw JSON from the agent's final output object.

### ASAN crash taxonomy (severity tiers)

| Tier | Crash type | Examples |
|------|-----------|---------|
| 5 | Control flow hijack | RIP/PC control, arbitrary write to code pointer |
| 4 | Arbitrary write | heap-buffer-overflow WRITE, stack-buffer-overflow WRITE |
| 3 | Arbitrary read | heap-buffer-overflow READ, use-after-free READ |
| 2 | Crash / DoS | NULL dereference, stack overflow, abort |
| 1 | Memory leak only | LeakSanitizer finding, no crash |

### Parser output schema
```json
{
  "job_id": "uuid4",
  "run_id": "uuid4",
  "file": "src/parser.c",
  "line": 247,
  "function": "parse_chunk",
  "vuln_type": "heap-buffer-overflow",
  "crash_rw": "READ",
  "severity_tier": 3,
  "cvss_estimate": 7.5,
  "asan_summary": "heap-buffer-overflow READ of size 4 at 0x... in parse_chunk /src/parser.c:247",
  "reproduction": "echo 'AAAA' | /target/bin/parser -f /dev/stdin",
  "candidate_patch": "--- a/src/parser.c\n+++ b/src/parser.c\n...",
  "agent_confidence": "high",
  "agent_reasoning": "...",
  "raw_agent_output": {...}
}
```

### CVSS estimation heuristic (for human starting point only)
- Tier 5: 9.0–10.0
- Tier 4: 7.5–9.0
- Tier 3: 5.0–7.5
- Tier 2: 3.5–5.0
- Tier 1: 1.0–3.5
Human must confirm or override. System label: `cvss_estimate` not `cvss_score`.

---

## Stage 5 — Validation agent

### Purpose
Filter false positives and minor/inconclusive findings. Prioritize what reaches human review. Modeled directly on Anthropic's "I received the following bug report. Can you please confirm if it's real and interesting?" final pass.

### Implementation
Single `litellm.acompletion()` call per finding candidate. Not a container. Model: configurable, default `anthropic/claude-opus-4-6`.

### Validation prompt template
```
You are a senior security researcher reviewing an automated vulnerability report.
Assess whether this finding is real, exploitable, and worth a human researcher's time.

Finding:
{json_dump_of_parser_output}

Answer the following:
1. Is the ASAN output consistent with a real memory safety bug? (yes/no/uncertain)
2. Is the reproduction case plausible and specific? (yes/no)
3. Is this a meaningful security issue (not just a crash in an error path with no attack surface)? (yes/no/uncertain)
4. Overall verdict: VALIDATE | REJECT | NEEDS_HUMAN_TRIAGE

Respond in JSON:
{
  "asan_real": true | false | null,
  "repro_plausible": true | false,
  "security_meaningful": true | false | null,
  "verdict": "VALIDATE" | "REJECT" | "NEEDS_HUMAN_TRIAGE",
  "reasoning": "..."
}
```

### Routing
- `VALIDATE` → enters human review queue with priority = severity_tier
- `REJECT` → logged as rejected, not shown in human review queue (but accessible in audit log)
- `NEEDS_HUMAN_TRIAGE` → enters human review queue with lower priority, flagged for extra scrutiny

---

## Audit log

### Format
Append-only JSONL file at `{run_dir}/audit.jsonl`. Each line is a JSON object:

```json
{
  "seq": 1,
  "ts": "2026-04-12T14:23:01.234Z",
  "run_id": "uuid4",
  "job_id": "uuid4 | null",
  "event_type": "run_start | job_dispatch | tool_call | llm_call | container_exit | finding_validated | human_review | disclosure_approved",
  "actor": "orchestrator | worker | validation_agent | human:{name}",
  "payload": {...},
  "prev_hash": "sha3-256 of previous line",
  "this_hash": "sha3-256 of this line including prev_hash"
}
```

Hash chaining: each entry's `this_hash` covers the full JSON of that entry including `prev_hash`. This makes the log tamper-evident — any modification breaks the chain from that point forward.

### Governance platform compatibility note
The audit JSONL format and SHA-3 hash chain are designed for direct ingestion by governance platforms. In v1, the file is the artifact — no gateway service is required. Adding governance platform ingestion is a one-day integration: POST each audit entry to the governance endpoint after the local write succeeds.

---

## Human review package

### Generated per validated finding
A markdown file at `{run_dir}/findings/{finding_id}.md` containing:

```markdown
# Finding: {vuln_type} in {project_name}

**Status**: Awaiting human review
**Severity tier**: {tier} / 5
**CVSS estimate**: {cvss_estimate} (unconfirmed)
**File**: {file}:{line} in `{function}`
**Run ID**: {run_id}
**Finding ID**: {finding_id}
**Discovered**: {timestamp}

## Description
{agent_description}

## Reproduction
\`\`\`bash
{reproduction_command}
\`\`\`

## ASAN output
\`\`\`
{asan_output}
\`\`\`

## Candidate patch
\`\`\`diff
{candidate_patch}
\`\`\`

## Agent reasoning
{agent_reasoning}

## Validation agent assessment
- ASAN real: {asan_real}
- Repro plausible: {repro_plausible}
- Security meaningful: {security_meaningful}
- Verdict: {verdict}
- Reasoning: {validation_reasoning}

---

## Reviewer sign-off (required before any external action)

- [ ] Confirmed real vulnerability
- [ ] CVSS confirmed: ____
- [ ] Disclosure approved
- [ ] Patch approved for submission
- [ ] Reviewer: __________________  Date: __________
```

---

## Results store schema (Postgres)

```sql
CREATE TABLE runs (
  run_id        UUID PRIMARY KEY,
  repo_url      TEXT NOT NULL,
  repo_commit   TEXT NOT NULL,
  started_at    TIMESTAMPTZ NOT NULL,
  completed_at  TIMESTAMPTZ,
  status        TEXT NOT NULL,  -- running | completed | aborted
  total_jobs    INT,
  completed_jobs INT,
  failed_jobs   INT,
  total_cost_usd NUMERIC(10,4),
  config        JSONB
);

CREATE TABLE jobs (
  job_id        UUID PRIMARY KEY,
  run_id        UUID REFERENCES runs(run_id),
  file_path     TEXT NOT NULL,
  priority_score INT NOT NULL,
  status        TEXT NOT NULL,  -- pending | running | done | failed | timeout
  started_at    TIMESTAMPTZ,
  completed_at  TIMESTAMPTZ,
  cost_usd      NUMERIC(10,4),
  container_id  TEXT,
  result_raw    JSONB           -- raw agent output
);

CREATE TABLE findings (
  finding_id    UUID PRIMARY KEY,
  job_id        UUID REFERENCES jobs(job_id),
  run_id        UUID REFERENCES runs(run_id),
  vuln_type     TEXT,
  file_path     TEXT,
  line_number   INT,
  function_name TEXT,
  severity_tier INT,
  cvss_estimate NUMERIC(4,1),
  cvss_confirmed NUMERIC(4,1),  -- set by human reviewer
  validation_verdict TEXT,       -- VALIDATE | REJECT | NEEDS_HUMAN_TRIAGE
  human_reviewed BOOLEAN DEFAULT FALSE,
  human_reviewer TEXT,
  reviewed_at   TIMESTAMPTZ,
  disclosure_approved BOOLEAN DEFAULT FALSE,
  -- exploit and patch stored encrypted, never plaintext
  reproduction_enc  BYTEA,      -- AES-256-GCM encrypted
  patch_enc         BYTEA,      -- AES-256-GCM encrypted
  asan_output_enc   BYTEA       -- AES-256-GCM encrypted
);
```

---

## Configuration file (`harness.yaml`)

```yaml
# Target
repo_url: https://github.com/owner/project
repo_commit: main             # branch, tag, or commit SHA
binary_name: parser           # name of compiled binary under /target/bin/
project_name: libfoo
project_description: "A C library for parsing FooBar format files"

# Scan scope
exclude_patterns:
  - "*/test/*"
  - "*/tests/*"
  - "*/vendor/*"
  - "*_generated.*"
  - "*/third_party/*"
max_files_to_scan: 100        # scan top N ranked files, null = all

# Agent
ranking_model: anthropic/claude-opus-4-6
worker_model: anthropic/claude-opus-4-6
validation_model: anthropic/claude-opus-4-6
max_turns_per_worker: 50

# Parallelism
max_parallel_workers: 4       # 4 locally, 50 in production

# Spend limits
max_run_spend_usd: 100.0
max_day_spend_usd: 500.0

# Container
worker_image: vuln-harness-worker:latest
container_timeout_seconds: 1800
worker_memory_gb: 4
worker_cpus: 2

# Storage
redis_url: redis://localhost:6379
postgres_url: postgresql://localhost:5432/vulnharness
run_output_dir: ./runs
findings_encryption_key_env: FINDINGS_ENC_KEY  # name of env var holding AES key
```

---

## Environment variables (never in config file)

```
ANTHROPIC_API_KEY          Required if using Anthropic models.
OPENAI_API_KEY             Required if using OpenAI models.
GOOGLE_API_KEY             Required if using Google models.
FINDINGS_ENC_KEY           Required. 32-byte AES-256 key, base64-encoded.
REDIS_PASSWORD             Optional.
POSTGRES_PASSWORD          Required in production.
WORKER_MODEL_OVERRIDE      Optional. Overrides worker_model for a single run.
```

---

## Worker container architecture

```
┌──────────────────────────────────────────────┐
│  Worker Container (Stage 3)                  │
│                                              │
│  entrypoint.sh                               │
│  ├── Copy source → /workspace/src            │
│  ├── Compile with ASAN (clang)               │
│  └── exec python3 /agent/run.py              │
│                                              │
│  agent/run.py                                │
│  ├── Load system prompt + task prompt         │
│  ├── ReAct loop (agent/loop.py):             │
│  │   ├── litellm.completion(model=...)  ◄──── any provider API
│  │   ├── Parse tool_calls                    │
│  │   ├── Execute: bash() or read_file()      │
│  │   ├── Feed results back → loop            │
│  │   └── No tool_calls → extract verdict     │
│  └── Output JSON verdict to stdout           │
│                                              │
│  Tools available to agent:                   │
│  ├── bash(command) — run shell commands       │
│  └── read_file(path) — read file contents    │
│                                              │
│  Network: egress only to model provider API  │
│  Filesystem: /workspace (rw), /target (ro)   │
└──────────────────────────────────────────────┘
```

## Provider flexibility

```
Config: worker_model                    Env vars (any one):
├── anthropic/claude-opus-4-6    →      ANTHROPIC_API_KEY
├── anthropic/claude-sonnet-4-6  →      ANTHROPIC_API_KEY
├── openai/gpt-4o               →      OPENAI_API_KEY
├── openai/o3                   →      OPENAI_API_KEY
├── gemini/gemini-2.5-pro       →      GOOGLE_API_KEY
├── ollama/llama3               →      (no key, local)
└── any litellm-supported model →      provider's key
```
