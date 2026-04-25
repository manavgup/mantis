# Mantis -- Architecture

## Overview

Mantis is a five-stage pipeline for autonomous vulnerability discovery in C/C++ projects. A Python asyncio orchestrator manages the full lifecycle: ranking source files by vulnerability likelihood, dispatching isolated Docker containers that each run a provider-agnostic LLM agent loop with AddressSanitizer-instrumented binaries, parsing and triaging crash output, validating findings with a separate LLM call, and producing encrypted findings and human-review reports. Every action is logged to a SHA-3 hash-chained audit trail before any subsequent step executes.

The system follows a "build once, scan many" model. ASAN binaries are compiled a single time in a builder container and then mounted read-only into every worker container. This eliminates redundant compilation, reduces per-container runtime by minutes, and ensures every worker tests the same binary. Workers never modify the source or the binary -- they only craft inputs and observe ASAN output.

All LLM calls route through litellm, making the system provider-agnostic. The default model is `anthropic/claude-opus-4-6` but any litellm-compatible model string works (`openai/gpt-4o`, `ollama/llama3`, etc.). Each stage's model is independently configurable via YAML or environment variables, with env vars taking precedence. File ranking defaults to a free, instant static regex ranker -- LLM ranking is available as an alternative.

---

## Pipeline diagram

```
                           TARGET REPOSITORY
                        (C/C++ open-source project)
                                  |
                                  v
   +--------------------------------------------------------------+
   |  STAGE 0 -- BUILD (one-time)                                  |
   |                                                               |
   |  Builder container: Clang + ASAN flags                        |
   |  Auto-detects build system (configure / autotools / cmake /   |
   |  Makefile), compiles with -fsanitize=address -g -O1           |
   |  Collects binaries to host bin/ dir                           |
   |                                                               |
   |  Key files:                                                   |
   |    harness/cli.py (_build_asan_binaries)                      |
   |    worker/entrypoint.sh (build-system detection)              |
   +-------------------------------+-------------------------------+
                                   |  binaries mounted read-only
                                   v
   +--------------------------------------------------------------+
   |  STAGE 1 -- FILE RANKING                                      |
   |                                                               |
   |  Default: Static regex ranker (free, instant, ~2-3s)          |
   |  Alternative: LLM ranker (any litellm model)                  |
   |                                                               |
   |  Scores each source file 1-5 by vulnerability likelihood      |
   |                                                               |
   |  [parser.c]  [decode.c]  [alloc.c]  [utils.c]  [config.h]    |
   |   score: 5    score: 5    score: 4    score: 2    score: 1    |
   +-------------------------------+-------------------------------+
                                   |  file scores
                                   v
   +--------------------------------------------------------------+
   |  STAGE 2 -- JOB DISPATCH                                      |
   |                                                               |
   |  +----------+    +----------------------------------+         |
   |  |  Redis   |<---| Orchestrator (Python asyncio)    |         |
   |  | Priority |    |   * Semaphore (N parallel)       |         |
   |  |  Queue   |    |   * Spend limit check per dequeue|         |
   |  +----------+    |   * Timeout + SIGKILL on expiry  |         |
   |                   +----------------------------------+         |
   +------+----------+----------+----------+-------------------+---+
          |          |          |          |
          v          v          v          v
   +-----------+ +-----------+ +-----------+ +-----------+
   | WORKER    | | WORKER    | | WORKER    | | WORKER    |
   | CONTAINER | | CONTAINER | | CONTAINER | | CONTAINER |
   |           | |           | |           | |           |
   | litellm   | | litellm   | | litellm   | | litellm   |
   | ReAct     | | ReAct     | | ReAct     | | ReAct     |
   | agent     | | agent     | | agent     | | agent     |
   |           | |           | |           | |           |
   | bash      | | bash      | | bash      | | bash      |
   | read_file | | read_file | | read_file | | read_file |
   | GDB/LLDB  | | GDB/LLDB  | | GDB/LLDB  | | GDB/LLDB  |
   | ASAN bin  | | ASAN bin  | | ASAN bin  | | ASAN bin  |
   |           | |           | |           | |           |
   | Egress:   | | Egress:   | | Egress:   | | Egress:   |
   | LLM API   | | LLM API   | | LLM API   | | LLM API   |
   | only      | | only      | | only      | | only      |
   +-----+-----+ +-----+-----+ +-----+-----+ +-----+-----+
         |             |             |             |
         +------+------+------+------+
                |
                v
   +--------------------------------------------------------------+
   |  STAGE 4 -- ASAN PARSER + TRIAGE                              |
   |                                                               |
   |  Extract crash metadata -> Assign severity tier -> Est. CVSS  |
   |                                                               |
   |  Tier 5: Control flow hijack (RIP/PC control)   CVSS 9.0-10  |
   |  Tier 4: Arbitrary write (heap-buffer-overflow)  CVSS 7.5-9.0 |
   |  Tier 3: Arbitrary read (use-after-free READ)    CVSS 5.0-7.5 |
   |  Tier 2: Crash / DoS (null deref, stack overflow) CVSS 3.5-5  |
   |  Tier 1: Memory leak only                        CVSS 1.0-3.5 |
   +-------------------------------+-------------------------------+
                                   |
                                   v
   +--------------------------------------------------------------+
   |  STAGE 5 -- VALIDATION AGENT                                  |
   |                                                               |
   |  Separate LLM call per finding (litellm, provider-agnostic):  |
   |  "Is the ASAN output real? Repro plausible? Meaningful?"      |
   |                                                               |
   |  +----------+    +--------------------+    +----------+       |
   |  | VALIDATE |    | NEEDS_HUMAN_TRIAGE |    |  REJECT  |       |
   |  | -> store |    | -> store (flagged) |    |  -> log  |       |
   |  +----+-----+    +---------+----------+    +----+-----+       |
   +-------+-----------------+--+--------------------+-------------+
           |                 |                       |
           v                 v                       v
   +--------------------------------------------------------------+
   |                                                               |
   |  +----------------+ +----------------+ +-------------------+  |
   |  | FINDINGS STORE | | AUDIT LOG      | | HUMAN REVIEW PKG  |  |
   |  | (Postgres)     | | (JSONL)        | | (Markdown/finding)|  |
   |  |                | |                | |                   |  |
   |  | AES-256-GCM    | | SHA-3 hash     | | Description       |  |
   |  |   encrypted    | |   chained      | | Reproduction      |  |
   |  | Exploit code   | | Every action   | | ASAN output       |  |
   |  |   never in     | |   logged BEFORE| | Candidate patch   |  |
   |  |   plaintext    | |   execution    | | Reviewer sign-off |  |
   |  +----------------+ +----------------+ +-------------------+  |
   |                                                               |
   |  HUMAN SIGN-OFF REQUIRED BEFORE ANY EXTERNAL ACTION (P2)     |
   +--------------------------------------------------------------+
```

---

## Stage 0 -- Build (pre-compilation)

**What it does**: Compiles the target project once with Clang and AddressSanitizer flags (`-fsanitize=address -g -O1 -fno-omit-frame-pointer`). The builder container auto-detects the build system (configure, autotools, cmake, or plain Makefile), applies optional `configure_flags` from config, and copies all resulting executables to a host directory.

**Key files**:
- `harness/cli.py` -- `_build_asan_binaries()` launches the builder container, `_BUILD_SCRIPT` is the in-container build logic
- `worker/entrypoint.sh` -- fallback: if no pre-compiled binaries are mounted, the entrypoint compiles from source

**Design decisions**:
- **Build once, scan many**: Compilation takes minutes for large projects (e.g. FFmpeg). Building once and mounting the result read-only into every worker container eliminates this per-container overhead.
- **Build-system auto-detection**: The builder tries configure, autotools (autoreconf), cmake, and Makefile in order. `configure_flags` in config allows project-specific build options (e.g. FFmpeg's `--extra-cflags`).
- **Fallback compilation**: If no `--bin-dir` is supplied to `vuln-harness run`, the pipeline auto-builds before dispatch. If pre-compiled binaries are mounted into the worker, the entrypoint skips compilation entirely.

---

## Stage 1 -- File ranking

**What it does**: Scores every C/C++ source file (`.c`, `.cpp`, `.h`, `.cc`, `.cxx`, `.hpp`) from 1 (lowest risk) to 5 (highest risk) based on vulnerability likelihood. Files are sorted by score descending and optionally capped by `max_files_to_scan`.

**Key files**:
- `harness/static_ranker.py` -- default static regex ranker
- `harness/ranker.py` -- LLM-based ranker (alternative), routing logic, `RankedFile` dataclass, `_enumerate_source_files()`

**Design decisions**:
- **Static ranker as default** (`ranking_strategy: static`): Counts unsafe calls (`strcpy`, `sprintf`, `gets`, etc.), input sources (`fread`, `recv`, `fgets`), memory management (`malloc`, `free`, `mmap`), pointer arithmetic, and `memcpy`. Applies multipliers for source+sink combinations and memory+pointer combinations. Adds path-based bonuses for high-risk directory names (`parser`, `codec`, `decode`, `compress`, `crypt`) and penalties for test/doc/example directories. Runs in ~2-3 seconds on 3000+ files with zero API cost.
- **LLM ranker as alternative** (`ranking_strategy: llm`): Sends file lists to any litellm model in batches of 100, asks for JSON-scored results. Useful when static heuristics are insufficient for a particular codebase.
- **Normalization**: Raw scores are normalized to a 1-5 integer scale regardless of backend.

---

## Stage 2 -- Job dispatch

**What it does**: Enqueues ranked files into a Redis sorted set (priority = vulnerability score), then dispatches Docker worker containers with concurrency controlled by an asyncio semaphore. Checks spend limits before each dequeue. Kills containers that exceed the configured timeout.

**Key files**:
- `harness/queue.py` -- `enqueue_jobs()`, `dequeue_job()` (ZPOPMAX for highest-priority-first), `get_run_spend()`, `increment_spend()`
- `harness/dispatcher.py` -- `dispatch_run()` (semaphore loop), `_run_container()` (docker run command assembly)

**Design decisions**:
- **Priority queue**: Redis sorted sets with ZPOPMAX ensure the highest-scored files are processed first, so if a run is interrupted or hits a spend limit, the most promising files have already been scanned.
- **Spend gating**: Before every dequeue, the dispatcher checks `get_run_spend()` against `max_run_spend_usd`. If the limit is reached, dispatch stops and logs a `spend_limit_reached` audit event.
- **Timeout enforcement**: Each container gets `container_timeout_seconds` (default 1800s / 30 min). On timeout, the container is killed via `docker kill` and the job is marked `timeout`.

---

## Stage 3 -- Worker containers (ReAct agent loop)

**What it does**: Each container receives one source file to analyze. The entrypoint renders a Jinja2 task prompt, copies source to a writable tmpfs, sets up the ASAN binary on PATH, and invokes the Python ReAct agent loop. The agent reads code, forms vulnerability hypotheses, crafts malformed inputs, runs the ASAN binary, and reads crash output. If it triggers a crash, it reports a structured JSON verdict to stdout.

**Key files**:
- `worker/agent/loop.py` -- `agent_loop()`: the core ReAct loop using `litellm.completion()` with tool_choice="auto"
- `worker/agent/tools.py` -- two tools: `bash` (execute shell commands) and `read_file` (read file contents)
- `worker/agent/run.py` -- entry point: reads env vars, loads prompts, calls `agent_loop()`, prints JSON verdict to stdout
- `worker/prompts/worker-task.txt.j2` -- Jinja2 task prompt template
- `worker/entrypoint.sh` -- container bootstrap (build detection, prompt rendering, agent invocation)
- `worker/Dockerfile` -- Ubuntu 24.04 base, Clang, GDB, LLDB, Valgrind, Python 3, litellm

**Design decisions**:
- **Custom ReAct loop, not Claude Code**: The agent is a straightforward litellm completion loop with tool definitions. This makes it provider-agnostic (any model that supports tool use works) and keeps the dependency surface minimal.
- **Two tools only**: `bash` (120s timeout per command) and `read_file`. The agent uses bash for everything: compiling inputs, running binaries, invoking GDB, inspecting ASAN output.
- **Stdout reserved for verdict**: All build and status output goes to stderr. Only the final JSON verdict is printed to stdout, which the orchestrator parses.
- **Token and cost tracking**: The loop tracks `prompt_tokens`, `completion_tokens`, and `response_cost` from litellm on every turn. These are included in the verdict metadata.

---

## Stage 4 -- ASAN parser and triage

**What it does**: Parses agent JSON output and container stderr for AddressSanitizer crash signatures. Extracts vulnerability type, read/write direction, source location (function, file, line). Assigns a severity tier (1-5) and estimates CVSS based on the tier.

**Key files**:
- `harness/parser.py` -- `parse_result()`, severity/CVSS maps, ASAN regex patterns

**Severity tiers**:

| Tier | Condition | CVSS range |
|------|-----------|------------|
| 5 | Control flow hijack (RIP/PC control) | 9.0 - 10.0 |
| 4 | Arbitrary write (heap-buffer-overflow WRITE, use-after-free WRITE) | 7.5 - 9.0 |
| 3 | Arbitrary read (heap-buffer-overflow READ, use-after-free READ) | 5.0 - 7.5 |
| 2 | Crash / DoS (null dereference, stack overflow) | 3.5 - 5.0 |
| 1 | Memory leak only | 1.0 - 3.5 |

**Design decisions**:
- **Regex-based extraction**: ASAN output has a predictable format. Regex extraction is reliable and requires no LLM call.
- **Conservative CVSS**: The estimate is the midpoint of the tier's range. Human reviewers must confirm or override (P7).

---

## Stage 5 -- Validation agent

**What it does**: A separate LLM call reviews each finding and renders one of three verdicts: `VALIDATE`, `REJECT`, or `NEEDS_HUMAN_TRIAGE`. The prompt asks three specific questions: (1) is the ASAN output consistent with a real bug, (2) is the reproduction plausible, (3) is this a meaningful security issue.

**Key files**:
- `harness/validator.py` -- `validate_finding()`, `VALIDATION_PROMPT` template, `ValidationResult` dataclass

**Design decisions**:
- **Separate LLM call**: The validation model is independently configurable (`validation_model` in config). Using a separate call prevents the worker agent from self-validating its own findings.
- **Provider-agnostic**: Uses the same `call_llm()` wrapper as all other LLM calls. Any litellm model works.
- **Three verdicts**: VALIDATE (real, store and report), REJECT (log and discard), NEEDS_HUMAN_TRIAGE (store but flag for manual review).

---

## Container security model

Every worker container is launched with the following security controls:

```
docker run --rm
    --memory {worker_memory_gb}g          # Memory limit (default 4 GB)
    --cpus {worker_cpus}                  # CPU limit (default 2)
    --tmpfs /tmp:size=4g                  # Writable tmpfs for /tmp
    -v {repo}:/target/src:ro              # Source mounted read-only
    -v {bin}:/target/bin:ro               # Pre-compiled binaries read-only
    --security-opt no-new-privileges      # No privilege escalation
    --cap-drop ALL                        # Drop all Linux capabilities
    {worker_image}
```

| Control | Implementation | Purpose |
|---------|---------------|---------|
| Non-root user | `USER researcher` (UID 1001) in Dockerfile | No root inside container |
| All capabilities dropped | `--cap-drop ALL` | No privileged syscalls |
| No privilege escalation | `--security-opt no-new-privileges` | Blocks setuid/setgid |
| Read-only source mount | `-v {repo}:/target/src:ro` | Agent cannot modify source |
| Read-only binary mount | `-v {bin}:/target/bin:ro` | Agent cannot modify binaries |
| tmpfs workspace | `--tmpfs /tmp:size=4g` | Writable area is ephemeral and size-limited |
| Memory limit | `--memory {worker_memory_gb}g` | Prevents OOM of host |
| CPU limit | `--cpus {worker_cpus}` | Prevents CPU starvation |
| Network egress allowlist | iptables on bridge network | Only LLM API endpoints reachable |
| No inter-container comms | `enable_icc=false` on Docker bridge | Containers cannot talk to each other |
| Ephemeral lifecycle | `--rm` flag, fresh per job | No state persists between runs |

**Network isolation** (`scripts/setup-network.sh`): Creates a Docker bridge network with ICC disabled and iptables rules that allow egress only to:
- `api.anthropic.com:443`
- `api.openai.com:443`
- `generativelanguage.googleapis.com:443`

The allowed domains are configurable via `ALLOWED_API_DOMAINS` env var. All other egress is silently dropped. DNS is allowed for initial resolution only.

---

## Hypothesis-test loop (inside each worker)

```
                +-----------------------------+
                |  AGENTIC HYPOTHESIS-TEST     |
                |  LOOP (inside each worker)   |
                |                              |
                |  +------------------------+  |
                |  | 1. Read source code     |  |
                |  +----------+-------------+  |
                |             v                |
                |  +------------------------+  |
                |  | 2. Form hypothesis      |  |
                |  |    "integer overflow in  |  |
                |  |     image dimensions"    |  |
                |  +----------+-------------+  |
                |             v                |
                |  +------------------------+  |
                |  | 3. Craft malformed input |  |
                |  |    (python3 script)      |  |
                |  +----------+-------------+  |
                |             v                |
                |  +------------------------+  |
                |  | 4. Run ASAN binary      |  |
                |  |    with crafted input   |  |
                |  +----------+-------------+  |
                |             v                |
                |  +------------------------+  |
                |  | 5. Read ASAN output     |--+--> CRASH? -> Report
                |  |    Did it crash?        |  |
                |  +----------+-------------+  |
                |             | No             |
                |             v                |
                |  +------------------------+  |
                |  | 6. Next hypothesis      |--+--> Loop back to 2
                |  +------------------------+  |
                |                              |
                +------------------------------+
```

The agent has up to `max_turns_per_worker` (default 50) LLM turns. Each turn may invoke one or more tools (`bash`, `read_file`). The agent reports a JSON verdict with fields: `verdict`, `vuln_type`, `file`, `line`, `function`, `asan_output`, `reproduction`, `candidate_patch`, `confidence`, `reasoning`.

---

## Data flow

```
Source files  ->  Scores (1-5)  ->  Redis priority queue
                                        |
                          +-------------+
                          v
                    Worker containers
                          |
                    JSON verdict (stdout) + ASAN traces (stderr)
                          |
                          v
                    Parsed findings (ParsedFinding)
                          |
                          v
                    Validation verdicts (VALIDATE / REJECT / NEEDS_HUMAN_TRIAGE)
                          |
                   +------+------+
                   |             |
                   v             v
            Encrypted        Markdown
            Postgres         human-review
            store            reports
                   |
                   v
            Human review + sign-off (P2)
```

Each stage writes to the audit log before acting. The audit log is the system of record: JSONL format, SHA-3 hash-chained, tamper-evident, designed for governance platform ingestion.

---

## Cost tracking

Spend is tracked at two levels:

- **Per-run**: `max_run_spend_usd` (default $100). Before each job dequeue, the dispatcher reads `spend:{run_id}` from Redis. If the current spend meets or exceeds the limit, dispatch stops immediately and a `spend_limit_reached` event is logged.
- **Per-day**: `max_day_spend_usd` (default $500). Provides a global safety net across multiple runs.

The worker agent loop tracks cost internally via litellm's `response_cost` metadata on each completion call. Token counts (`input_tokens`, `output_tokens`) and cost are included in every `llm_call` audit entry from both the orchestrator (ranking, validation) and workers.

All LLM calls are also logged to the audit trail with model name, token counts, and cost, providing a complete cost breakdown per stage. The CLI command `vuln-harness cost --run-id <uuid>` parses the audit log and prints a per-stage cost summary.

---

## Audit and encryption

**Audit log** (`harness/audit.py`): Append-only JSONL, one entry per action. Each entry includes a SHA-3 hash of its contents and the hash of the previous entry, forming a tamper-evident chain. Writes are synchronous with file locking (`fcntl.LOCK_EX`). If a write fails, the run fails (P3). Chain integrity is verifiable via `vuln-harness audit-verify`.

**Findings encryption** (`harness/crypto.py`): Reproduction steps, candidate patches, and ASAN output are encrypted with AES-256-GCM before storage in Postgres. The encryption key is loaded from the `FINDINGS_ENC_KEY` environment variable (base64-encoded, 32-byte key). Exploit code is never stored in plaintext (P8).

---

## Key file reference

| Component | Path | Purpose |
|-----------|------|---------|
| CLI | `harness/cli.py` | Commands: `run`, `build`, `rank`, `review`, `approve`, `audit-verify`, `cost` |
| Config | `harness/config.py` | Pydantic-settings model, YAML + env var loading |
| Static ranker | `harness/static_ranker.py` | Default file ranker (regex, free) |
| LLM ranker | `harness/ranker.py` | Alternative file ranker (litellm) |
| Queue | `harness/queue.py` | Redis sorted set job queue |
| Dispatcher | `harness/dispatcher.py` | Container launch, concurrency, timeout |
| Parser | `harness/parser.py` | ASAN output parsing, severity tiers |
| Validator | `harness/validator.py` | LLM-based finding validation |
| Findings store | `harness/findings.py` | Postgres storage, report generation |
| Audit log | `harness/audit.py` | SHA-3 hash-chained JSONL |
| Encryption | `harness/crypto.py` | AES-256-GCM for findings at rest |
| Agent loop | `worker/agent/loop.py` | ReAct loop via litellm |
| Agent tools | `worker/agent/tools.py` | bash, read_file tool implementations |
| Agent entry | `worker/agent/run.py` | Worker container entry point |
| Task prompt | `worker/prompts/worker-task.txt.j2` | Jinja2 prompt template |
| Dockerfile | `worker/Dockerfile` | Worker image (Ubuntu 24.04, Clang, GDB) |
| Entrypoint | `worker/entrypoint.sh` | Build detection, ASAN compile, agent invoke |
| Network setup | `scripts/setup-network.sh` | iptables egress allowlist |
| Constitution | `01-constitution.md` | P1-P8 non-negotiable principles |
