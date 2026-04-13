# Tasks
# IBM Enterprise Vulnerability Harness (vuln-harness)
# Implementation order for Claude Code

## How to use this file

Work through tasks in order. Each task is self-contained and testable before moving on.
Do not skip tasks or reorder them — later tasks depend on earlier ones.
After completing each task, run its verification step before marking done.

---

## Phase 0 — Project scaffolding

### Task 0.1 — Initialize project structure
Create the full directory tree from the plan:
```
vuln-harness/
  harness/
  worker/prompts/
  migrations/versions/
  tests/unit/
  tests/integration/
  tests/fixtures/
```
Create empty `__init__.py` in `harness/`.
Create `.env.example` with all env vars from spec (values as placeholders).
Create `harness.yaml.example` with all fields from spec (values as examples).
Create `README.md` with one-paragraph project description and quickstart.

**Verify**: `find vuln-harness -type f | sort` shows expected tree.

### Task 0.2 — Create `pyproject.toml`
Exact content from plan. Use `uv` for dependency management.
Run `uv sync` to create lockfile.

**Verify**: `uv run python --version` shows 3.12+. `uv run python -c "import anthropic"` succeeds.

### Task 0.3 — Create `docker-compose.yml`
Exact content from plan. Parameterized with `${POSTGRES_PASSWORD}`.

**Verify**: `docker compose up -d` starts Redis and Postgres. `docker compose ps` shows both healthy.

---

## Phase 1 — Core infrastructure

### Task 1.1 — `harness/config.py`
Implement `Config` class using `pydantic-settings`. Load from `harness.yaml` (path configurable via `HARNESS_CONFIG` env var, default `./harness.yaml`). All fields from spec with types and defaults. Fail-fast validation: raise `SystemExit` with clear message if `ANTHROPIC_API_KEY` or `FINDINGS_ENC_KEY` missing. Add `model_config = SettingsConfigDict(yaml_file="harness.yaml")`.

Write a unit test `tests/unit/test_config.py` that:
- Loads a minimal valid config from a temp yaml file
- Asserts a missing required field raises on construction
- Asserts missing env vars raise on construction

**Verify**: `uv run pytest tests/unit/test_config.py -v` passes.

### Task 1.2 — `harness/audit.py`
Implement `AuditLog` class with SHA-3 hash chaining as specified.
- Use `hashlib.sha3_256`
- Use `fcntl.flock` for exclusive write lock
- First entry has `prev_hash = "genesis"`
- `seq` is monotonically incrementing integer read from last line
- All timestamps in ISO 8601 UTC with milliseconds

Write unit tests:
- Single entry written and readable
- Two entries: second entry's `prev_hash` matches first entry's `this_hash`
- Tampered entry (modify a field) causes hash mismatch on verify
- Concurrent writes from two threads do not corrupt file (use `threading.Thread`)

Add `verify_chain(path: Path) -> bool` function that reads all entries and validates the full chain.

**Verify**: `uv run pytest tests/unit/test_audit.py -v` passes.

### Task 1.3 — `harness/crypto.py`
Implement `encrypt(plaintext: str, key: bytes) -> bytes` and `decrypt(ciphertext: bytes, key: bytes) -> str`.
Use `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
Random 12-byte nonce prepended to ciphertext output.
Add `load_key_from_env(env_var: str) -> bytes` that base64-decodes the env var value and validates it is exactly 32 bytes.

Write unit tests:
- Encrypt then decrypt returns original plaintext
- Different nonces each call (encrypt same string twice, outputs differ)
- Wrong key raises exception on decrypt
- Key length != 32 bytes raises on `load_key_from_env`

**Verify**: `uv run pytest tests/unit/test_crypto.py -v` passes.

### Task 1.4 — Database migrations (`migrations/`)
Set up Alembic. Create `migrations/env.py` pointed at `harness/models.py` (create a minimal SQLAlchemy `Base` with the three tables: `runs`, `jobs`, `findings` — schema exactly as in spec). Create initial migration `001_initial_schema.py`.

**Verify**: `uv run alembic upgrade head` against local Postgres creates all three tables. `uv run alembic current` shows `001`.

---

## Phase 2 — Stage 1 (file ranking)

### Task 2.1 — `harness/ranker.py`
Implement `rank_files()` as specified. Use `anthropic.AsyncAnthropic`. Batch files in groups of 200. Parse model response to extract `(path, score, reason)` triples. If a file's score is missing from response, default to 3 and log warning. Sort by score descending. Write result JSON to `{run_dir}/file_rankings.json`. Log one `llm_call` audit event per batch call.

The file enumeration logic: walk the repo path, collect `.c .cpp .h .cc .cxx .hpp` files, apply exclusion glob patterns, return sorted list.

Write unit tests (mock `anthropic.AsyncAnthropic`):
- 10 files → correct sorted order returned
- Missing score in response → defaults to 3
- API failure → retries 3 times, then raises
- Exclusion patterns applied correctly

Add a fixture `tests/fixtures/sample_ranking_response.json` with a realistic model response for 5 files.

**Verify**: `uv run pytest tests/unit/test_ranker.py -v` passes.

### Task 2.2 — CLI `rank` subcommand
Implement `vuln-harness rank --config harness.yaml` in `harness/cli.py`.
- Creates a run directory under `{run_output_dir}/{run_id}/`
- Calls `rank_files()`
- Pretty-prints ranked files table to stdout: rank | score | path | reason
- Prints total files, excluded files, cost

**Verify**: With a real `harness.yaml` pointing to a real C repo (e.g. sqlite), `vuln-harness rank` prints a sensible ranked list. Top files should be parsers, I/O handlers, not headers or test files.

---

## Phase 3 — Stage 2 (queue and dispatch)

### Task 3.1 — `harness/queue.py`
Implement all queue functions using `redis.asyncio`. Use Redis sorted sets for priority queue. Use Redis hashes for job records. Use Redis string with `INCRBYFLOAT` for spend tracking. All operations are async.

Write integration tests `tests/integration/test_queue.py` (requires Redis running):
- Enqueue 5 jobs → dequeue returns highest priority first
- `update_job_status` correctly updates hash fields
- `increment_spend` is accurate across concurrent increments
- `get_queue_depth` returns correct count

**Verify**: `uv run pytest tests/integration/test_queue.py -v` (with Redis running) passes.

### Task 3.2 — `harness/dispatcher.py`
Implement `dispatch_run()` async function. Maintains asyncio semaphore at `max_parallel_workers`. For each job:

1. Check spend limit before dispatch — if exceeded, log and break loop
2. Dequeue next job from queue
3. Build docker run command (exact flags from spec)
4. Write `job_dispatch` audit entry
5. Launch container via `asyncio.create_subprocess_exec`
6. Await completion with timeout (SIGKILL on timeout)
7. Collect stdout, stderr
8. Write `container_exit` audit entry (include exit code, stdout length)
9. Return (job_id, stdout, stderr, exit_code) to caller

The dispatcher itself does not parse or validate — it just runs containers and returns raw output. Parsing and validation are separate concerns called by the main `run` command.

Write integration tests (requires Docker):
- Dispatch a container that exits 0 immediately → job marked done
- Dispatch a container that exits 1 → job marked failed
- Dispatch a container that runs > timeout → job marked timeout, SIGKILL sent
- Semaphore respected: with max_parallel=2 and 4 jobs, only 2 run simultaneously

**Verify**: `uv run pytest tests/integration/test_dispatcher.py -v` passes.

---

## Phase 4 — Stage 3 (worker container)

### Task 4.1 — `worker/prompts/worker-system.txt`
Exact content from specification. No changes.

### Task 4.2 — `worker/prompts/worker-task.txt.j2`
Jinja2 template. Variables: `file_path`, `project_name`, `project_description`, `binary_name`, `max_turns`. Exact content from specification.

### Task 4.3 — `worker/entrypoint.sh`
Shell script (bash). Steps exactly as in specification:
1. `set -euo pipefail`
2. Print "=== vuln-harness worker starting ===" with timestamp
3. Render task prompt from Jinja2 template using Python one-liner
4. `cd /target/src`
5. `git submodule update --init --recursive 2>/dev/null || true`
6. Compile with ASAN flags, capturing stderr; on failure write JSON `{"verdict":"not_found","description":"Compilation failed","reasoning":"..."}` to stdout and exit 1
7. Set `ASAN_OPTIONS`
8. Print "=== invoking claude-code ==="
9. Execute `claude --print ...` (exact flags from spec, task prompt from rendered template)

Make it executable: `chmod +x worker/entrypoint.sh`.

### Task 4.4 — `worker/Dockerfile`
Exact content from plan. Build and verify:
```bash
docker build -t vuln-harness-worker:latest ./worker/
```

**Verify**: `docker run --rm vuln-harness-worker:latest claude --version` prints a claude version string. `docker run --rm vuln-harness-worker:latest clang --version` prints clang version.

### Task 4.5 — Manual end-to-end smoke test
This is a manual verification step, not automated.

Target: clone `https://github.com/mozilla/zlib` (small, C, has known ASAN-triggerable behavior).

Steps:
```bash
cd /tmp && git clone https://github.com/madler/zlib && cd zlib
# compile with ASAN outside container first to verify
CC=clang CFLAGS="-fsanitize=address -g -O1" ./configure && make

# Now run one worker container against one file
docker run --rm \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -v /tmp/zlib:/target/src:ro \
  -v /tmp/zlib:/target/bin:ro \
  -e WORKER_MODEL=claude-opus-4-6 \
  -e MAX_TURNS=20 \
  -e FILE_PATH=inflate.c \
  -e PROJECT_NAME=zlib \
  -e PROJECT_DESCRIPTION="zlib compression library" \
  -e BINARY_NAME=minigzip \
  vuln-harness-worker:latest 2>&1 | tee /tmp/worker-output.json
```

**Verify**: Output is valid JSON. `verdict` field is present. Agent made multiple bash calls (visible in Claude Code's turn output). Run completed without container crash.

---

## Phase 5 — Stages 4 and 5 (parser and validator)

### Task 5.1 — `harness/parser.py`
Implement `parse_result(agent_json: dict, stderr: str) -> ParsedFinding`. Apply ASAN patterns from plan. Assign severity tier. Compute CVSS estimate. Return `ParsedFinding` dataclass with all fields from spec's parser output schema.

Add fixture `tests/fixtures/sample_asan_output.txt` with realistic ASAN heap-buffer-overflow output.
Add fixture `tests/fixtures/sample_agent_response.json` with realistic agent JSON including `verdict: "found"`, `asan_output`, `reproduction`, etc.

Write unit tests:
- heap-buffer-overflow READ → tier 3, correct cvss range
- heap-buffer-overflow WRITE → tier 4
- use-after-free → tier 3
- null-dereference → tier 2
- `verdict: "not_found"` → returns None (no finding to store)
- Missing ASAN output in agent response → falls back to parsing stderr

**Verify**: `uv run pytest tests/unit/test_parser.py -v` passes.

### Task 5.2 — `harness/validator.py`
Implement `validate_finding(finding: ParsedFinding, config: Config, audit: AuditLog) -> ValidationResult`. Direct `anthropic.AsyncAnthropic` call. Parse JSON response. Return `ValidationResult` dataclass with `verdict`, `asan_real`, `repro_plausible`, `security_meaningful`, `reasoning`. Log `llm_call` audit event.

Write unit tests (mock anthropic client):
- `VALIDATE` verdict → correctly parsed
- `REJECT` verdict → correctly parsed
- Model returns malformed JSON → raise with clear message
- API failure → retry 3 times then raise

**Verify**: `uv run pytest tests/unit/test_validator.py -v` passes.

---

## Phase 6 — Findings store and reports

### Task 6.1 — `harness/findings.py`
Implement:
- `store_finding(finding: ParsedFinding, validation: ValidationResult, run_id: str, job_id: str) -> str` — inserts to Postgres, encrypts sensitive fields, returns `finding_id`
- `generate_report(finding_id: str) -> str` — renders Jinja2 template from spec, returns markdown string
- `list_pending_review(run_id: str) -> list[FindingSummary]` — returns findings awaiting human review ordered by severity_tier desc
- `record_human_review(finding_id: str, reviewer: str, cvss_confirmed: float, approve_disclosure: bool) -> None` — updates Postgres, writes `human_review` audit event

Write unit tests (mock asyncpg):
- `store_finding` encrypts `reproduction_enc`, `patch_enc`, `asan_output_enc`
- `generate_report` produces markdown with all required sections present
- `record_human_review` sets `human_reviewed=True` and logs audit event

**Verify**: `uv run pytest tests/unit/test_findings.py -v` passes.

---

## Phase 7 — CLI and full pipeline

### Task 7.1 — Complete `harness/cli.py`
Implement all CLI subcommands from plan:
- `run` — full pipeline end-to-end
- `rank` — stage 1 only (already done in 2.2)
- `review` — list findings awaiting review, formatted table
- `approve` — record human sign-off
- `audit-verify` — verify hash chain, print result
- `cost` — print cost breakdown per stage

The `run` command:
1. Load config
2. Initialize audit log
3. Clone repo (or use local path if `repo_url` is a local path)
4. Call `rank_files()` → priority queue
5. Enqueue jobs to Redis
6. Call `dispatch_run()` (async) — for each completed container:
   a. Call `parse_result()`
   b. If finding: call `validate_finding()`
   c. If validated: call `store_finding()`, generate and write report markdown
7. Print summary: jobs run, findings found, validated, rejected, total cost

**Verify**: `vuln-harness --help` shows all subcommands. `vuln-harness run --help` shows all options.

### Task 7.2 — Full local pipeline test
Run the complete pipeline against a real target. Use sqlite (small, C, OSS-Fuzz corpus):
```bash
cat > harness.yaml << EOF
repo_url: https://github.com/sqlite/sqlite
repo_commit: master
binary_name: sqlite3
project_name: SQLite
project_description: "SQLite embedded SQL database engine in C"
exclude_patterns:
  - "*/test/*"
  - "*/ext/lemon/*"
max_files_to_scan: 10
max_parallel_workers: 2
max_run_spend_usd: 20.0
worker_model: claude-opus-4-6
postgres_url: postgresql://harness:${POSTGRES_PASSWORD}@localhost:5432/vulnharness
run_output_dir: ./runs
EOF

vuln-harness run --config harness.yaml
```

**Verify**:
- Run completes without unhandled exceptions
- `runs/` directory contains `file_rankings.json` and `audit.jsonl`
- `audit.jsonl` has entries for `run_start`, `job_dispatch`, `container_exit`, `llm_call`
- `vuln-harness audit-verify --run-id <uuid>` prints "Chain valid"
- `vuln-harness cost --run-id <uuid>` prints itemized cost under $20
- At least one finding produced (even if validation rejects it — `audit.jsonl` should show the validation call)
- `vuln-harness review --run-id <uuid>` shows findings table

---

## Phase 8 — Hardening and production readiness

### Task 8.1 — Network isolation enforcement
Write a shell script `scripts/setup-network.sh` that:
1. Creates `vuln-harness-net` Docker bridge network
2. Adds iptables rules blocking all egress from the bridge except to `api.anthropic.com:443`
3. Prints the rules applied for verification
4. Is idempotent (safe to run multiple times)

Add a corresponding `scripts/teardown-network.sh` that removes the rules and network.

Include a `--dry-run` flag that prints commands without executing.

**Verify**: With network isolation active, a container on `vuln-harness-net` can reach `api.anthropic.com` but `curl https://example.com` times out.

### Task 8.2 — Spend limit enforcement test
Verify spend limit actually stops dispatch:
- Set `max_run_spend_usd: 0.01` (effectively zero)
- Run pipeline
- Assert dispatcher logs "spend limit reached" and stops after first container

**Verify**: `audit.jsonl` contains a `spend_limit_reached` event. No more than 2 containers were dispatched.

### Task 8.3 — `vuln-harness audit-verify` correctness test
- Run a pipeline, collect `audit.jsonl`
- Manually corrupt one character in the middle of the file
- Run `audit-verify`
- Assert it reports the corrupted entry's sequence number

**Verify**: Output says "Chain broken at entry seq=N".

### Task 8.4 — README.md
Write complete README covering:
1. What this is and what it does (2 paragraphs)
2. Prerequisites (Docker, Python 3.12+, uv, API key, OpenShift for production)
3. Local quickstart (5 steps: clone, install, docker compose up, configure yaml, run)
4. Architecture overview (brief, refers to specs/ for detail)
5. Constitution summary (P1–P8 one-liners)
6. CLI reference (all subcommands with examples)
7. Moving to production (3 paragraphs: OpenShift, network policy, watsonx.governance)
8. Cost expectations (per-file estimates, per-run estimates)

---

## Implementation notes for Claude Code

- Use `uv` exclusively for Python package management. Never use `pip` directly.
- All async code uses `asyncio`. No threads except in `audit.py` write lock.
- All Anthropic API calls use the official `anthropic` Python SDK, not raw HTTP.
- Claude Code CLI is invoked via `asyncio.create_subprocess_exec`, not `subprocess.run` (blocking).
- All file paths use `pathlib.Path`, never string concatenation.
- All datetime objects are timezone-aware UTC. Use `datetime.now(timezone.utc)`.
- All UUIDs use `uuid.uuid4()`. Never use sequential IDs for security-relevant identifiers.
- Sensitive values (API key, enc key) must never appear in log output. Use `***REDACTED***` if logging config.
- Every function that calls the Anthropic API must log to the audit log before returning.
- The `findings` table's encrypted columns must never be decrypted in a SELECT * query. Always explicit column selection.
- All tests use `pytest`. Async tests use `pytest-asyncio` with `asyncio_mode = "auto"` in `pyproject.toml`.
- Ruff for linting, mypy for type checking. Both must pass before a phase is considered done.
