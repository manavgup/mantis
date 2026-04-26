# Mantis Threat Model

**Document version**: 1.0
**Last updated**: 2026-04-25
**Methodology**: STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
**Scope**: The Mantis system itself -- not the target software it scans

---

## 1. System Overview

Mantis is an autonomous vulnerability discovery harness that runs LLM-powered security research agents inside isolated Docker containers against AddressSanitizer-instrumented C/C++ binaries. The system consists of:

- **Orchestrator** (Python 3.12+): CLI-driven pipeline controller running on the operator's host
- **Worker containers** (Docker): Ephemeral, isolated environments running ReAct agent loops via litellm
- **Redis**: Job queue and spend tracking (local dev) or Postgres (production)
- **Postgres**: Findings store with encrypted sensitive columns (AES-256-GCM)
- **Audit log**: Append-only SHA-3 hash-chained JSONL file on local filesystem
- **LLM provider API**: External service (Anthropic, OpenAI, Google, or local Ollama)
- **Network layer**: Docker bridge network with iptables egress rules

---

## 2. Asset Inventory

| Asset | Type | Classification | Location | Integrity Mechanism |
|-------|------|---------------|----------|-------------------|
| Audit log (JSONL) | Data | Compliance | `{run_dir}/audit.jsonl` | SHA-3 hash chain (`harness/audit.py:81-83`) |
| Findings store | Data | Internal/Restricted | Postgres `findings` table | AES-256-GCM for sensitive columns (`harness/crypto.py:13-18`) |
| Exploit code / PoC | Data | Restricted | Postgres `reproduction_enc` column | AES-256-GCM encrypted (`harness/findings.py:125`) |
| Worker containers | Compute | Ephemeral | Docker runtime | `--cap-drop ALL`, `no-new-privileges`, read-only rootfs |
| LLM API connection | Network | Sensitive | Egress from containers | HTTPS only, iptables allowlist (`scripts/setup-network.sh:67-69`) |
| Configuration (YAML) | Config | Internal | `harness.yaml` on operator host | No secrets in file; env vars override (`harness/config.py:37-96`) |
| Encryption key (FINDINGS_ENC_KEY) | Secret | Critical | Environment variable | Base64-encoded, 32-byte validation (`harness/crypto.py:30-37`) |
| API keys (ANTHROPIC_API_KEY, etc.) | Secret | Critical | Environment variables | Runtime injection only (P4), never in images or on disk |
| Target source code | Data | External | Volume-mounted read-only | `:ro` mount prevents modification (`harness/dispatcher.py:44`) |
| Pre-compiled ASAN binaries | Binary | Internal | Volume-mounted read-only | `:ro` mount, built in controlled environment |

---

## 3. Data Flow Diagram

```
                                    EXTERNAL
                                 +-----------+
                                 | LLM       |
                                 | Provider  |
                                 | API       |
                                 +-----+-----+
                                       | HTTPS :443
                                       | (allowlisted IPs only)
                                       |
+------------------+             +-----+-----+              +-----------+
|                  |  dispatch   |           |  raw output  |           |
|  Operator Host   +----------->+ Worker    +------------->+ ASAN      |
|                  |  (docker   | Container |  (stdout)    | Parser    |
|  - CLI           |   run)     | (N of M)  |              |           |
|  - Config YAML   |            |           |              +-----+-----+
|  - Audit Log     |<-----------+ - ReAct   |                    |
|                  |  exit code | - bash    |              +-----+-----+
+--------+---------+  + stdout  | - litellm |              |           |
         |                      +-----+-----+              | Validation|
         |                            |                    | Agent     |
         |                            | tmpfs              | (litellm) |
         |                            | (destroyed         |           |
         |                            |  on exit)          +-----+-----+
         |                                                       |
         |              +--------------------+                   |
         +------------->+                    +<------------------+
                        |  Postgres          |
                        |  - runs            |
                        |  - jobs            |
                        |  - findings (enc)  |
                        +--------------------+

    +-------------------+
    |  Redis             |
    |  - job queue       |
    |  - spend tracking  |
    +-------------------+
```

**Data flows**:
1. Operator -> Orchestrator: CLI commands, configuration
2. Orchestrator -> Redis: Job enqueue, spend updates
3. Orchestrator -> Docker: Container lifecycle (create, monitor, destroy)
4. Container -> LLM API: Prompts and tool definitions (HTTPS)
5. LLM API -> Container: Responses with tool calls
6. Container -> Orchestrator: stdout (agent JSON), stderr (ASAN output)
7. Orchestrator -> Audit Log: Every action before execution
8. Orchestrator -> Postgres: Findings (sensitive fields encrypted)
9. Orchestrator -> Filesystem: Human review reports (markdown)

---

## 4. STRIDE Analysis

### 4.1 Spoofing

| Asset / Component | Threat | Mitigation | Residual Risk |
|-------------------|--------|-----------|---------------|
| Human reviewer identity | Attacker impersonates a reviewer to approve disclosure of a finding | Reviewer identity recorded in audit log and database (`harness/findings.py:213`). Audit log hash chain prevents retroactive identity changes. | **Medium**. No authentication system verifies reviewer identity. The `reviewer` field is a string passed by the caller. An operator with database access could forge reviews. Mitigated in production by deploying behind an authenticated API gateway. |
| LLM API endpoint | Man-in-the-middle replaces LLM API endpoint to feed malicious instructions to agents | HTTPS enforced (port 443 only, `scripts/setup-network.sh:67-69`). iptables rules restrict egress to specific resolved IPs. | **Low**. TLS certificate validation by litellm/requests prevents MITM. DNS spoofing could redirect to wrong IP, but TLS cert mismatch would cause connection failure. |
| Worker container identity | Rogue container on the Docker network impersonates a legitimate worker | Inter-container communication disabled (`--icc=false`, `scripts/setup-network.sh:39`). Container names include job ID. Results collected via Docker stdout, not network. | **Low**. No inter-container network path exists. |
| Orchestrator | Attacker gains access to operator host and runs unauthorized scans | Gap. No authentication for CLI access. Relies on OS-level access controls. | **Medium**. In production, the orchestrator should be behind an authenticated service layer. |

### 4.2 Tampering

| Asset / Component | Threat | Mitigation | Residual Risk |
|-------------------|--------|-----------|---------------|
| Audit log | Attacker modifies audit log to hide actions or forge compliance evidence | SHA-3 hash chain: each entry's `this_hash` covers full JSON including `prev_hash`. `verify_chain()` detects any modification (`harness/audit.py:93-123`). | **Low** for detection, **Medium** for prevention. The hash chain detects tampering but does not prevent it. An attacker with filesystem access could rewrite the entire log with a valid chain. Mitigation: ship audit entries to an external immutable store (e.g., governance platform, S3 with Object Lock). |
| Findings database | Attacker modifies finding records to change severity, approval status, or exploit code | Sensitive fields encrypted with AES-256-GCM (`harness/crypto.py:13-18`). Modification of encrypted fields without the key produces authentication tag failure on decryption. | **Medium**. Unencrypted metadata fields (severity_tier, cvss_estimate, validation_verdict, human_reviewed) could be modified by anyone with database access. Postgres row-level security or application-level audit triggers would reduce this risk. |
| Target source code | Agent modifies target source to hide vulnerabilities or inject backdoors | Source mounted read-only (`:ro` flag, `harness/dispatcher.py:44`). Agent cannot write to `/target/src`. | **Negligible**. Docker enforces read-only mount. |
| Container image | Supply chain attack modifies worker Docker image to exfiltrate data | Images built from Dockerfile in repository. Base image `ubuntu:24.04` from Docker Hub. | **Medium**. No image signing or digest pinning. An attacker who compromises Docker Hub or the build pipeline could inject malicious code. Mitigation: pin base image by digest, sign images with cosign. |
| LLM responses | LLM provider returns manipulated responses to cause false negatives (missed vulnerabilities) | Validation agent (Stage 5) provides independent second opinion. ASAN provides deterministic ground truth -- the LLM cannot fake ASAN output. | **Low**. ASAN is the oracle, not the LLM. The LLM guides exploration, but ASAN confirms crashes. A compromised LLM could miss vulnerabilities (false negatives) but cannot fabricate them (false positives are caught by validation + human review). |

### 4.3 Repudiation

| Asset / Component | Threat | Mitigation | Residual Risk |
|-------------------|--------|-----------|---------------|
| Human review actions | Reviewer denies having approved a disclosure | Audit log entry with reviewer name, timestamp, and hash chain (`harness/findings.py:241-251`). Database records `human_reviewer` and `reviewed_at`. | **Low**. Hash chain provides non-repudiation for the sequence of events. However, without digital signatures on individual entries, an attacker with full system access could theoretically rebuild the chain. |
| Agent actions | Need to prove what the agent did or did not do | Every tool call and LLM response logged in audit before execution (P3, `harness/audit.py:39-88`). Worker stderr captures tool call details (`worker/agent/loop.py:82-91`). | **Low**. Comprehensive logging with hash chain provides strong evidence trail. |
| Disclosure decisions | Regulatory inquiry about whether disclosure was properly authorized | `disclosure_approved` field with timestamp and reviewer in database (`migrations/versions/001_initial_schema.py:74`). Corresponding audit log entry. | **Low**. Dual recording (database + audit log) provides redundant evidence. |
| Cost expenditure | Dispute about how much was spent on a scan run | Every LLM call records token counts and cost estimate in audit log. Redis tracks running spend total. | **Low**. Multiple independent cost records (audit log, Redis, LLM response metadata). |

### 4.4 Information Disclosure

| Asset / Component | Threat | Mitigation | Residual Risk |
|-------------------|--------|-----------|---------------|
| Exploit code / PoC | Leaked exploit code enables attackers to exploit the vulnerability before disclosure | AES-256-GCM encryption in Postgres (P8, `harness/crypto.py:13-18`). Never printed to stdout in plaintext (`01-constitution.md:40-41`). Container tmpfs destroyed on exit. | **Low** if encryption key is protected. **Critical** if key is leaked. The FINDINGS_ENC_KEY is the single point of failure for exploit code confidentiality. |
| API keys | Leaked API keys enable unauthorized LLM usage or impersonation | Environment variable injection only (P4). Never in Docker images, config files, or audit log. `harness/dispatcher.py:51-54` passes keys via `-e` flag. | **Medium**. API keys exist in the process environment of running containers. A container escape or `/proc` filesystem read could expose them. Mitigated by `--cap-drop ALL` and `no-new-privileges`. |
| ASAN output with vulnerability details | Detailed crash information leaks vulnerability details before responsible disclosure | ASAN output encrypted in findings store (`asan_output_enc` column). Raw agent output in Redis/job records may contain ASAN details in plaintext. | **Medium**. Job `result_raw` JSONB column in Postgres is not encrypted. It may contain ASAN output embedded in agent JSON. This is a gap -- `result_raw` should be encrypted or access-restricted. |
| Audit log contents | Audit log may contain sensitive payload data (LLM prompts, finding details) | Audit log is a local file with OS-level access controls. No encryption of audit log contents. | **Medium**. Audit log payloads include event metadata but not full exploit code. However, finding validation payloads include verdicts and job IDs that could be correlated to findings. Access should be restricted to authorized personnel. |
| LLM API traffic | Network interception of prompts/responses containing vulnerability analysis | HTTPS enforced for all LLM API traffic (`scripts/setup-network.sh:67-69`). TLS protects data in transit. | **Low**. Standard TLS protection. LLM provider has access to all prompts and responses -- this is inherent to the architecture. |

### 4.5 Denial of Service

| Asset / Component | Threat | Mitigation | Residual Risk |
|-------------------|--------|-----------|---------------|
| Worker containers | Resource exhaustion (memory, CPU, disk) | Memory limit: `--memory 4g` with no swap. CPU limit: `--cpus 2`. tmpfs size limits: `/tmp:size=4g`. Hard timeout: 1800 seconds with forced kill. | **Low**. Docker enforces resource limits. Timeout mechanism kills unresponsive containers (`harness/dispatcher.py:108-157`). |
| LLM API | Rate limiting or outage prevents agent operation | Three retries with exponential backoff for validation calls (`harness/validator.py:60-73`). Agent loop handles API failures gracefully, returning `inconclusive` verdict. | **Medium**. LLM provider outage halts all scanning. No fallback provider configuration. Mitigation: configure multiple providers or use local Ollama as fallback. |
| Redis queue | Queue flooding or Redis outage | Concurrency limit via asyncio.Semaphore (`harness/dispatcher.py:216`). Spend limit checks before each dispatch. | **Medium**. Redis is a single point of failure for job dispatch in local dev. Production should use Postgres or Redis with replication. |
| Audit log filesystem | Disk full prevents audit writes, which blocks all operations (P3) | Audit write failure causes run failure (`01-constitution.md:26-27`). This is by design -- silent log failure would violate P3. | **Low** for data integrity, **Medium** for availability. A full disk stops all operations. Operators should monitor disk space and configure log rotation/archival. |
| Postgres database | Database outage prevents finding storage | asyncpg connections are per-operation (open, execute, close). No connection pooling. | **Medium**. No connection pooling or retry logic for database operations. A transient Postgres outage during finding storage could lose results. |
| Operator host | Attacker floods CLI with scan requests | No rate limiting on CLI invocation. Spend limits cap financial exposure. | **Low**. CLI is local; attacker needs host access, which is a larger compromise. |

### 4.6 Elevation of Privilege

| Asset / Component | Threat | Mitigation | Residual Risk |
|-------------------|--------|-----------|---------------|
| Worker container escape | Agent exploits container runtime vulnerability to escape to host | `--cap-drop ALL`: all Linux capabilities removed. `--security-opt no-new-privileges`: prevents suid/sgid escalation. Non-root user (UID 1001, `worker/Dockerfile:33-34`). Read-only root filesystem. tmpfs-only writable paths. | **Low** but **Critical impact**. Container escape would grant host access. Defense in depth (multiple layers), but Docker escape vulnerabilities do occur. Kubernetes with gVisor or Kata Containers would add a stronger isolation boundary. |
| Agent prompt injection | LLM manipulated into executing unauthorized commands via crafted input in target source code | Agent has `bash()` and `read_file()` tools only (`worker/agent/tools.py:5-37`). No network tools, no file write to persistent storage. Workspace is tmpfs. Container network blocks all non-API egress. | **Medium**. The agent has bash access by design -- it needs it for security research. A prompt injection in the target code could cause the agent to execute arbitrary bash within the container, but the container's security boundary limits impact. The agent cannot exfiltrate data (no outbound except API), modify source (read-only), or persist state (tmpfs). |
| Agent privilege within container | Agent escalates from non-root to root inside container | `no-new-privileges` security option. No setuid binaries (capabilities dropped). Non-root user by default. | **Low**. Standard Linux privilege escalation mitigated. Kernel exploits are the remaining vector, addressed by keeping Docker and kernel updated. |
| Database access | Attacker with Postgres access modifies findings or approval status | Gap -- partial. No row-level security. No database audit trail beyond application-level audit log. Connection authenticated by password (env var). | **Medium**. Anyone with `POSTGRES_PASSWORD` can modify any record. Postgres RLS and audit triggers would improve this. |
| Orchestrator escalation | Attacker with operator access gains access to encrypted findings | Encryption key (`FINDINGS_ENC_KEY`) must be in the environment to operate. Operator with env access can decrypt findings. | **Medium**. This is inherent -- the operator must be trusted. In production, use a secrets manager (Vault, AWS Secrets Manager) with access logging. |

---

## 5. Attack Trees

### 5.1 Highest Risk: LLM Provider Compromise

```
Goal: Exfiltrate vulnerability data via compromised LLM provider
|
+-- 1. Compromise LLM provider API
|   |
|   +-- 1a. Compromise provider infrastructure (external, out of scope)
|   +-- 1b. Steal API key from operator environment
|       |
|       +-- 1b.i. Access operator host (OS compromise)
|       +-- 1b.ii. Read from container /proc (requires container escape)
|       +-- 1b.iii. Intercept docker run command (requires host access)
|
+-- 2. Extract vulnerability information from API traffic
|   |
|   +-- 2a. LLM provider logs contain full prompts/responses
|   |   (Mitigation: select provider with data retention policy)
|   +-- 2b. Provider-side employee accesses conversation data
|       (Mitigation: contractual controls, SOC2 attestation from provider)
|
+-- 3. Manipulate agent behavior via compromised API
    |
    +-- 3a. Return false negatives (miss real vulns)
    |   (Mitigation: ASAN is ground truth, not LLM)
    +-- 3b. Return instructions to exfiltrate via API calls
        (Mitigation: agent sends prompts to API; data in prompts IS the risk)
```

**Assessment**: The LLM provider inherently sees all prompts and responses. This includes target source code, ASAN output, and vulnerability analysis. This is a fundamental architectural property, not a bug. Mitigation: choose providers with strong data handling policies, consider local models (Ollama) for highly sensitive targets, and use the data classification system to decide what targets are appropriate for which providers.

### 5.2 Container Escape

```
Goal: Escape worker container to access host system
|
+-- 1. Exploit Docker runtime vulnerability
|   |
|   +-- 1a. Kernel exploit from within container
|   |   (Mitigation: --cap-drop ALL, no-new-privileges, non-root)
|   +-- 1b. Docker daemon exploit via API
|   |   (Mitigation: no Docker socket mounted in container)
|   +-- 1c. Exploit in volume mount handling
|       (Mitigation: read-only mounts, tmpfs only writable)
|
+-- 2. Exploit agent to perform escape
|   |
|   +-- 2a. Prompt injection in target source causes agent to
|   |   attempt escape techniques
|   |   (Mitigation: capabilities dropped, no suid, no network)
|   +-- 2b. Agent discovers and exploits 0-day in container runtime
|       (Mitigation: agent has bash but limited tools; no persistent network)
|
+-- 3. Exploit shared resources
    |
    +-- 3a. Exploit via /proc or /sys filesystem
    |   (Mitigation: default Docker seccomp profile, no-new-privileges)
    +-- 3b. Exploit via mounted volumes
        (Mitigation: source and binaries read-only, workspace is tmpfs)
```

**Assessment**: Container escape is the highest-impact local threat. Multiple layers of defense are in place (capability drop, non-root, read-only filesystem, no Docker socket, network restriction). The residual risk is kernel-level container escape vulnerabilities, which are rare but have occurred (CVE-2024-21626, CVE-2019-5736). Production deployments should use gVisor, Kata Containers, or equivalent sandbox runtime.

### 5.3 Audit Log Manipulation

```
Goal: Tamper with audit log to hide unauthorized actions
|
+-- 1. Modify existing entries
|   |
|   +-- 1a. Edit a single entry
|   |   (Detected by: hash chain verification, verify_chain())
|   +-- 1b. Rewrite entire log with valid new chain
|       (Mitigation: ship entries to external immutable store)
|
+-- 2. Prevent new entries from being written
|   |
|   +-- 2a. Fill disk to block audit writes
|   |   (Effect: run fails, P3 enforced -- no silent failure)
|   +-- 2b. Corrupt audit file
|       (Effect: next write detects corruption on read)
|
+-- 3. Delete audit log
    |
    +-- 3a. Remove file from filesystem
        (Mitigation: OS file permissions + external backup)
```

**Assessment**: The hash chain provides tamper detection but not tamper prevention. For regulated deployments, audit entries should be forwarded to an external immutable store in real time. The specification notes this as a "one-day integration" (`02-specification.md:374-375`).

---

## 6. Residual Risk Register

| ID | Risk | Likelihood | Impact | Current Mitigations | Residual Status | Accepted? |
|----|------|-----------|--------|---------------------|-----------------|-----------|
| R1 | LLM provider sees all vulnerability analysis data | Certain (by design) | High | Provider selection, data classification, local model option | **High** | Accepted with controls. Operators must evaluate provider trust before scanning sensitive targets. |
| R2 | Container escape via kernel vulnerability | Very Low | Critical | `--cap-drop ALL`, `no-new-privileges`, non-root, read-only rootfs, network isolation | **Low** | Accepted for dev. Production should use gVisor/Kata. |
| R3 | Audit log rewritten with valid chain | Low | High | Hash chain detects single-entry tampering. Full rewrite requires filesystem access. | **Medium** | Not accepted. External immutable store integration required for production. |
| R4 | FINDINGS_ENC_KEY compromised | Low | Critical | Env-var only, not on disk. Access requires host compromise. | **Medium** | Accepted with monitoring. Production should use secrets manager with access logging. |
| R5 | API key leaked from container environment | Low | High | Keys in env vars only, capability drop limits `/proc` access | **Low** | Accepted. Short-lived API keys or per-container tokens recommended for production. |
| R6 | Reviewer identity spoofed (no authentication) | Medium | High | Audit log records identity, but no verification | **High** | Not accepted for production. Authentication system required (issue #18). |
| R7 | `result_raw` JSONB column contains unencrypted vulnerability details | Certain (by design) | Medium | Database access controls | **Medium** | Not accepted. `result_raw` should be encrypted or redacted (issue #30). |
| R8 | Prompt injection in target source | Medium | Low | Container isolation limits blast radius, ASAN is ground truth | **Low** | Accepted. Agent needs bash access; container boundary is the control. |
| R9 | Supply chain compromise of container base image | Very Low | Critical | Dockerfile in version control, reproducible builds | **Low** | Accepted with recommendation to pin base image by digest. |
| R10 | Redis single point of failure | Medium | Medium | Spend limits cap exposure. Jobs can be re-enqueued. | **Medium** | Accepted for dev. Production should use Redis replication or Postgres queue. |
| R11 | Database operations lack retry logic | Medium | Low | Per-operation connections, asyncpg error handling | **Medium** | Accepted. Add retry logic with exponential backoff (issue #31). |
| R12 | No automated backup for findings store | Medium | High | Manual Postgres backup available | **High** | Not accepted for production. Automated backup required (issue #27). |

---

## 7. Review Schedule

This threat model should be reviewed:
- After any significant architecture change
- After any container runtime CVE affecting Docker
- After adding new data flows or external integrations
- At minimum annually
- After any security incident involving the Mantis system itself
