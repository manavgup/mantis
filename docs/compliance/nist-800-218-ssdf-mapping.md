# NIST SP 800-218 (SSDF) v1.1 -- Mantis Compliance Mapping

**Document version**: 1.0
**Last updated**: 2026-04-25
**Applicable system**: Mantis Autonomous Vulnerability Discovery Harness
**Framework**: NIST SP 800-218 — Secure Software Development Framework (SSDF) v1.1

---

## Overview

This document maps each SSDF practice group and task to the corresponding Mantis implementation. Evidence locations reference actual file paths in the repository. Gaps are identified honestly and marked with planned remediation.

---

## PO: Prepare the Organization

| Practice | Task | Mantis Implementation | Evidence |
|----------|------|----------------------|----------|
| PO.1 | Define security requirements for software development | P1-P8 non-negotiable principles define enforceable security requirements: isolation, human review, audit logging, credential hygiene, ephemeral containers, cost tracking, human severity confirmation, exploit containment. | `01-constitution.md:19-41` |
| PO.1.1 | Define security requirements | Eight codified principles (P1-P8) serve as the security requirements baseline. They are defined as "non-negotiable" and cover isolation, access control, audit, credential management, data-at-rest encryption, and human oversight. | `01-constitution.md:19-41` |
| PO.1.2 | Communicate requirements to third parties | The system uses litellm for all LLM provider interactions; third-party API keys are injected at runtime only (P4). Network egress is restricted to allowlisted API endpoints. No third-party code executes outside Docker containers. | `harness/config.py:60-64`, `scripts/setup-network.sh:12` |
| PO.1.3 | Review and update security requirements | Gap -- planned. No formal periodic review cadence for the constitution is currently defined. The constitution is version-controlled in git, providing change history. See issue #17. | `01-constitution.md` (git history) |
| PO.2 | Implement roles and responsibilities | Gap -- partial. The system enforces role separation between automated agents and human reviewers (P2, P7). Human reviewer identity is recorded in audit log and findings store. No formal RBAC system for operator/reviewer/admin roles exists yet. See issue #18. | `harness/findings.py:210-251` (human reviewer field), `01-constitution.md:23-24` (P2) |
| PO.2.1 | Identify software development roles | Two roles are implicit: operator (runs scans) and human reviewer (confirms findings, approves disclosure). Agent actors are distinguished in audit log entries (`orchestrator`, `worker`, `validation_agent`, `human:{name}`). | `harness/audit.py:70-78` (actor field) |
| PO.2.2 | Identify security-relevant roles | The audit log tracks actor identity on every entry. Human review requires named reviewer identity for sign-off. Disclosure requires explicit human approval. | `harness/findings.py:210-251`, `02-specification.md:423-432` |
| PO.2.3 | Provide role-specific training | Gap -- planned. No training materials or runbooks exist for operators or reviewers. See issue #19. | N/A |
| PO.3 | Implement supporting toolchains | Development toolchain: ruff linter/formatter, pre-commit hooks, pytest with coverage, Alembic for migrations. Runtime toolchain: Docker containers, clang/ASAN, Redis, Postgres. | `Makefile`, `.pre-commit-config.yaml`, `pyproject.toml` |
| PO.3.1 | Specify required toolchains | Toolchain requirements are codified: Python 3.12+, clang with AddressSanitizer, Docker, Redis, Postgres. Worker container image specifies all packages installed at build time. | `01-constitution.md:47-54`, `worker/Dockerfile:1-23` |
| PO.3.2 | Evaluate and select tools | litellm selected for provider-agnostic LLM access. ASAN selected as the deterministic ground-truth oracle for memory safety. SHA-3 selected for hash chain integrity. AES-256-GCM selected for encryption at rest. All choices documented. | `01-constitution.md:48-54`, `harness/crypto.py:1-2`, `harness/audit.py:1` |
| PO.3.3 | Ensure toolchain security | Worker container images are built credential-free (P4). Pre-commit hooks enforce code quality. Dependencies pinned in `requirements.txt` and `agent/requirements.txt`. | `worker/Dockerfile:29-31`, `01-constitution.md:29` |
| PO.4 | Define and use criteria for software security checks | Static analysis (ruff), pre-commit hooks, unit tests, and integration tests enforce quality gates. ASAN provides runtime memory safety verification. Validation agent provides automated finding review. | `Makefile` (check target), `harness/validator.py:49-128` |
| PO.4.1 | Define criteria for security checks | Severity tier system (1-5) with CVSS ranges defined. Validation agent uses explicit criteria: ASAN consistency, reproduction plausibility, security meaningfulness. | `harness/parser.py:23-40`, `harness/validator.py:16-37` |
| PO.4.2 | Implement criteria | Validation agent enforces three-question assessment with explicit verdict routing: VALIDATE, REJECT, or NEEDS_HUMAN_TRIAGE. | `harness/validator.py:93-127` |
| PO.5 | Implement and maintain secure environments | Worker containers run with `--cap-drop ALL`, `--security-opt no-new-privileges`, read-only root filesystem, memory limits, and restricted network egress. | `harness/dispatcher.py:55-77`, `worker/Dockerfile:33-34`, `scripts/setup-network.sh` |
| PO.5.1 | Separate development from production | Worker containers are isolated from orchestrator infrastructure. Source is mounted read-only. tmpfs workspace is destroyed on container exit. No shared state between workers. | `harness/dispatcher.py:43-45` (`:ro` mount), `worker/entrypoint.sh:22-24` |
| PO.5.2 | Protect development environments | Gap -- partial. No formal developer workstation security policy. Production secrets are environment-variable only (P4) and never committed. `.env` files excluded from git. See issue #20. | `01-constitution.md:29` |

---

## PS: Protect the Software

| Practice | Task | Mantis Implementation | Evidence |
|----------|------|----------------------|----------|
| PS.1 | Protect all forms of code | Source code in git with branch protection. Docker images built without credentials (P4). Exploit code encrypted at rest with AES-256-GCM (P8). | `01-constitution.md:29, 40-41`, `harness/crypto.py:13-18` |
| PS.1.1 | Store code securely | Findings with exploit code stored in Postgres with AES-256-GCM encrypted columns (`reproduction_enc`, `patch_enc`, `asan_output_enc`). Encryption key loaded from environment variable, never from disk or config file. | `harness/findings.py:125-127`, `harness/crypto.py:30-37`, `migrations/versions/001_initial_schema.py:75-77` |
| PS.1.2 | Protect code integrity | Audit log uses SHA-3 hash chain for tamper evidence. Each entry's `this_hash` covers the full JSON including `prev_hash`. Chain verification function provided. | `harness/audit.py:81-83` (hash computation), `harness/audit.py:93-123` (verify_chain) |
| PS.2 | Verify third-party components | Gap -- partial. Worker container installs packages at build time from Ubuntu and PyPI repositories. No SBOM generation or dependency vulnerability scanning pipeline exists. See issue #21. | `worker/Dockerfile:5-23` |
| PS.2.1 | Identify third-party components | Dependencies listed in `requirements.txt` files. Container packages enumerated in Dockerfile. No automated SBOM tool. | `worker/Dockerfile:5-23`, `worker/agent/requirements.txt` |
| PS.2.2 | Verify third-party components | Gap -- planned. No automated dependency vulnerability scanning (e.g., `pip-audit`, `trivy`). See issue #21. | N/A |
| PS.3 | Configure build processes | Build processes use specific compiler flags for ASAN instrumentation. Entrypoint script handles autotools, CMake, and plain Makefile projects with consistent ASAN flags. | `worker/entrypoint.sh:35-84` |
| PS.3.1 | Use well-defined build processes | Entrypoint script defines deterministic build sequence: autotools > CMake > Makefile. Compiler flags hardcoded for ASAN (`-fsanitize=address -g -O1 -fno-omit-frame-pointer`). Build failures produce structured JSON error output. | `worker/entrypoint.sh:35-91` |
| PS.3.2 | Protect build artifacts | Pre-compiled binaries mounted read-only into containers (`:ro`). Built binaries placed in tmpfs, destroyed on container exit (P5). Docker images built credential-free (P4). | `harness/dispatcher.py:48-49`, `worker/entrypoint.sh:30-33` |

---

## PW: Produce Well-Secured Software

| Practice | Task | Mantis Implementation | Evidence |
|----------|------|----------------------|----------|
| PW.1 | Design software to meet security requirements | Architecture designed around 8 non-negotiable security principles. Five-stage pipeline with isolation at every boundary. Separate validation agent prevents single-point-of-failure in finding quality. | `01-constitution.md:19-41`, `02-specification.md:1-31` |
| PW.1.1 | Use secure design principles | Defense in depth: container isolation (P1) + network restriction + capability dropping + read-only filesystem + separate validation agent + mandatory human review (P2). Least privilege: `--cap-drop ALL`, non-root user (UID 1001). | `worker/Dockerfile:33-34`, `harness/dispatcher.py:74-76`, `scripts/setup-network.sh:38-40` |
| PW.1.2 | Evaluate security risk of design | Threat model documented (see `docs/compliance/threat-model.md`). Container escape, LLM provider compromise, and audit log tampering identified as primary risks. | `docs/compliance/threat-model.md` |
| PW.2 | Review the software design | Gap -- partial. Design documented in specification but no formal design review process with sign-off. Architecture decisions are recorded in `01-constitution.md` and `02-specification.md`. See issue #22. | `02-specification.md` |
| PW.4 | Reuse existing, well-secured software | Uses established libraries: litellm (LLM abstraction), cryptography (AES-256-GCM), asyncpg (Postgres), pydantic (validation). Does not implement custom cryptography. | `harness/crypto.py:8` (cryptography.hazmat), `harness/llm.py:8` (litellm), `harness/findings.py:8` (asyncpg) |
| PW.4.1 | Prefer established components | AES-256-GCM via Python `cryptography` library (not custom). SHA-3 via Python `hashlib` stdlib. litellm for LLM provider abstraction. All standard, audited libraries. | `harness/crypto.py:8`, `harness/audit.py:4` |
| PW.5 | Create source code by adhering to secure coding practices | Ruff linter enforces code quality (E, F, I, W rules). Pre-commit hooks run on every commit. Async/await patterns used throughout for proper resource management. | `pyproject.toml`, `.pre-commit-config.yaml` |
| PW.5.1 | Follow secure coding practices | Input validation via pydantic models. SQL parameterized queries (no string concatenation). Encryption key validation (32-byte check). JSON parsing with error handling. | `harness/config.py:37-96` (pydantic), `harness/findings.py:131-153` (parameterized SQL), `harness/crypto.py:35-37` (key validation) |
| PW.6 | Configure software to have secure settings by default | Default configuration: 4 parallel workers, $100 per-run spend limit, $500 per-day limit, 30-minute container timeout, 4GB memory limit. Static ranker (no API cost) as default ranking strategy. | `harness/config.py:54-84` |
| PW.6.1 | Define secure default settings | Defaults are restrictive: low parallelism, conservative spend limits, short timeouts. Network egress deny-all by default with explicit allowlist. | `harness/config.py:68-83`, `scripts/setup-network.sh:62-63` |
| PW.7 | Review and analyze human-readable code | Pre-commit hooks enforce linting and formatting. Validation agent reviews findings programmatically. Human review mandatory for all findings before external action (P2). | `.pre-commit-config.yaml`, `harness/validator.py:49-128` |
| PW.7.1 | Perform code review | Gap -- partial. Pre-commit hooks provide automated checks. No formal peer code review process is mandated for Mantis development itself. See issue #22. | `.pre-commit-config.yaml` |
| PW.8 | Test executable code | Unit tests (35+) and integration tests (8+) with pytest. ASAN provides runtime memory safety testing of target binaries. Audit chain verification function serves as integrity test. | `tests/unit/`, `tests/integration/`, `harness/audit.py:93-123` |
| PW.8.1 | Use automated testing | `make test` runs unit tests with coverage. `make test-all` runs integration tests. Pre-commit hooks run linting on every commit. | `Makefile` |
| PW.8.2 | Perform fuzz testing | The core product IS a fuzz/vulnerability testing tool. ASAN is the ground-truth oracle. Agent-generated inputs serve as intelligent, targeted fuzz inputs. | `worker/agent/loop.py`, `harness/parser.py:9-17` |
| PW.9 | Configure software to have secure settings | Configuration via YAML + env var override (pydantic-settings). Env vars take precedence for secrets. No secrets in config files. | `harness/config.py:37-96` |
| PW.9.1 | Define secure configuration | All sensitive values (API keys, encryption keys) loaded from environment variables, never from YAML. Key validation enforces 32-byte length for AES-256. | `harness/config.py:86-88`, `harness/crypto.py:30-37` |

---

## RV: Respond to Vulnerabilities

| Practice | Task | Mantis Implementation | Evidence |
|----------|------|----------------------|----------|
| RV.1 | Identify and confirm vulnerabilities | Five-stage pipeline: agent discovers, ASAN confirms, parser extracts metadata, validation agent filters, human confirms. Three-question validation: ASAN real? Repro plausible? Security meaningful? | `harness/parser.py:150-202`, `harness/validator.py:49-128` |
| RV.1.1 | Gather vulnerability information | ASAN output parsed for crash type, READ/WRITE direction, location (file, line, function). Agent provides reproduction commands, candidate patches, confidence level, and reasoning. | `harness/parser.py:63-92` (detection), `02-specification.md:270-310` (parser output schema) |
| RV.1.2 | Assess vulnerability severity | Automated severity tier (1-5) with CVSS estimate ranges. P7 mandates human confirmation of severity before any external action. `cvss_estimate` vs `cvss_confirmed` columns enforce this distinction. | `harness/parser.py:23-40`, `01-constitution.md:37-38`, `migrations/versions/001_initial_schema.py:68-69` |
| RV.1.3 | Validate vulnerabilities | Validation agent (Stage 5) uses separate LLM call to independently assess each finding. Three retries on failure. Verdicts: VALIDATE, REJECT, NEEDS_HUMAN_TRIAGE. | `harness/validator.py:49-128` |
| RV.2 | Assess and prioritize vulnerabilities | Severity tier determines priority in human review queue (`ORDER BY severity_tier DESC`). Tier 5 (RCE) prioritized above Tier 1 (memory leak). | `harness/findings.py:191-207` (list_pending_review), `harness/parser.py:33-40` (CVSS ranges) |
| RV.2.1 | Prioritize vulnerability response | Human review queue ordered by severity tier. Validation verdict determines routing: VALIDATE goes to review queue, REJECT is logged but not queued, NEEDS_HUMAN_TRIAGE gets lower priority with extra scrutiny flag. | `harness/findings.py:191-207`, `02-specification.md:347-349` |
| RV.3 | Respond to vulnerabilities | Incident response playbook defined (see `docs/compliance/incident-response-playbook.md`). P2 enforces human sign-off before any external disclosure. Audit log records disclosure approval. | `docs/compliance/incident-response-playbook.md`, `harness/findings.py:210-251` |
| RV.3.1 | Remediate vulnerabilities | System generates candidate patches as part of findings. Human reviewer must approve patches before submission. Disclosure approval tracked in database and audit log. | `harness/findings.py:210-251` (record_human_review), `02-specification.md:423-432` (reviewer sign-off) |
| RV.3.2 | Communicate vulnerability information | Gap -- partial. Finding reports generated in structured markdown with all necessary context. No automated notification system for stakeholders. Coordinated disclosure timeline defined in incident response playbook but not enforced by code. See issue #23. | `harness/findings.py:15-63` (REPORT_TEMPLATE) |
| RV.3.3 | Track vulnerabilities | Findings stored in Postgres with full lifecycle tracking: discovery, validation verdict, human review status, reviewer identity, review timestamp, disclosure approval. | `migrations/versions/001_initial_schema.py:58-87` |

---

## Summary of Gaps

| Gap | SSDF Practice | Description | Planned Remediation |
|-----|--------------|-------------|---------------------|
| Periodic requirements review | PO.1.3 | No formal review cadence for P1-P8 | Issue #17 |
| Formal RBAC | PO.2 | Roles are implicit, no access control system | Issue #18 |
| Training materials | PO.2.3 | No operator/reviewer training | Issue #19 |
| Developer workstation policy | PO.5.2 | No formal dev security policy | Issue #20 |
| SBOM and dependency scanning | PS.2 | No automated supply chain verification | Issue #21 |
| Formal design/code review process | PW.2, PW.7.1 | No mandated peer review for Mantis code | Issue #22 |
| Automated disclosure notifications | RV.3.2 | No notification system for stakeholders | Issue #23 |
