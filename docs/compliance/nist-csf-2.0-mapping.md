# NIST Cybersecurity Framework 2.0 -- Mantis Compliance Mapping

**Document version**: 1.0
**Last updated**: 2026-04-25
**Applicable system**: Mantis Autonomous Vulnerability Discovery Harness
**Framework**: NIST Cybersecurity Framework (CSF) 2.0

---

## Overview

This document maps NIST CSF 2.0 functions and subcategories to Mantis controls, cross-referencing the P1-P8 non-negotiable principles from the Mantis constitution. Evidence locations reference actual file paths in the codebase.

---

## GV: Govern

The Govern function establishes and monitors the organization's cybersecurity risk management strategy, expectations, and policy.

| Subcategory | Mantis Implementation | Principle | Evidence |
|-------------|----------------------|-----------|----------|
| GV.OC-01: Organizational context for cybersecurity risk management is understood | Mantis is purpose-built for defensive security research in regulated industries (financial services, federal government). The constitution defines the operational context and constraints. | -- | `01-constitution.md:1-6` |
| GV.OC-02: Internal and external stakeholders are identified | Two primary stakeholder roles: operators (run scans, manage infrastructure) and human reviewers (confirm findings, approve disclosure). Audit log actor field distinguishes `orchestrator`, `worker`, `validation_agent`, and `human:{name}`. | P2, P7 | `harness/audit.py:70-78`, `harness/findings.py:210-251` |
| GV.OC-03: Legal, regulatory, and contractual requirements are understood | System designed for FINRA/SOX, GDPR/CCPA compliance. Data retention and destruction policies documented. Coordinated disclosure follows 90+45 day timeline. | P2 | `docs/compliance/data-retention-policy.md`, `01-constitution.md:1-6` |
| GV.OC-04: Critical objectives, capabilities, and services are determined | Five-stage vulnerability discovery pipeline with defined success criteria: find true-positive vulnerabilities, produce structured reports, maintain audit trail, stay within cost limits. | -- | `01-constitution.md:63-73`, `02-specification.md:1-31` |
| GV.OC-05: Outcomes, capabilities, and services dependencies are determined | Dependencies: Docker runtime, Redis queue, Postgres database, LLM provider API (configurable). All external dependencies documented. | -- | `01-constitution.md:47-54`, `harness/config.py:37-96` |
| GV.RM-01: Risk management objectives are established | P1-P8 principles define risk tolerance: zero tolerance for credential leakage, unreviewed disclosure, or unlogged actions. Explicit spend limits control financial risk. | P1-P8 | `01-constitution.md:19-41` |
| GV.RM-02: Risk appetite and tolerance are determined | Cost limits: $100/run default, $500/day default. Container timeout: 30 minutes. Memory limit: 4GB per container. All configurable but with conservative defaults. | P6 | `harness/config.py:71-83` |
| GV.RM-03: Enterprise risk management and cybersecurity risk are aligned | Gap -- partial. No formal enterprise risk management integration. The system maintains its own risk posture through P1-P8 but does not integrate with organizational ERM tools. See issue #24. | -- | N/A |
| GV.RM-07: Strategic opportunities are characterized | Gap -- not applicable. Mantis is a security tool, not a business system. Risk opportunities are identified through vulnerability discovery. | -- | N/A |
| GV.RR-01: Organizational leadership establishes cybersecurity roles and responsibilities | Constitution mandates human review (P2) and human severity confirmation (P7). Reviewer identity recorded in database and audit log. | P2, P7 | `01-constitution.md:23-24, 37-38` |
| GV.RR-02: Roles, responsibilities, and authorities are established | Audit log enforces actor accountability: every entry records who performed each action. Human review function requires named reviewer. | P3 | `harness/audit.py:70-78`, `harness/findings.py:213` |
| GV.PO-01: Policy for managing cybersecurity risk is established | P1-P8 constitution serves as the cybersecurity policy. It is version-controlled in git. Defined as "non-negotiable" and "not configurable, not bypassable, not optional" (P2). | P1-P8 | `01-constitution.md:19-41` |
| GV.PO-02: Policy for managing cybersecurity risk is communicated | Constitution is the first file in the repository and is referenced by all design documents. CLAUDE.md provides operational guidance for developers. | -- | `01-constitution.md`, `CLAUDE.md` |
| GV.SC-01: Cybersecurity supply chain risk management program is established | Gap -- partial. Dependencies installed from standard repositories (Ubuntu apt, PyPI). No formal supply chain risk management or SBOM. See issue #21. | -- | `worker/Dockerfile:5-23` |
| GV.SC-02: Cybersecurity roles for suppliers and partners are established | LLM provider interactions are constrained: egress-only network to allowlisted endpoints, API keys injected at runtime only, no persistent credentials. | P1, P4 | `scripts/setup-network.sh:12`, `01-constitution.md:29` |

---

## ID: Identify

The Identify function helps determine the current cybersecurity risk to the organization.

| Subcategory | Mantis Implementation | Principle | Evidence |
|-------------|----------------------|-----------|----------|
| ID.AM-01: Inventories of hardware and software assets are maintained | Worker container image contents defined in Dockerfile. Python dependencies in requirements files. System components documented in specification. | -- | `worker/Dockerfile:1-41`, `02-specification.md` |
| ID.AM-02: Inventories of software platforms and applications are maintained | Container base image (`ubuntu:24.04`), installed packages (clang, gdb, lldb, valgrind, etc.), and Python packages (litellm, jinja2) are enumerated in Dockerfile. | -- | `worker/Dockerfile:1-31` |
| ID.AM-03: Data assets are identified | Data classification defined: audit logs, finding metadata, exploit code/PoC, worker artifacts, API keys. See data retention policy. | P3, P8 | `docs/compliance/data-retention-policy.md` |
| ID.AM-05: Resources are prioritized based on classification | Exploit code classified as Restricted (encrypted). Audit logs classified as Compliance (integrity-protected). API keys classified as Secret (environment-only). | P8 | `docs/compliance/data-retention-policy.md`, `harness/crypto.py:13-18` |
| ID.AM-07: Data flows are mapped | Five-stage pipeline data flow documented in specification. Data flow from target repo through ranking, dispatch, worker analysis, parsing, validation, to human review. | -- | `02-specification.md:8-31` |
| ID.AM-08: Systems and assets criticality is assessed | Findings severity tier (1-5) provides criticality assessment for discovered vulnerabilities. Infrastructure components prioritized by role (audit log, findings store, worker containers). | P7 | `harness/parser.py:23-40`, `docs/compliance/threat-model.md` |
| ID.RA-01: Vulnerabilities in assets are identified | This IS the core function of Mantis. ASAN identifies memory safety vulnerabilities. Static ranker identifies high-risk code files. Parser extracts structured vulnerability metadata. | -- | `harness/parser.py:150-202`, `harness/static_ranker.py` |
| ID.RA-02: Threat intelligence is received from information sharing forums | Gap -- not implemented. Mantis discovers new vulnerabilities rather than consuming threat intelligence feeds. Could integrate with NVD/CVE databases for context. See issue #25. | -- | N/A |
| ID.RA-03: Internal and external threats are identified | Threat model documents threats to the Mantis system itself (container escape, LLM compromise, audit tampering). See threat model. | -- | `docs/compliance/threat-model.md` |
| ID.RA-04: Potential impacts and likelihoods are identified | STRIDE threat analysis with likelihood/impact assessment. Residual risk register maintained. CVSS estimates provide vulnerability impact assessment. | P7 | `docs/compliance/threat-model.md`, `harness/parser.py:33-40` |
| ID.RA-05: Threats, vulnerabilities, likelihoods, and impacts are used to understand risk | Severity tier system maps crash types to risk levels. CVSS estimation provides quantitative risk score. Human reviewer must confirm before action. | P7 | `harness/parser.py:82-91`, `01-constitution.md:37-38` |
| ID.RA-06: Risk responses are chosen | Validation agent routing: VALIDATE (high confidence), REJECT (false positive), NEEDS_HUMAN_TRIAGE (uncertain). Human reviewer makes final disposition. | P2, P7 | `harness/validator.py:93-127`, `02-specification.md:347-349` |
| ID.IM-01: Improvements from risk assessments are documented | Gap -- partial. Finding reports include full reasoning chain. No formal lessons-learned or improvement tracking process. See issue #26. | -- | `harness/findings.py:15-63` |

---

## PR: Protect

The Protect function supports the ability to secure assets to prevent or lower the likelihood and impact of cybersecurity events.

| Subcategory | Mantis Implementation | Principle | Evidence |
|-------------|----------------------|-----------|----------|
| PR.AA-01: Identities and credentials are managed | API keys loaded from environment variables, never persisted in images or config files (P4). Encryption key validated for correct length (32 bytes). Human reviewer identity recorded by name. | P4 | `harness/crypto.py:30-37`, `01-constitution.md:29`, `harness/findings.py:213` |
| PR.AA-02: Identities are proofed and bound to credentials | Gap -- partial. Human reviewer identity is recorded as a string (name), but no authentication system verifies reviewer identity. See issue #18. | P2 | `harness/findings.py:213` |
| PR.AA-03: Users and services are authenticated | Gap -- partial. No authentication layer for CLI or API access. Database access controlled by Postgres credentials. API keys authenticate to LLM providers. See issue #18. | P4 | `harness/config.py:82` |
| PR.AA-05: Access permissions and authorizations are defined | Filesystem: target source mounted read-only, workspace on tmpfs. Container: `--cap-drop ALL`, `no-new-privileges`. Network: egress allowlist only. Database: encrypted sensitive columns. | P1, P8 | `harness/dispatcher.py:43-76`, `scripts/setup-network.sh:62-63` |
| PR.AA-06: Physical access is managed | Gap -- not applicable at application level. Physical security is the responsibility of the deployment environment (data center, cloud provider). | -- | N/A |
| PR.AT-01: Awareness and training are provided | Gap -- planned. No formal security awareness training for operators. See issue #19. | -- | N/A |
| PR.AT-02: Individuals in specialized roles are provided awareness and training | Gap -- planned. No reviewer training materials. Incident response playbook provides operational guidance. See issue #19. | -- | `docs/compliance/incident-response-playbook.md` |
| PR.DS-01: Data-at-rest is protected | Exploit code, reproduction steps, and ASAN output stored with AES-256-GCM encryption in Postgres. 96-bit random nonce per encryption operation. Key loaded from environment variable. | P8 | `harness/crypto.py:13-18`, `harness/findings.py:125-127` |
| PR.DS-02: Data-in-transit is protected | LLM API calls use HTTPS (port 443 only, enforced by iptables). No plaintext exploit code transmitted. | P1, P8 | `scripts/setup-network.sh:67-69` (port 443 only) |
| PR.DS-10: Data-in-use is protected | Worker containers use tmpfs for workspace (data in RAM only, destroyed on exit). Container memory limited to 4GB. No swap (`--memory-swap` equals `--memory`). | P5 | `harness/dispatcher.py:38-39`, `02-specification.md:237` |
| PR.DS-11: Data backups are created and protected | Gap -- planned. No automated backup for Postgres findings store or audit logs. Audit logs are append-only files that can be backed up with standard tools. See issue #27. | -- | N/A |
| PR.IR-01: Incident response plans are established | Incident response playbook defines four phases: Triage, Internal Review, Coordinated Disclosure, Post-Incident Review. Escalation matrix based on severity tier. | P2 | `docs/compliance/incident-response-playbook.md` |
| PR.PS-01: Configuration management practices are established | Configuration via YAML + environment variable override (pydantic-settings). Env vars take precedence. All config fields have secure defaults. | -- | `harness/config.py:37-96` |
| PR.PS-02: Software is maintained and replaced | Container images rebuilt from Dockerfile. Ubuntu base image can be updated. Dependencies updated via requirements files. Alembic manages database schema migrations. | -- | `worker/Dockerfile`, `migrations/versions/001_initial_schema.py` |
| PR.PS-04: Log records are generated | SHA-3 hash-chained JSONL audit log records every action before execution (P3). Includes: event type, actor, timestamp, payload, sequence number, hash chain. File locking ensures atomicity. | P3 | `harness/audit.py:39-88` |
| PR.PS-05: Installation and disposal of hardware and software is managed | Containers created fresh per job and destroyed after result collection (P5). `--rm` flag on `docker run`. tmpfs destroyed on exit. No persistent state in containers. | P5 | `harness/dispatcher.py:34` (`--rm`), `01-constitution.md:32-33` |
| PR.PS-06: Secure software development practices are integrated | Pre-commit hooks, ruff linting, unit tests with coverage, integration tests. SSDF mapping documents compliance. | -- | `Makefile`, `.pre-commit-config.yaml`, `docs/compliance/nist-800-218-ssdf-mapping.md` |
| PR.IR-02: Incident response activities are managed | Playbook defines roles, timelines, and escalation. Audit log provides evidence trail. Finding lifecycle tracked in database (discovery through disclosure). | P2, P3 | `docs/compliance/incident-response-playbook.md`, `migrations/versions/001_initial_schema.py:58-87` |

---

## DE: Detect

The Detect function enables timely discovery of cybersecurity events.

| Subcategory | Mantis Implementation | Principle | Evidence |
|-------------|----------------------|-----------|----------|
| DE.CM-01: Networks are monitored for potential cybersecurity events | Network egress restricted to allowlisted endpoints. iptables rules log dropped traffic. Inter-container communication disabled (`enable_icc=false`). | P1 | `scripts/setup-network.sh:38-40, 62-63` |
| DE.CM-02: Physical environments are monitored | Gap -- not applicable at application level. | -- | N/A |
| DE.CM-03: Personnel activity is monitored | Audit log records all human actions: review sign-offs, disclosure approvals, with timestamp and reviewer identity. | P3 | `harness/findings.py:241-251` (audit write on human review) |
| DE.CM-06: External service provider activity is monitored | LLM API calls logged in audit: model, token counts, cost. Every LLM interaction recorded before execution. | P3, P6 | `harness/validator.py:75-89` (audit of validation call) |
| DE.CM-09: Computing hardware and software are monitored | Container exit events logged with exit code, stdout length, and error details. Timeout detection with forced container kill. | P3 | `harness/dispatcher.py:145-157, 170-182` |
| DE.AE-02: Potentially adverse events are analyzed | ASAN output parsed and classified by crash type and severity. Validation agent performs independent analysis. Three-question assessment framework. | -- | `harness/parser.py:150-202`, `harness/validator.py:16-37` |
| DE.AE-03: Information is correlated from multiple sources | Parser combines agent JSON output with ASAN stderr. Validation agent cross-references ASAN consistency, reproduction plausibility, and security meaningfulness. | -- | `harness/parser.py:166-172` (multiple source correlation) |
| DE.AE-06: Information on adverse events is provided to authorized staff | Findings enter human review queue ordered by severity. Reports include all context: description, reproduction, ASAN output, patch, agent reasoning, validation assessment. | P2, P7 | `harness/findings.py:15-63, 191-207` |
| DE.AE-07: Cyber threat intelligence and other contextual information are integrated | Gap -- planned. No integration with external threat intelligence (NVD, CVE databases). See issue #25. | -- | N/A |
| DE.AE-08: Incidents are declared based on criteria | Validation verdicts serve as incident declaration criteria: VALIDATE = confirmed incident, REJECT = non-incident, NEEDS_HUMAN_TRIAGE = requires human determination. | -- | `harness/validator.py:102-104` |

---

## RS: Respond

The Respond function supports the ability to take action regarding a detected cybersecurity incident.

| Subcategory | Mantis Implementation | Principle | Evidence |
|-------------|----------------------|-----------|----------|
| RS.MA-01: Incident response plan is executed | Incident response playbook provides step-by-step procedures for each severity tier. Four phases: Triage, Internal Review, Coordinated Disclosure, Post-Incident Review. | P2 | `docs/compliance/incident-response-playbook.md` |
| RS.MA-02: Incident reports are triaged | Severity tier (1-5) provides automatic triage. Validation agent routes findings. Human review queue ordered by priority. | P7 | `harness/parser.py:82-91`, `harness/findings.py:191-207` |
| RS.MA-03: Incidents are categorized | Crash taxonomy: heap-buffer-overflow, stack-buffer-overflow, use-after-free, use-after-return, null-dereference, memory-leak, global-buffer-overflow. Each mapped to severity tier with READ/WRITE distinction. | -- | `harness/parser.py:9-31` |
| RS.MA-04: Incidents are escalated | Escalation matrix in playbook: Tier 5 = CISO + Legal + Eng Lead within 4 hours; Tier 4 = Security Lead + Eng Lead within 24 hours; Tier 1 = monthly report. | P2 | `docs/compliance/incident-response-playbook.md` |
| RS.MA-05: Incidents are resolved | Human reviewer confirms finding, sets confirmed CVSS, approves/denies disclosure. Record updated in database with timestamp. Audit log entry written. | P2, P7 | `harness/findings.py:210-251` |
| RS.AN-03: Analysis is performed to establish what took place | Agent reasoning recorded in findings. ASAN output provides deterministic crash evidence. Reproduction commands allow independent verification. Full audit trail available. | P3 | `harness/findings.py:15-63`, `harness/audit.py:39-88` |
| RS.AN-06: Actions performed during investigation are recorded | Every action logged before execution (P3). Audit entries include sequence number, timestamp, actor, event type, and full payload. Hash chain ensures tamper evidence. | P3 | `harness/audit.py:39-88` |
| RS.AN-07: Incident data and metadata are collected and preserved | All finding data preserved in Postgres: raw agent output, parsed metadata, validation results, human review decisions. Sensitive fields encrypted (P8). Audit log preserved separately. | P3, P8 | `migrations/versions/001_initial_schema.py:58-87`, `harness/findings.py:114-156` |
| RS.AN-08: Incidents are analyzed for patterns | Gap -- partial. Individual findings analyzed. No cross-run pattern analysis or trend detection capability. See issue #28. | -- | N/A |
| RS.CO-02: Internal stakeholders are notified of incidents | Gap -- partial. Findings appear in human review queue. No push notification system (email, Slack, PagerDuty). See issue #23. | P2 | `harness/findings.py:191-207` |
| RS.CO-03: Information is shared with designated external stakeholders | P2 mandates human sign-off before any external communication. Coordinated disclosure follows 90+45 day timeline per incident response playbook. | P2 | `01-constitution.md:23-24`, `docs/compliance/incident-response-playbook.md` |
| RS.MI-01: Incidents are contained | Container isolation prevents lateral movement. Exploit code encrypted at rest. No autonomous external transmission. Containers destroyed after use. | P1, P5, P8 | `harness/dispatcher.py:34-76`, `harness/crypto.py:13-18` |
| RS.MI-02: Incidents are eradicated | Containers are ephemeral -- destroyed after each job (P5). tmpfs workspace cleared on exit. No persistent state to clean up. | P5 | `01-constitution.md:32-33`, `harness/dispatcher.py:34` |

---

## RC: Recover

The Recover function supports timely return to normal operations to reduce the impact of a cybersecurity incident.

| Subcategory | Mantis Implementation | Principle | Evidence |
|-------------|----------------------|-----------|----------|
| RC.RP-01: Recovery plan is executed | Container crash/timeout produces a failed-job record, not data loss (P5). Queue continues processing remaining jobs. Retry mechanism: failed containers retried once with different seed. | P5 | `01-constitution.md:32-33`, `02-specification.md:113-114` |
| RC.RP-02: Recovery actions are selected and performed | Failed containers automatically retried once. Timeout containers killed and job marked. Spend limit reached pauses dispatch (does not cancel running work). | P5 | `harness/dispatcher.py:112-157` |
| RC.RP-03: The integrity of backups and restored assets is verified | Audit log hash chain verification function validates integrity of recovered logs. `verify_chain()` returns the exact sequence number where corruption begins, if any. | P3 | `harness/audit.py:93-123` |
| RC.RP-04: Critical functions and services are restored | Gap -- partial. No automated service recovery (container orchestration restart, database failover). Kubernetes deployment would provide this. See issue #29. | -- | N/A |
| RC.RP-05: Recovery activities are verified | Audit chain verification provides integrity verification after recovery. Container re-execution capability allows re-running failed jobs. | P3 | `harness/audit.py:93-123` |
| RC.CO-03: Recovery activities are communicated | Gap -- planned. No automated communication of recovery status. See issue #23. | -- | N/A |
| RC.CO-04: Public updates on incident recovery are shared | P2 ensures no public communication without explicit human sign-off. Coordinated disclosure handles external communication timeline. | P2 | `01-constitution.md:23-24` |

---

## Summary: Principle-to-CSF Cross-Reference

| Principle | CSF Functions Addressed |
|-----------|------------------------|
| P1 -- Isolation is absolute | PR (PR.AA-05, PR.DS-02), DE (DE.CM-01), RS (RS.MI-01) |
| P2 -- Human review before external action | GV (GV.RR-01), RS (RS.CO-03, RS.MA-05), RC (RC.CO-04) |
| P3 -- Every action logged before execution | GV (GV.RR-02), PR (PR.PS-04), DE (DE.CM-03, DE.CM-06), RS (RS.AN-06, RS.AN-07) |
| P4 -- No credential persistence | PR (PR.AA-01), GV (GV.SC-02) |
| P5 -- Containers ephemeral and disposable | PR (PR.DS-10, PR.PS-05), RS (RS.MI-02), RC (RC.RP-01) |
| P6 -- Cost tracked in real time | GV (GV.RM-02), DE (DE.CM-06) |
| P7 -- Tool never decides severity alone | GV (GV.RR-01), ID (ID.RA-05), RS (RS.MA-02) |
| P8 -- Exploit code is contained | PR (PR.DS-01), RS (RS.MI-01, RS.AN-07) |

---

## Summary of Gaps

| Gap | CSF Subcategory | Description | Planned Remediation |
|-----|----------------|-------------|---------------------|
| Enterprise risk management integration | GV.RM-03 | No ERM tool integration | Issue #24 |
| Supply chain risk management | GV.SC-01 | No SBOM or dependency scanning | Issue #21 |
| Identity authentication | PR.AA-02, PR.AA-03 | No user authentication system | Issue #18 |
| Security training | PR.AT-01, PR.AT-02 | No training materials | Issue #19 |
| Data backups | PR.DS-11 | No automated backup procedures | Issue #27 |
| Threat intelligence integration | DE.AE-07 | No NVD/CVE integration | Issue #25 |
| Cross-run pattern analysis | RS.AN-08 | No trend detection | Issue #28 |
| Stakeholder notifications | RS.CO-02 | No push notifications | Issue #23 |
| Automated service recovery | RC.RP-04 | No orchestration-level recovery | Issue #29 |
