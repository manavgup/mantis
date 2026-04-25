# Mantis Incident Response Playbook

## When a Zero-Day Vulnerability is Discovered

**Document version**: 1.0
**Last updated**: 2026-04-25
**Applicable system**: Mantis Autonomous Vulnerability Discovery Harness
**Policy owner**: Security Operations Lead

---

## Overview

This playbook defines the operational procedures for handling vulnerability discoveries made by the Mantis system. It covers the full lifecycle from initial automated discovery through coordinated disclosure. All actions must comply with the P1-P8 principles defined in `01-constitution.md`.

**Cardinal rule (P2)**: No finding, disclosure, patch, or report reaches any external party without explicit human sign-off recorded in the audit log with timestamp and reviewer identity.

---

## Phase 1: Triage (Target: < 4 hours from discovery)

### 1.1 Automated Pre-Triage (System-Performed)

These steps are performed automatically by the Mantis pipeline before human involvement:

1. **ASAN parser extracts crash metadata** (`harness/parser.py:150-202`)
   - Crash type (heap-buffer-overflow, use-after-free, etc.)
   - READ or WRITE direction
   - Affected file, line, and function
   - Severity tier (1-5) assigned automatically

2. **CVSS estimate computed** (`harness/parser.py:88-91`)
   - Tier 5 (control flow hijack): 9.0-10.0
   - Tier 4 (arbitrary write): 7.5-9.0
   - Tier 3 (arbitrary read): 5.0-7.5
   - Tier 2 (DoS/crash): 3.5-5.0
   - Tier 1 (memory leak): 1.0-3.5

3. **Validation agent reviews finding** (`harness/validator.py:49-128`)
   - Is the ASAN output consistent with a real memory safety bug?
   - Is the reproduction case plausible and specific?
   - Is this a meaningful security issue?
   - Verdict: VALIDATE / REJECT / NEEDS_HUMAN_TRIAGE

4. **Finding stored encrypted** (`harness/findings.py:114-156`)
   - Exploit code, reproduction steps, and ASAN output encrypted with AES-256-GCM
   - Finding enters human review queue ordered by severity tier

5. **Audit trail established** (`harness/audit.py:39-88`)
   - All discovery actions logged in hash-chained JSONL before execution
   - Complete evidence chain from first tool call through validation verdict

### 1.2 Human Triage (First Responder)

When a finding appears in the human review queue (`harness/findings.py:191-207`):

1. **Confirm ASAN output is a real memory safety bug**
   - Review the ASAN output in the finding report
   - Check crash type matches the parser's classification
   - Verify the stack trace points to the reported file and function
   - If ASAN output is absent or unclear, mark for deeper investigation

2. **Review the validation agent verdict**
   - VALIDATE: high confidence, proceed with triage
   - NEEDS_HUMAN_TRIAGE: extra scrutiny required, agent was uncertain
   - REJECT: should not normally appear in review queue (log review recommended)

3. **Assess exploitability**
   - Is the crash reachable from external input?
   - Does the crash affect a commonly-used code path?
   - Is the READ/WRITE classification correct?
   - Could this be escalated beyond the assigned tier? (e.g., a controlled write that enables code execution = upgrade from Tier 4 to Tier 5)

4. **Assign incident severity**
   - Confirm or override the automated CVSS estimate
   - Record the confirmed CVSS in the database via `record_human_review()` (`harness/findings.py:210-251`)
   - The confirmed score replaces the estimate (`cvss_confirmed` column)

5. **Verify the reproduction case**
   - If possible, re-run the reproduction command in a fresh container
   - Confirm the ASAN crash is deterministic (reproduces consistently)
   - Document any modifications needed to reproduce

6. **Record triage decision in audit log**
   - Human review is recorded via `record_human_review()` which writes to both Postgres and audit log
   - Include: reviewer identity, confirmed CVSS, disclosure decision

---

## Phase 2: Internal Review (Target: < 24 hours from triage)

### 2.1 Assemble Review Team

Based on severity tier:

| Severity | Required Reviewers | Notification Method |
|----------|-------------------|---------------------|
| Tier 5 (RCE / control flow hijack) | CISO + Legal Counsel + Engineering Lead + Security Researcher | Direct contact (phone/in-person) |
| Tier 4 (Arbitrary write) | Security Lead + Engineering Lead + Security Researcher | Secure messaging |
| Tier 3 (Arbitrary read) | Security Lead + Security Researcher | Secure messaging |
| Tier 2 (DoS/crash) | Security Team | Standard channels |
| Tier 1 (Memory leak) | Security Team (batch review) | Weekly digest |

### 2.2 Technical Deep Dive

1. **Root cause analysis**
   - Review the agent's full reasoning chain (available in finding report and audit log)
   - Read the affected source code independently
   - Determine if the bug is in the target project or in a dependency
   - Identify all affected versions if possible

2. **Impact assessment**
   - What applications or products use the affected library?
   - Is the vulnerable code path reachable in common configurations?
   - Are there existing mitigations (ASLR, stack canaries, etc.) that reduce exploitability?
   - What is the worst-case impact if exploited?

3. **Candidate patch review**
   - Review the agent-generated patch (`candidate_patch` in finding)
   - Determine if the patch is correct and complete
   - Check for regressions -- does the fix break legitimate functionality?
   - Prepare a production-quality patch if the candidate is insufficient

4. **Classify finding for disclosure track**

   | Classification | Criteria | Disclosure Track |
   |---------------|----------|-----------------|
   | Critical (CVSS >= 9.0) | RCE, authentication bypass, data breach | Expedited: 30-day disclosure |
   | High (CVSS 7.0-8.9) | Arbitrary write, privilege escalation | Standard: 90-day disclosure |
   | Medium (CVSS 4.0-6.9) | Information leak, DoS | Standard: 90-day disclosure |
   | Low (CVSS < 4.0) | Memory leak, minor crash | Extended: 120-day or batch disclosure |

### 2.3 Legal Review (Tier 4-5 only)

1. Does the target project have a responsible disclosure policy?
2. Does the target project have a security contact (SECURITY.md, security@, HackerOne)?
3. Are there contractual obligations with the target project's maintainers?
4. Are there regulatory notification requirements (e.g., if the target is used in regulated infrastructure)?
5. Document legal review outcome in the audit log

---

## Phase 3: Coordinated Disclosure

### 3.1 Standard Timeline (90 + 45 days)

```
Day 0     : Vulnerability discovered by Mantis
Day 0-1   : Phase 1 triage (< 4 hours) + Phase 2 internal review (< 24 hours)
Day 1-7   : Prepare disclosure package
Day 7     : INITIAL CONTACT with upstream maintainer (private channel)
Day 7-14  : Confirm maintainer received report, establish communication channel
Day 14-90 : Remediation period (maintainer develops and tests fix)
Day 60    : Check-in with maintainer on progress
Day 90    : Public disclosure deadline (if patch available)
Day 90-135: Grace period (+45 days if maintainer requests and is actively working)
Day 135   : Final disclosure deadline (regardless of patch status)
```

### 3.2 Disclosure Package Contents

Prepare the following for the upstream maintainer (all content from encrypted findings store):

1. **Vulnerability summary**: type, affected file/function/line, severity assessment
2. **Reproduction steps**: exact commands to trigger the crash with ASAN
3. **ASAN output**: full sanitizer output showing the crash
4. **Candidate patch**: agent-generated fix (as a starting point, not guaranteed correct)
5. **Impact assessment**: exploitability analysis from Phase 2
6. **Contact information**: security team contact for follow-up questions

**Do NOT include**: raw audit log entries, agent reasoning chains, internal review notes, Mantis system configuration details.

### 3.3 Communication Channels (in preference order)

1. Project's established security reporting mechanism (SECURITY.md, HackerOne, Bugcrowd)
2. Security-specific email (security@project.org)
3. Direct encrypted email to maintainer (PGP/GPG)
4. Private issue on project's issue tracker (if supported)
5. Direct message to maintainer on established platform

All communications must be encrypted in transit. Record all outbound communications in the audit log.

### 3.4 CVE Assignment Process

1. **Determine CNA**: identify the appropriate CVE Numbering Authority
   - If the target project is a CNA, they assign the CVE
   - Otherwise, request through MITRE or the relevant root CNA
2. **Request CVE ID** after maintainer acknowledges the vulnerability
3. **Provide CVE details**: description, affected versions, CVSS score (human-confirmed), references
4. **Coordinate publication**: align CVE publication with patch availability

### 3.5 Escalation: Maintainer Non-Response

| Day | Action |
|-----|--------|
| Day 7 | Initial contact sent |
| Day 14 | If no response: second contact attempt via alternate channel |
| Day 21 | If no response: escalate to CERT/CC or relevant national CERT |
| Day 30 | If no response: notify CISO; begin planning unilateral disclosure |
| Day 90 | If no response and no patch: proceed with public disclosure per policy |

---

## Phase 4: Post-Incident Review (Target: < 2 weeks after disclosure)

### 4.1 Retrospective

Conduct a post-incident review covering:

1. **Timeline review**
   - How long from discovery to triage?
   - How long from triage to maintainer contact?
   - Was the 90+45 day timeline respected?
   - Were there avoidable delays?

2. **Quality assessment**
   - Was the ASAN output correctly interpreted?
   - Was the severity assessment accurate?
   - Was the candidate patch useful to the maintainer?
   - Did the validation agent correctly classify the finding?

3. **Process improvements**
   - What would have made triage faster?
   - Were the right people notified at the right time?
   - Are there tools or automation that would help?

4. **Mantis system improvements**
   - Should the parser's severity mapping be updated?
   - Should the validation prompt be refined?
   - Are there new crash types to add to the taxonomy?

### 4.2 Metrics to Track

| Metric | Target |
|--------|--------|
| Time from discovery to triage completion | < 4 hours |
| Time from triage to internal review completion | < 24 hours |
| Time from internal review to maintainer contact | < 7 days |
| False positive rate (findings rejected at human review) | < 20% |
| Validation agent accuracy (agreement with human reviewer) | > 80% |
| Maintainer response rate (within 14 days) | > 70% |
| Successful coordinated disclosure rate | > 90% |

### 4.3 Documentation

1. Archive the complete finding record (encrypted) per data retention policy
2. Update the finding's status in the database
3. Record the disclosure outcome in the audit log
4. If a CVE was assigned, record the CVE ID
5. File the retrospective notes for future reference

---

## Escalation Matrix

| Severity | Crash Category | Examples | Notification | Timeline |
|----------|---------------|----------|-------------|----------|
| Tier 5 (CVSS 9.0-10.0) | Control flow hijack | RIP/PC control, arbitrary write to code pointer, RCE | CISO + Legal + Engineering Lead | Within 4 hours of confirmation |
| Tier 4 (CVSS 7.5-9.0) | Arbitrary write | heap-buffer-overflow WRITE, stack-buffer-overflow WRITE | Security Lead + Engineering Lead | Within 24 hours |
| Tier 3 (CVSS 5.0-7.5) | Arbitrary read | heap-buffer-overflow READ, use-after-free READ | Security Lead | Within 48 hours |
| Tier 2 (CVSS 3.5-5.0) | DoS / crash | NULL dereference, stack overflow, abort | Security Team weekly digest | Next business day |
| Tier 1 (CVSS 1.0-3.5) | Memory leak only | LeakSanitizer finding, no crash | Security Team monthly report | Monthly |

Reference: `harness/parser.py:23-40` (severity tier definitions), `02-specification.md:275-283` (crash taxonomy)

---

## Special Scenarios

### S1: Vulnerability in Widely-Deployed Infrastructure (e.g., OpenSSL, glibc)

1. Escalate immediately to Tier 5 timeline regardless of CVSS score
2. Engage Legal within 4 hours
3. Contact national CERT (US-CERT, CERT/CC) in parallel with upstream maintainer
4. Consider embargo coordination with other known users of the affected software
5. Prepare customer advisory draft during remediation period

### S2: Duplicate Finding (vulnerability already known/disclosed)

1. Check NVD, CVE databases, and project issue tracker before initiating disclosure
2. If a CVE already exists: document the duplicate, close the finding, record in audit log
3. If being actively fixed: monitor for patch and verify the fix addresses the root cause
4. Report generation still has value: our reproduction case may differ from the original report

### S3: Finding in Mantis's Own Dependencies

1. Treat as an internal security incident
2. Assess if the vulnerability affects Mantis operation (e.g., in litellm, cryptography, asyncpg)
3. Apply patch immediately if available; pin to fixed version
4. If the vulnerability affects the `cryptography` library used for AES-256-GCM: emergency key rotation

### S4: Legal Hold / Litigation

1. Suspend all data destruction for related findings immediately
2. Preserve all audit logs, finding records, and human review reports
3. Disable cryptographic erasure for affected encryption keys
4. Notify Legal and Compliance
5. Document the hold scope and affected records in the audit log

### S5: Accidental Disclosure

If vulnerability details are accidentally made public before coordinated disclosure:

1. Immediately notify the upstream maintainer with full details
2. Escalate to CISO and Legal
3. Contact CERT/CC for emergency coordination
4. Request expedited CVE assignment
5. Prepare public advisory with available mitigations
6. Conduct root cause analysis of the accidental disclosure
7. Update procedures to prevent recurrence

---

## Roles and Responsibilities

| Role | Responsibilities |
|------|-----------------|
| **Security Researcher** (first responder) | Triage findings, verify reproduction, confirm severity, perform technical analysis |
| **Security Lead** | Approve disclosure decisions, coordinate with upstream maintainers, manage timelines |
| **Engineering Lead** | Review candidate patches, assess impact on downstream consumers |
| **CISO** | Approve Tier 5 disclosures, manage organizational risk, authorize CERT engagement |
| **Legal Counsel** | Review disclosure obligations, manage legal hold, advise on regulatory requirements |
| **Mantis Operator** | Run scans, manage infrastructure, escalate system issues |

---

## Audit Requirements

Every action in this playbook must satisfy P3 (every action logged before execution):

- Triage decisions recorded via `record_human_review()` (`harness/findings.py:210-251`)
- Disclosure approvals recorded in audit log with `event_type: "disclosure_approved"`
- Human reviewer identity recorded in both database and audit log
- All timestamps in UTC
- Audit log hash chain must verify cleanly at any point (`harness/audit.py:93-123`)

Audit log event types relevant to this playbook:
- `finding_validated`: automated validation complete (`harness/validator.py:114-127`)
- `human_review`: human triage complete (`harness/findings.py:241-251`)
- `disclosure_approved`: external communication authorized
- `disclosure_sent`: upstream maintainer contacted
- `disclosure_public`: vulnerability publicly disclosed
- `cve_assigned`: CVE ID assigned to finding
