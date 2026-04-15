"""Findings store (Postgres) and report generator."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import asyncpg

from harness.audit import AuditLog
from harness.crypto import encrypt
from harness.parser import ParsedFinding
from harness.validator import ValidationResult

REPORT_TEMPLATE = """\
# Finding: {vuln_type} in {project_name}

**Status**: Awaiting human review
**Severity tier**: {severity_tier} / 5
**CVSS estimate**: {cvss_estimate} (unconfirmed)
**File**: {file}:{line} in `{function}`
**Run ID**: {run_id}
**Finding ID**: {finding_id}
**Discovered**: {timestamp}

## Description
{description}

## Reproduction
```bash
{reproduction}
```

## ASAN output
```
{asan_output}
```

## Candidate patch
```diff
{candidate_patch}
```

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
"""


async def ensure_run_exists(
    run_id: str,
    repo_url: str,
    repo_commit: str,
    postgres_url: str,
) -> None:
    """Insert run record if it doesn't exist (upsert)."""
    conn = await asyncpg.connect(postgres_url)
    try:
        await conn.execute(
            """
            INSERT INTO runs (run_id, repo_url, repo_commit, started_at, status)
            VALUES ($1, $2, $3, NOW(), 'running')
            ON CONFLICT (run_id) DO NOTHING
            """,
            uuid.UUID(run_id), repo_url, repo_commit,
        )
    finally:
        await conn.close()


async def ensure_job_exists(
    job_id: str,
    run_id: str,
    file_path: str,
    priority_score: int,
    postgres_url: str,
) -> None:
    """Insert job record if it doesn't exist (upsert)."""
    conn = await asyncpg.connect(postgres_url)
    try:
        await conn.execute(
            """
            INSERT INTO jobs (job_id, run_id, file_path, priority_score, status)
            VALUES ($1, $2, $3, $4, 'completed')
            ON CONFLICT (job_id) DO NOTHING
            """,
            uuid.UUID(job_id), uuid.UUID(run_id), file_path, priority_score,
        )
    finally:
        await conn.close()


async def store_finding(
    finding: ParsedFinding,
    validation: ValidationResult,
    run_id: str,
    job_id: str,
    enc_key: bytes,
    postgres_url: str,
) -> str:
    """Insert finding into Postgres with encrypted sensitive fields. Returns finding_id."""
    finding_id = str(uuid.uuid4())

    reproduction_enc = encrypt(finding.reproduction or "", enc_key) if finding.reproduction else None
    patch_enc = encrypt(finding.candidate_patch or "", enc_key) if finding.candidate_patch else None
    asan_enc = encrypt(finding.asan_summary or "", enc_key) if finding.asan_summary else None

    conn = await asyncpg.connect(postgres_url)
    try:
        await conn.execute(
            """
            INSERT INTO findings (
                finding_id, job_id, run_id, vuln_type, file_path, line_number,
                function_name, severity_tier, cvss_estimate, validation_verdict,
                reproduction_enc, patch_enc, asan_output_enc
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            """,
            uuid.UUID(finding_id),
            uuid.UUID(job_id),
            uuid.UUID(run_id),
            finding.vuln_type,
            finding.file,
            finding.line,
            finding.function,
            finding.severity_tier,
            finding.cvss_estimate,
            validation.verdict,
            reproduction_enc,
            patch_enc,
            asan_enc,
        )
    finally:
        await conn.close()

    return finding_id


def generate_report(
    finding: ParsedFinding,
    validation: ValidationResult,
    run_id: str,
    finding_id: str,
    project_name: str = "",
) -> str:
    """Render the markdown human-review report for a finding."""
    return REPORT_TEMPLATE.format(
        vuln_type=finding.vuln_type or "Unknown",
        project_name=project_name,
        severity_tier=finding.severity_tier,
        cvss_estimate=finding.cvss_estimate,
        file=finding.file or "unknown",
        line=finding.line or "?",
        function=finding.function or "unknown",
        run_id=run_id,
        finding_id=finding_id,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        description=finding.description or "",
        reproduction=finding.reproduction or "N/A",
        asan_output=finding.asan_summary or "N/A",
        candidate_patch=finding.candidate_patch or "N/A",
        agent_reasoning=finding.agent_reasoning or "",
        asan_real=validation.asan_real,
        repro_plausible=validation.repro_plausible,
        security_meaningful=validation.security_meaningful,
        verdict=validation.verdict,
        validation_reasoning=validation.reasoning,
    )


async def list_pending_review(run_id: str, postgres_url: str) -> list[dict]:
    """Return findings awaiting human review, ordered by severity_tier desc."""
    conn = await asyncpg.connect(postgres_url)
    try:
        rows = await conn.fetch(
            """
            SELECT finding_id, vuln_type, file_path, line_number, function_name,
                   severity_tier, cvss_estimate, validation_verdict
            FROM findings
            WHERE run_id = $1 AND human_reviewed = FALSE
            ORDER BY severity_tier DESC
            """,
            uuid.UUID(run_id),
        )
        return [dict(r) for r in rows]
    finally:
        await conn.close()


async def record_human_review(
    finding_id: str,
    reviewer: str,
    cvss_confirmed: float,
    approve_disclosure: bool,
    postgres_url: str,
    audit: AuditLog | None = None,
) -> None:
    """Record human review sign-off on a finding."""
    now = datetime.now(timezone.utc)
    conn = await asyncpg.connect(postgres_url)
    try:
        await conn.execute(
            """
            UPDATE findings SET
                human_reviewed = TRUE,
                human_reviewer = $2,
                cvss_confirmed = $3,
                disclosure_approved = $4,
                reviewed_at = $5
            WHERE finding_id = $1
            """,
            uuid.UUID(finding_id),
            reviewer,
            cvss_confirmed,
            approve_disclosure,
            now,
        )
    finally:
        await conn.close()

    if audit:
        audit.write(
            run_id="",
            event_type="human_review",
            actor=f"human:{reviewer}",
            payload={
                "finding_id": finding_id,
                "cvss_confirmed": cvss_confirmed,
                "disclosure_approved": approve_disclosure,
            },
        )
