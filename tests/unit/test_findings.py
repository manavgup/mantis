"""Tests for harness.findings — findings store and report generator."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from harness.audit import AuditLog
from harness.crypto import encrypt
from harness.findings import generate_report, record_human_review, store_finding
from harness.parser import ParsedFinding
from harness.validator import ValidationResult


@pytest.fixture()
def enc_key() -> bytes:
    return os.urandom(32)


@pytest.fixture()
def sample_finding() -> ParsedFinding:
    return ParsedFinding(
        job_id="00000000-0000-0000-0000-000000000001",
        run_id="00000000-0000-0000-0000-000000000002",
        file="src/parser.c",
        line=247,
        function="parse_chunk",
        vuln_type="heap-buffer-overflow",
        crash_rw="READ",
        severity_tier=3,
        cvss_estimate=6.2,
        asan_summary="heap-buffer-overflow READ in parse_chunk",
        reproduction="echo AAAA | ./parser",
        candidate_patch="--- a/src/parser.c\n+++ b/src/parser.c",
        agent_confidence="high",
        agent_reasoning="found the bug by examining buffer allocation",
        description="Heap buffer overflow in parse_chunk",
        raw_agent_output={},
    )


@pytest.fixture()
def sample_validation() -> ValidationResult:
    return ValidationResult(
        asan_real=True,
        repro_plausible=True,
        security_meaningful=True,
        verdict="VALIDATE",
        reasoning="ASAN output is consistent with a real heap overflow",
    )


@pytest.fixture()
def audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.mark.asyncio
async def test_store_finding_encrypts_fields(
    sample_finding: ParsedFinding,
    sample_validation: ValidationResult,
    enc_key: bytes,
):
    """store_finding should encrypt reproduction, patch, and asan_output."""
    mock_conn = AsyncMock()

    with patch("harness.findings.asyncpg.connect", return_value=mock_conn):
        finding_id = await store_finding(
            sample_finding, sample_validation,
            run_id="00000000-0000-0000-0000-000000000002",
            job_id="00000000-0000-0000-0000-000000000001",
            enc_key=enc_key,
            postgres_url="postgresql://test",
        )

    assert finding_id  # non-empty UUID string
    mock_conn.execute.assert_called_once()

    # The encrypted fields are passed as bytes (not None)
    call_args = mock_conn.execute.call_args[0]
    # reproduction_enc is arg index 11, patch_enc is 12, asan_output_enc is 13
    reproduction_enc = call_args[11]
    patch_enc = call_args[12]
    asan_enc = call_args[13]

    assert isinstance(reproduction_enc, bytes)
    assert isinstance(patch_enc, bytes)
    assert isinstance(asan_enc, bytes)

    # Verify they're actual encrypted data (nonce + ciphertext), not plaintext
    assert reproduction_enc != sample_finding.reproduction.encode()


def test_generate_report_has_all_sections(
    sample_finding: ParsedFinding,
    sample_validation: ValidationResult,
):
    report = generate_report(
        sample_finding, sample_validation,
        run_id="run-123", finding_id="find-456",
        project_name="TestProject",
    )

    # Check all required sections
    assert "# Finding:" in report
    assert "## Description" in report
    assert "## Reproduction" in report
    assert "## ASAN output" in report
    assert "## Candidate patch" in report
    assert "## Agent reasoning" in report
    assert "## Validation agent assessment" in report
    assert "## Reviewer sign-off" in report

    # Check specific content
    assert "heap-buffer-overflow" in report
    assert "src/parser.c" in report
    assert "VALIDATE" in report
    assert "run-123" in report
    assert "find-456" in report


@pytest.mark.asyncio
async def test_record_human_review_logs_audit(audit_log: AuditLog):
    mock_conn = AsyncMock()

    with patch("harness.findings.asyncpg.connect", return_value=mock_conn):
        await record_human_review(
            finding_id="00000000-0000-0000-0000-000000000001",
            reviewer="alice",
            cvss_confirmed=7.5,
            approve_disclosure=True,
            postgres_url="postgresql://test",
            audit=audit_log,
        )

    mock_conn.execute.assert_called_once()
    assert audit_log.path.exists()

    import json
    lines = [l for l in audit_log.path.read_text().splitlines() if l.strip()]
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["event_type"] == "human_review"
    assert entry["actor"] == "human:alice"
    assert entry["payload"]["cvss_confirmed"] == 7.5
