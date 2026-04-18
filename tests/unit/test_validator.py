"""Tests for harness.validator — validation agent via litellm."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from harness.audit import AuditLog
from harness.llm import LLMResponse
from harness.parser import ParsedFinding
from harness.validator import validate_finding


@dataclass
class MockConfig:
    validation_model: str = "anthropic/claude-opus-4-6"


@pytest.fixture()
def audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture()
def sample_finding() -> ParsedFinding:
    return ParsedFinding(
        job_id="job-1",
        run_id="run-1",
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
        agent_reasoning="found the bug",
        description="heap overflow",
        raw_agent_output={},
    )


def _make_llm_response(response_json: dict) -> LLMResponse:
    return LLMResponse(
        text=json.dumps(response_json),
        input_tokens=500,
        output_tokens=200,
        cost_usd=0.02,
    )


@pytest.mark.asyncio
async def test_validate_verdict(sample_finding: ParsedFinding, audit_log: AuditLog):
    validation_response = {
        "asan_real": True,
        "repro_plausible": True,
        "security_meaningful": True,
        "verdict": "VALIDATE",
        "reasoning": "ASAN output is consistent with a real heap overflow",
    }
    mock_call = AsyncMock(return_value=_make_llm_response(validation_response))

    with patch("harness.validator.call_llm", mock_call):
        result = await validate_finding(sample_finding, MockConfig(), audit_log)

    assert result.verdict == "VALIDATE"
    assert result.asan_real is True
    assert result.repro_plausible is True


@pytest.mark.asyncio
async def test_reject_verdict(sample_finding: ParsedFinding, audit_log: AuditLog):
    validation_response = {
        "asan_real": False,
        "repro_plausible": False,
        "security_meaningful": False,
        "verdict": "REJECT",
        "reasoning": "Not a real bug",
    }
    mock_call = AsyncMock(return_value=_make_llm_response(validation_response))

    with patch("harness.validator.call_llm", mock_call):
        result = await validate_finding(sample_finding, MockConfig(), audit_log)

    assert result.verdict == "REJECT"


@pytest.mark.asyncio
async def test_malformed_json_raises(sample_finding: ParsedFinding, audit_log: AuditLog):
    bad_response = LLMResponse(
        text="This is not JSON at all",
        input_tokens=100,
        output_tokens=50,
        cost_usd=0.01,
    )
    mock_call = AsyncMock(return_value=bad_response)

    with patch("harness.validator.call_llm", mock_call):
        with pytest.raises(ValueError, match="malformed JSON"):
            await validate_finding(sample_finding, MockConfig(), audit_log)


@pytest.mark.asyncio
async def test_api_failure_retries(sample_finding: ParsedFinding, audit_log: AuditLog):
    mock_call = AsyncMock(side_effect=Exception("LLM error"))

    with patch("harness.validator.call_llm", mock_call):
        with pytest.raises(Exception, match="LLM error"):
            await validate_finding(sample_finding, MockConfig(), audit_log)

    assert mock_call.call_count == 3
