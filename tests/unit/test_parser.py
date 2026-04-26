"""Tests for harness.parser — ASAN output parsing and triage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.parser import parse_result


@pytest.fixture()
def sample_asan() -> str:
    return Path("tests/fixtures/sample_asan_output.txt").read_text()


@pytest.fixture()
def sample_agent() -> dict:
    return json.loads(Path("tests/fixtures/sample_agent_response.json").read_text())


def test_heap_buffer_overflow_read(sample_agent: dict):
    stdout = json.dumps(sample_agent)
    finding = parse_result(stdout, "", job_id="j1", run_id="r1")
    assert finding is not None
    assert finding.vuln_type == "heap-buffer-overflow"
    assert finding.severity_tier == 3  # READ
    assert 5.0 <= finding.cvss_estimate <= 7.5
    assert finding.file == "src/parser.c"
    assert finding.line == 247
    assert finding.function == "parse_chunk"


def test_heap_buffer_overflow_write():
    agent = {
        "verdict": "found",
        "vuln_type": "heap-buffer-overflow",
        "file": "src/alloc.c",
        "line": 100,
        "function": "my_alloc",
        "description": "heap overflow write",
        "asan_output": "ERROR: AddressSanitizer: heap-buffer-overflow\nWRITE of size 8",
        "confidence": "high",
        "reasoning": "test",
    }
    finding = parse_result(json.dumps(agent), "", job_id="j1", run_id="r1")
    assert finding is not None
    assert finding.severity_tier == 4  # WRITE
    assert 7.5 <= finding.cvss_estimate <= 9.0


def test_use_after_free():
    agent = {
        "verdict": "found",
        "vuln_type": "use-after-free",
        "file": "src/obj.c",
        "line": 55,
        "function": "free_obj",
        "description": "use after free",
        "asan_output": "ERROR: AddressSanitizer: heap-use-after-free\nREAD of size 4 in free_obj /src/obj.c:55",
        "confidence": "medium",
        "reasoning": "test",
    }
    finding = parse_result(json.dumps(agent), "", job_id="j1", run_id="r1")
    assert finding is not None
    assert finding.vuln_type == "use-after-free"
    assert finding.severity_tier == 3


def test_null_dereference():
    agent = {
        "verdict": "found",
        "vuln_type": "null-dereference",
        "file": "src/init.c",
        "line": 10,
        "function": "init",
        "description": "null deref",
        "asan_output": "ERROR: AddressSanitizer: null-dereference\nREAD of size 8",
        "confidence": "low",
        "reasoning": "test",
    }
    finding = parse_result(json.dumps(agent), "", job_id="j1", run_id="r1")
    assert finding is not None
    assert finding.severity_tier == 2
    assert 3.5 <= finding.cvss_estimate <= 5.0


def test_not_found_returns_none():
    agent = {
        "verdict": "not_found",
        "description": "no bugs found",
        "reasoning": "looked everywhere",
    }
    result = parse_result(json.dumps(agent), "", job_id="j1", run_id="r1")
    assert result is None


def test_missing_asan_falls_back_to_stderr(sample_asan: str):
    agent = {
        "verdict": "found",
        "vuln_type": None,
        "file": None,
        "line": None,
        "function": None,
        "description": "found a crash",
        "asan_output": None,
        "confidence": "medium",
        "reasoning": "test",
    }
    finding = parse_result(json.dumps(agent), sample_asan, job_id="j1", run_id="r1")
    assert finding is not None
    assert finding.vuln_type == "heap-buffer-overflow"
    assert finding.function == "parse_chunk"
    assert finding.file == "/src/parser.c"
    assert finding.line == 247


# --- Multi-sanitizer tests ---


@pytest.fixture()
def ubsan_output() -> str:
    return Path("tests/fixtures/ubsan_output.txt").read_text()


@pytest.fixture()
def msan_output() -> str:
    return Path("tests/fixtures/msan_output.txt").read_text()


@pytest.fixture()
def tsan_output() -> str:
    return Path("tests/fixtures/tsan_output.txt").read_text()


def test_ubsan_signed_integer_overflow(ubsan_output: str):
    """UBSan signed-integer-overflow detected from stderr, severity tier 3."""
    agent = {
        "verdict": "found",
        "vuln_type": None,
        "file": "/tmp/src/codec.c",
        "line": 142,
        "function": "encode_frame",
        "description": "signed integer overflow in codec",
        "asan_output": None,
        "confidence": "high",
        "reasoning": "test",
    }
    finding = parse_result(json.dumps(agent), ubsan_output, job_id="j1", run_id="r1")
    assert finding is not None
    assert finding.vuln_type == "signed-integer-overflow"
    assert finding.severity_tier == 3
    assert 5.0 <= finding.cvss_estimate <= 7.5


def test_msan_use_of_uninitialized_value(msan_output: str):
    """MSan use-of-uninitialized-value detected from stderr, severity tier 3."""
    agent = {
        "verdict": "found",
        "vuln_type": None,
        "file": None,
        "line": None,
        "function": None,
        "description": "read of uninitialized memory",
        "asan_output": None,
        "confidence": "high",
        "reasoning": "test",
    }
    finding = parse_result(json.dumps(agent), msan_output, job_id="j1", run_id="r1")
    assert finding is not None
    assert finding.vuln_type == "use-of-uninitialized-value"
    assert finding.severity_tier == 3
    assert 5.0 <= finding.cvss_estimate <= 7.5


def test_tsan_data_race(tsan_output: str):
    """TSan data-race detected from stderr, severity tier 3."""
    agent = {
        "verdict": "found",
        "vuln_type": None,
        "file": None,
        "line": None,
        "function": None,
        "description": "data race in counter",
        "asan_output": None,
        "confidence": "high",
        "reasoning": "test",
    }
    finding = parse_result(json.dumps(agent), tsan_output, job_id="j1", run_id="r1")
    assert finding is not None
    assert finding.vuln_type == "data-race"
    assert finding.severity_tier == 3
    assert 5.0 <= finding.cvss_estimate <= 7.5


def test_asan_still_works_with_multi_sanitizer_patterns(sample_asan: str):
    """Regression: existing ASAN output still parses correctly after adding new patterns."""
    agent = {
        "verdict": "found",
        "vuln_type": None,
        "file": None,
        "line": None,
        "function": None,
        "description": "heap overflow",
        "asan_output": None,
        "confidence": "medium",
        "reasoning": "test",
    }
    finding = parse_result(json.dumps(agent), sample_asan, job_id="j1", run_id="r1")
    assert finding is not None
    assert finding.vuln_type == "heap-buffer-overflow"
    assert finding.function == "parse_chunk"
    assert finding.file == "/src/parser.c"
    assert finding.line == 247
    assert finding.severity_tier == 3
