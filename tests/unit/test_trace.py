"""Tests for harness.trace — trace extraction, formatting, and LLM judge."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from harness.trace import JUDGE_RUBRIC, extract_trace, format_trace_markdown, judge_trace

# --- Trace extraction ---


def test_extract_trace_mixed_content():
    """Extracts only JSON tool-call lines from mixed stderr."""
    path = Path("tests/fixtures/sample_stderr_trace.jsonl")
    trace = extract_trace(path)
    assert len(trace) == 6
    assert trace[0] == {"turn": 1, "tool": "read_file", "arguments": {"path": "/tmp/src/lib/dgif_lib.c"}}
    assert trace[5]["turn"] == 6
    assert trace[5]["tool"] == "bash"


def test_extract_trace_empty_file(tmp_path):
    path = tmp_path / "empty.log"
    path.write_bytes(b"")
    assert extract_trace(path) == []


def test_extract_trace_no_json_lines(tmp_path):
    path = tmp_path / "no_json.log"
    path.write_text("=== starting ===\nBuild system: configure\n=== done ===\n")
    assert extract_trace(path) == []


def test_extract_trace_nonexistent_file(tmp_path):
    path = tmp_path / "does_not_exist.log"
    assert extract_trace(path) == []


def test_extract_trace_malformed_json(tmp_path):
    path = tmp_path / "bad.log"
    path.write_text(
        '{"turn": 1, "tool": "bash", "arguments": {"command": "ls"}}\n'
        "{invalid json\n"
        '{"turn": 2, "tool": "read_file", "arguments": {"path": "/x"}}\n'
    )
    trace = extract_trace(path)
    assert len(trace) == 2
    assert trace[0]["turn"] == 1
    assert trace[1]["turn"] == 2


# --- Trace formatting ---


def test_format_trace_markdown():
    trace = [
        {"turn": 1, "tool": "read_file", "arguments": {"path": "/tmp/src/lib/dgif_lib.c"}},
        {"turn": 2, "tool": "bash", "arguments": {"command": "python3 craft.py"}},
        {"turn": 3, "tool": "bash", "arguments": {"command": "/tmp/bin/gif2rgb /tmp/poc.gif"}},
    ]
    md = format_trace_markdown(trace, job_id="abc123", file_path="lib/dgif_lib.c", verdict="found")
    assert "## Agent Trace: lib/dgif_lib.c" in md
    assert "abc123" in md
    assert "found" in md
    assert "### Turn 1: read_file" in md
    assert "### Turn 2: bash" in md
    assert "### Turn 3: bash" in md
    assert "python3 craft.py" in md


# --- LLM judge ---


def test_judge_rubric_is_constant():
    """Rubric must be a non-empty string constant."""
    assert isinstance(JUDGE_RUBRIC, str)
    assert len(JUDGE_RUBRIC) > 100
    assert "hypothesis" in JUDGE_RUBRIC.lower()
    assert "methodology" in JUDGE_RUBRIC.lower()


@pytest.mark.asyncio
async def test_judge_trace_valid_response():
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = json.dumps(
        {
            "hypothesis_quality": 4,
            "methodology": 5,
            "tool_usage": 3,
            "persistence": 4,
            "overall": 4,
            "reasoning": "Good systematic approach",
        }
    )
    mock_response.usage = MagicMock(prompt_tokens=1000, completion_tokens=200)

    with patch("harness.trace.litellm.acompletion", new_callable=AsyncMock, return_value=mock_response):
        result = await judge_trace("trace content here", model="anthropic/claude-opus-4-7")

    assert result is not None
    assert result["hypothesis_quality"] == 4
    assert result["methodology"] == 5
    assert result["overall"] == 4
    assert result["judge_disagreement"] is False
    assert len(result["pass_scores"]) == 3


@pytest.mark.asyncio
async def test_judge_trace_temperature_zero():
    """Verify temperature=0 is passed to all judge calls."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = json.dumps(
        {
            "hypothesis_quality": 4,
            "methodology": 4,
            "tool_usage": 4,
            "persistence": 4,
            "overall": 4,
            "reasoning": "ok",
        }
    )
    mock_response.usage = MagicMock(prompt_tokens=1000, completion_tokens=200)

    with patch("harness.trace.litellm.acompletion", new_callable=AsyncMock, return_value=mock_response) as mock_call:
        await judge_trace("trace", model="anthropic/claude-opus-4-7")

    # Called 3 times (3 passes)
    assert mock_call.call_count == 3
    for call in mock_call.call_args_list:
        assert call.kwargs.get("temperature", call[1].get("temperature")) == 0


@pytest.mark.asyncio
async def test_judge_trace_disagreement_detection():
    """High score variance triggers disagreement flag."""
    responses = []
    for scores in [[2, 3, 2, 3, 2], [5, 5, 5, 5, 5], [3, 4, 3, 3, 3]]:
        mock_resp = MagicMock()
        mock_resp.choices = [MagicMock()]
        mock_resp.choices[0].message.content = json.dumps(
            {
                "hypothesis_quality": scores[0],
                "methodology": scores[1],
                "tool_usage": scores[2],
                "persistence": scores[3],
                "overall": scores[4],
                "reasoning": "test",
            }
        )
        mock_resp.usage = MagicMock(prompt_tokens=1000, completion_tokens=200)
        responses.append(mock_resp)

    with patch("harness.trace.litellm.acompletion", new_callable=AsyncMock, side_effect=responses):
        result = await judge_trace("trace", model="anthropic/claude-opus-4-7")

    assert result is not None
    assert result["judge_disagreement"] is True  # hypothesis_quality spans 2->5 (>2 points)


@pytest.mark.asyncio
async def test_judge_trace_invalid_json_response():
    """Non-JSON response returns None."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "I cannot score this trace because..."
    mock_response.usage = MagicMock(prompt_tokens=1000, completion_tokens=200)

    with patch("harness.trace.litellm.acompletion", new_callable=AsyncMock, return_value=mock_response):
        result = await judge_trace("trace", model="anthropic/claude-opus-4-7")

    assert result is None
