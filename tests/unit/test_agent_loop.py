"""Tests for worker agent loop."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


def _make_completion_response(content: str = "", tool_calls=None):
    """Create a mock litellm completion response."""
    message = MagicMock()
    message.content = content
    message.tool_calls = tool_calls
    message.model_dump.return_value = {
        "role": "assistant",
        "content": content,
        "tool_calls": None,
    }

    choice = MagicMock()
    choice.message = message

    response = MagicMock()
    response.choices = [choice]
    response.usage = MagicMock()
    response.usage.prompt_tokens = 100
    response.usage.completion_tokens = 50
    response._hidden_params = {"response_cost": 0.01}

    return response


def _make_tool_call(name: str, arguments: dict, call_id: str = "call_1"):
    tc = MagicMock()
    tc.id = call_id
    tc.function.name = name
    tc.function.arguments = json.dumps(arguments)
    return tc


class TestAgentLoop:
    def test_immediate_verdict(self):
        """Agent returns verdict on first turn without tool calls."""
        from worker.agent.loop import agent_loop

        verdict_json = json.dumps({
            "verdict": "not_found",
            "description": "No vulnerabilities found",
            "reasoning": "Code looks safe",
        })
        mock_response = _make_completion_response(content=verdict_json)

        with patch("worker.agent.loop.litellm") as mock_litellm:
            mock_litellm.completion.return_value = mock_response
            result = agent_loop(
                model="anthropic/claude-opus-4-6",
                system_prompt="You are a security researcher.",
                task_prompt="Analyze test.c",
                max_turns=5,
            )

        assert result["verdict"] == "not_found"
        assert result["turns_used"] == 1
        assert "cost_usd" in result

    def test_tool_call_then_verdict(self):
        """Agent makes a tool call, then returns verdict."""
        from worker.agent.loop import agent_loop

        # First response: tool call to read a file
        tool_call = _make_tool_call("read_file", {"path": "/target/src/test.c"})
        tool_response = _make_completion_response(tool_calls=[tool_call])
        tool_response.choices[0].message.model_dump.return_value = {
            "role": "assistant",
            "content": None,
            "tool_calls": [{"id": "call_1", "function": {"name": "read_file", "arguments": '{"path": "/target/src/test.c"}'}}],
        }

        # Second response: verdict
        verdict_json = json.dumps({
            "verdict": "found",
            "vuln_type": "heap-buffer-overflow",
            "description": "Buffer overflow in parse()",
            "reasoning": "Found OOB read",
        })
        verdict_response = _make_completion_response(content=verdict_json)

        with patch("worker.agent.loop.litellm") as mock_litellm:
            mock_litellm.completion.side_effect = [tool_response, verdict_response]
            with patch("worker.agent.loop.execute_tool", return_value="int main() { return 0; }"):
                result = agent_loop(
                    model="anthropic/claude-opus-4-6",
                    system_prompt="You are a security researcher.",
                    task_prompt="Analyze test.c",
                    max_turns=5,
                )

        assert result["verdict"] == "found"
        assert result["turns_used"] == 2

    def test_max_turns_exhausted(self):
        """Agent hits max turns without producing a verdict."""
        from worker.agent.loop import agent_loop

        # Every response is a tool call — never a final answer
        tool_call = _make_tool_call("bash", {"command": "ls"})
        tool_response = _make_completion_response(tool_calls=[tool_call])
        tool_response.choices[0].message.model_dump.return_value = {
            "role": "assistant",
            "content": None,
            "tool_calls": [{"id": "call_1", "function": {"name": "bash", "arguments": '{"command": "ls"}'}}],
        }

        with patch("worker.agent.loop.litellm") as mock_litellm:
            mock_litellm.completion.return_value = tool_response
            with patch("worker.agent.loop.execute_tool", return_value="/tmp/src"):
                result = agent_loop(
                    model="anthropic/claude-opus-4-6",
                    system_prompt="test",
                    task_prompt="test",
                    max_turns=3,
                )

        assert result["verdict"] == "inconclusive"
        assert result["turns_used"] == 3

    def test_api_error_returns_inconclusive(self):
        """API failure produces an inconclusive verdict, not an exception."""
        from worker.agent.loop import agent_loop

        with patch("worker.agent.loop.litellm") as mock_litellm:
            mock_litellm.completion.side_effect = Exception("Connection timeout")
            result = agent_loop(
                model="anthropic/claude-opus-4-6",
                system_prompt="test",
                task_prompt="test",
                max_turns=5,
            )

        assert result["verdict"] == "inconclusive"
        assert "Connection timeout" in result["description"]


class TestTools:
    def test_execute_bash(self):
        from worker.agent.tools import execute_bash

        result = execute_bash("echo hello")
        assert "hello" in result

    def test_execute_bash_timeout(self):
        from worker.agent.tools import execute_bash

        # Override timeout for test
        with patch("worker.agent.tools.TOOL_TIMEOUT_SECONDS", 1):
            result = execute_bash("sleep 10")
        assert "timed out" in result

    def test_read_file(self, tmp_path):
        from worker.agent.tools import read_file

        f = tmp_path / "test.txt"
        f.write_text("hello world")
        result = read_file(str(f))
        assert result == "hello world"

    def test_read_file_not_found(self):
        from worker.agent.tools import read_file

        result = read_file("/nonexistent/file.txt")
        assert "[error" in result

    def test_execute_tool_dispatch(self):
        from worker.agent.tools import execute_tool

        result = execute_tool("bash", {"command": "echo test"})
        assert "test" in result

        result = execute_tool("unknown_tool", {})
        assert "unknown tool" in result
