"""LLM call abstraction — routes through Claude Code CLI or direct Anthropic API."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    text: str
    input_tokens: int
    output_tokens: int
    cost_usd: float


async def call_llm(
    prompt: str,
    model: str,
    max_tokens: int = 4096,
    use_claude_code: bool = True,
    api_key: str | None = None,
) -> LLMResponse:
    """Make an LLM call via Claude Code CLI or direct Anthropic API.

    When use_claude_code=True (default), shells out to `claude --print`.
    No API key needed — Claude Code uses its own auth (Max subscription).

    When use_claude_code=False, uses the anthropic SDK directly.
    Requires api_key or ANTHROPIC_API_KEY env var.
    """
    if use_claude_code:
        return await _call_via_claude_code(prompt, model, max_tokens)
    else:
        return await _call_via_api(prompt, model, max_tokens, api_key)


async def _call_via_claude_code(
    prompt: str, model: str, max_tokens: int
) -> LLMResponse:
    """Call LLM via `claude --print` subprocess.

    Pipes the prompt via stdin to handle arbitrarily long prompts
    without hitting shell argument length limits.
    """
    import shutil

    claude_bin = shutil.which("claude")
    if claude_bin is None:
        raise RuntimeError("claude CLI not found in PATH. Install: npm install -g @anthropic-ai/claude-code")

    cmd = [
        claude_bin,
        "--print",
        "--model", model,
        "--output-format", "json",
        "--max-turns", "1",
        "-",  # read prompt from stdin
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_bytes, stderr_bytes = await proc.communicate(input=prompt.encode())

    if proc.returncode != 0:
        stderr_text = stderr_bytes.decode(errors="replace")
        raise RuntimeError(f"claude --print failed (exit {proc.returncode}): {stderr_text[:500]}")

    stdout_text = stdout_bytes.decode(errors="replace")

    # Claude Code --output-format json wraps output as:
    # {"type":"result","result":"...the text...","session_id":"...","cost_usd":0.01,...}
    response_text = stdout_text
    cost = 0.0
    input_tokens = 0
    output_tokens = 0

    try:
        outer = json.loads(stdout_text)
        if isinstance(outer, dict):
            if outer.get("type") == "result" and "result" in outer:
                response_text = outer["result"]
            cost = outer.get("cost_usd", 0.0) or 0.0
            input_tokens = outer.get("input_tokens", 0) or 0
            output_tokens = outer.get("output_tokens", 0) or 0
    except (json.JSONDecodeError, TypeError):
        pass

    return LLMResponse(
        text=response_text,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_usd=cost,
    )


async def _call_via_api(
    prompt: str, model: str, max_tokens: int, api_key: str | None
) -> LLMResponse:
    """Call LLM via direct Anthropic API."""
    import anthropic

    kwargs = {}
    if api_key:
        kwargs["api_key"] = api_key
    client = anthropic.AsyncAnthropic(**kwargs)

    response = await client.messages.create(
        model=model,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )

    response_text = response.content[0].text
    input_tokens = response.usage.input_tokens
    output_tokens = response.usage.output_tokens

    # Rough cost estimate (opus pricing as upper bound)
    cost = (input_tokens * 15 + output_tokens * 75) / 1_000_000

    return LLMResponse(
        text=response_text,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_usd=cost,
    )
