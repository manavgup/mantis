"""LLM call abstraction — provider-agnostic via litellm."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import litellm

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
    system_prompt: str | None = None,
) -> LLMResponse:
    """Make a single-turn LLM call via litellm.

    Supports any litellm-compatible model string (e.g. 'anthropic/claude-opus-4-6',
    'openai/gpt-4o', 'ollama/llama3'). API keys are read from standard
    environment variables (ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.).
    """
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    response = await litellm.acompletion(
        model=model,
        messages=messages,
        max_tokens=max_tokens,
    )

    text = response.choices[0].message.content or ""
    input_tokens = response.usage.prompt_tokens or 0
    output_tokens = response.usage.completion_tokens or 0
    cost = getattr(response, "_hidden_params", {}).get("response_cost", 0) or 0.0

    return LLMResponse(
        text=text,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_usd=cost,
    )
