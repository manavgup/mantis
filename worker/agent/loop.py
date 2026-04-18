"""ReAct agent loop using litellm for provider-agnostic LLM access."""

import json
import re
import sys

import litellm

from .tools import TOOL_DEFINITIONS, execute_tool


def agent_loop(
    model: str,
    system_prompt: str,
    task_prompt: str,
    max_turns: int = 50,
) -> dict:
    """Run a ReAct agent loop that uses tools to investigate vulnerabilities.

    Returns the agent's final JSON verdict dict, or an error/inconclusive dict.
    """
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": task_prompt},
    ]

    total_input_tokens = 0
    total_output_tokens = 0
    total_cost_usd = 0.0

    for turn in range(max_turns):
        try:
            response = litellm.completion(
                model=model,
                messages=messages,
                tools=TOOL_DEFINITIONS,
                tool_choice="auto",
            )
        except Exception as e:
            return {
                "verdict": "inconclusive",
                "description": f"LLM call failed on turn {turn + 1}: {e}",
                "reasoning": f"Agent loop terminated due to API error: {e}",
                "turns_used": turn + 1,
                "cost_usd": total_cost_usd,
                "input_tokens": total_input_tokens,
                "output_tokens": total_output_tokens,
            }

        # Track usage
        if hasattr(response, "usage") and response.usage:
            total_input_tokens += response.usage.prompt_tokens or 0
            total_output_tokens += response.usage.completion_tokens or 0
        # litellm tracks cost in _hidden_params
        cost = getattr(response, "_hidden_params", {}).get("response_cost", 0)
        if cost:
            total_cost_usd += cost

        message = response.choices[0].message

        # Append assistant message to conversation
        messages.append(message.model_dump())

        # If no tool calls, the agent is done — extract verdict
        if not message.tool_calls:
            return _extract_verdict(
                message.content or "",
                turn + 1,
                total_cost_usd,
                total_input_tokens,
                total_output_tokens,
            )

        # Execute each tool call and append results
        for tool_call in message.tool_calls:
            try:
                arguments = json.loads(tool_call.function.arguments)
            except json.JSONDecodeError:
                arguments = {"command": tool_call.function.arguments}

            # Print tool calls to stderr for audit trail
            print(
                json.dumps({
                    "turn": turn + 1,
                    "tool": tool_call.function.name,
                    "arguments": arguments,
                }),
                file=sys.stderr,
            )

            result = execute_tool(tool_call.function.name, arguments)

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": result,
            })

    # Max turns exhausted
    return {
        "verdict": "inconclusive",
        "description": "Max turns reached without a final verdict.",
        "reasoning": "Agent exhausted all available turns.",
        "turns_used": max_turns,
        "cost_usd": total_cost_usd,
        "input_tokens": total_input_tokens,
        "output_tokens": total_output_tokens,
    }


def _parse_json_from_response(content: str) -> dict | None:
    """Extract a JSON verdict object from agent output, tolerating surrounding text.

    Strategies tried in order:
    1. Direct parse of entire content.
    2. Extract from ```json ... ``` fenced code block.
    3. Scan backward from end to find outermost balanced-brace JSON object.
    """
    if not content or not content.strip():
        return None

    # Strategy 1: entire content is JSON
    try:
        obj = json.loads(content)
        if isinstance(obj, dict):
            return obj
    except (json.JSONDecodeError, TypeError):
        pass

    # Strategy 2: fenced code block
    m = re.search(r"```(?:json)?\s*\n(\{.*?\})\s*\n```", content, re.DOTALL)
    if m:
        try:
            obj = json.loads(m.group(1))
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    # Strategy 3: find outermost JSON object by balanced-brace scan from the end
    end = content.rfind("}")
    while end >= 0:
        # Walk backward to find the matching opening brace
        depth = 0
        in_string = False
        escape = False
        start = None
        for i in range(end, -1, -1):
            ch = content[i]
            if escape:
                escape = False
                continue
            if ch == "\\" and in_string:
                escape = True
                continue
            if ch == '"' and not escape:
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "}":
                depth += 1
            elif ch == "{":
                depth -= 1
                if depth == 0:
                    start = i
                    break
        if start is not None:
            try:
                obj = json.loads(content[start : end + 1])
                if isinstance(obj, dict) and "verdict" in obj:
                    return obj
            except json.JSONDecodeError:
                pass
        # Try the next } to the left
        end = content.rfind("}", 0, end)

    return None


def _extract_verdict(
    content: str,
    turns_used: int,
    cost_usd: float,
    input_tokens: int,
    output_tokens: int,
) -> dict:
    """Parse the agent's final message into a structured verdict dict."""
    verdict = _parse_json_from_response(content)
    if verdict is None:
        verdict = {
            "verdict": "inconclusive",
            "description": "Could not parse agent output as JSON.",
            "reasoning": content,
        }

    # Augment with metadata
    verdict["turns_used"] = turns_used
    verdict["cost_usd"] = cost_usd
    verdict["input_tokens"] = input_tokens
    verdict["output_tokens"] = output_tokens
    return verdict
