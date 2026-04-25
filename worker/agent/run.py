"""Entry point for the vulnerability research agent inside a worker container.

Reads configuration from environment variables, runs the ReAct agent loop,
and outputs the JSON verdict to stdout.
"""

import json
import os
import sys

from .loop import agent_loop


def main() -> None:
    model = os.environ.get("MODEL", "anthropic/claude-opus-4-6")
    max_turns = int(os.environ.get("MAX_TURNS", "50"))
    system_prompt_path = os.environ.get("SYSTEM_PROMPT_PATH", "/prompts/worker-system.txt")
    task_prompt = os.environ.get("TASK_PROMPT", "")

    if not task_prompt:
        print(
            json.dumps(
                {
                    "verdict": "inconclusive",
                    "description": "No TASK_PROMPT environment variable set.",
                    "reasoning": "Agent cannot run without a task prompt.",
                }
            )
        )
        sys.exit(1)

    # Load system prompt from file
    try:
        with open(system_prompt_path) as f:
            system_prompt = f.read()
    except FileNotFoundError:
        print(
            json.dumps(
                {
                    "verdict": "inconclusive",
                    "description": f"System prompt not found at {system_prompt_path}",
                    "reasoning": "Agent cannot run without a system prompt.",
                }
            )
        )
        sys.exit(1)

    # Run the agent loop
    result = agent_loop(
        model=model,
        system_prompt=system_prompt,
        task_prompt=task_prompt,
        max_turns=max_turns,
    )

    # Output the verdict as JSON to stdout
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
