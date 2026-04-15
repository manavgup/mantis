# Make LLM backends swappable across all stages

## Context
Currently the worker containers are tightly coupled to Claude Code CLI (`claude --print`) as the agent runtime. The orchestrator calls (ranking, validation) already have an abstraction layer (`harness/llm.py`) that could support multiple backends, but only Anthropic is implemented.

## Requirements
1. **Orchestrator calls (ranker, validator)** — Add OpenAI, Bedrock, and Vertex AI backends to `harness/llm.py`. These are single-turn prompts and straightforward to swap.
2. **Worker containers** — Research alternative agent runtimes that support non-Anthropic models:
   - OpenAI Codex CLI
   - Custom agent loop using OpenAI Responses API with tool use
   - Open-source frameworks (e.g., LangChain agents, CrewAI)
   - Evaluate whether each can match Claude Code's capabilities: multi-turn tool execution, shell access, prompt caching, context compaction
3. **Config** — Extend `harness.yaml` with a `backend` field per stage:
   ```yaml
   ranking_backend: claude_code | anthropic_api | openai_api
   worker_backend: claude_code | openai_codex | custom_agent
   validation_backend: claude_code | anthropic_api | openai_api
   ```

## Why not now
The Glasswing methodology specifically used Claude Code because of its battle-tested agentic loop. Swapping the worker runtime is rebuilding a core component, not a configuration change. The orchestrator side is easy; the worker side is a significant effort.

## Priority
Medium — address after v1 validation is complete.
