"""Stage 1: file ranking via LLM (provider-agnostic via litellm)."""

from __future__ import annotations

import fnmatch
import json
import logging
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from harness.audit import AuditLog
from harness.llm import call_llm

logger = logging.getLogger(__name__)

SOURCE_EXTENSIONS = {".c", ".cpp", ".h", ".cc", ".cxx", ".hpp"}

_RANKING_PROMPT_TEMPLATE = (
    "You are a security researcher triaging source files in a C/C++ project for vulnerability scanning.\n"
    "\n"
    "Score each file from 1 to 5 based on how likely it contains exploitable memory safety vulnerabilities:\n"
    "\n"
    "Score: 1 — constants, generated code, no logic\n"
    "Score: 2 — utility functions, low attack surface\n"
    "Score: 3 — internal data processing, moderate surface\n"
    "Score: 4 — parses external input, manages memory, handles auth\n"
    "Score: 5 — network I/O, file parsing of untrusted data, memory allocators, crypto\n"
    "\n"
    'Respond with a JSON array. Each element must have exactly these fields:\n'
    '  {{"path": "<file path>", "score": <1-5>, "reason": "<brief reason>"}}\n'
    "\n"
    "Return ONLY the JSON array, no other text.\n"
    "\n"
    "Files to score:\n"
    "{file_list}"
)


@dataclass
class RankedFile:
    path: str
    score: int
    reason: str


def _enumerate_source_files(
    repo_path: Path, exclude_patterns: list[str]
) -> list[str]:
    """Walk repo and collect source files, applying exclusion patterns."""
    files = []
    for p in sorted(repo_path.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix not in SOURCE_EXTENSIONS:
            continue
        rel = str(p.relative_to(repo_path))
        if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch("/" + rel, pat) for pat in exclude_patterns):
            continue
        files.append(rel)
    return files


def _parse_ranking_response(
    response_text: str, expected_files: list[str]
) -> list[RankedFile]:
    """Parse model response into RankedFile list, defaulting missing files to score 3."""
    text = response_text.strip()
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if match:
        text = match.group(0)

    try:
        items = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("Failed to parse ranking response as JSON, defaulting all to score 3")
        return [RankedFile(path=f, score=3, reason="parse failure — defaulted") for f in expected_files]

    scored: dict[str, RankedFile] = {}
    for item in items:
        path = item.get("path", "")
        score = item.get("score", 3)
        reason = item.get("reason", "")
        if not isinstance(score, int) or score < 1 or score > 5:
            score = 3
        scored[path] = RankedFile(path=path, score=score, reason=reason)

    results = []
    for f in expected_files:
        if f in scored:
            results.append(scored[f])
        else:
            logger.warning("File %s missing from ranking response, defaulting to score 3", f)
            results.append(RankedFile(path=f, score=3, reason="missing from model response — defaulted"))

    return results


async def rank_files(
    run_id: str,
    repo_path: Path,
    exclude_patterns: list[str],
    ranking_model: str,
    max_files_to_scan: int | None,
    audit: AuditLog,
) -> list[RankedFile]:
    """Rank source files by vulnerability likelihood via litellm."""
    all_files = _enumerate_source_files(repo_path, exclude_patterns)

    if not all_files:
        return []

    all_ranked: list[RankedFile] = []
    total_cost = 0.0

    batch_size = 200
    for i in range(0, len(all_files), batch_size):
        batch = all_files[i : i + batch_size]
        file_list = "\n".join(batch)
        prompt = _RANKING_PROMPT_TEMPLATE.format(file_list=file_list)

        last_exc = None
        for attempt in range(3):
            try:
                response = await call_llm(
                    prompt=prompt,
                    model=ranking_model,
                    max_tokens=4096,
                )
                break
            except Exception as e:
                last_exc = e
                if attempt < 2:
                    logger.warning("Ranking call failed (attempt %d): %s", attempt + 1, e)
                    continue
                raise last_exc from None

        total_cost += response.cost_usd

        audit.write(
            run_id=run_id,
            event_type="llm_call",
            actor="orchestrator",
            payload={
                "stage": "ranking",
                "model": ranking_model,
                "backend": "litellm",
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
                "cost_usd": round(response.cost_usd, 6),
                "batch_files": len(batch),
            },
        )

        ranked = _parse_ranking_response(response.text, batch)
        all_ranked.extend(ranked)

    all_ranked.sort(key=lambda r: (-r.score, r.path))

    if max_files_to_scan is not None:
        all_ranked = all_ranked[:max_files_to_scan]

    return all_ranked


def write_rankings_json(
    run_dir: Path,
    run_id: str,
    repo_url: str,
    repo_commit: str,
    ranked_files: list[RankedFile],
    total_files: int,
    excluded: int,
    cost: float,
) -> Path:
    """Write file_rankings.json to the run directory."""
    run_dir.mkdir(parents=True, exist_ok=True)
    output = {
        "run_id": run_id,
        "repo": repo_url,
        "commit": repo_commit,
        "ranked_files": [asdict(rf) for rf in ranked_files],
        "total_files": total_files,
        "excluded": excluded,
        "ranked": len(ranked_files),
        "ranking_cost_usd": round(cost, 6),
    }
    path = run_dir / "file_rankings.json"
    path.write_text(json.dumps(output, indent=2))
    return path
