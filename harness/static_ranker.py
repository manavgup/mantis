"""Stage 1 alternative: static analysis file ranker.

Scores files by counting vulnerability-relevant patterns (unsafe calls,
input sources, memory management, pointer arithmetic) in actual source code.
Runs in ~2-3 seconds on 3000+ files. No LLM, no API cost.
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

from harness.audit import AuditLog
from harness.ranker import RankedFile, _enumerate_source_files

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled regex patterns (compiled once at module import)
# ---------------------------------------------------------------------------

_PATTERNS: dict[str, re.Pattern] = {
    "unsafe_calls": re.compile(r"\b(strcpy|strcat|sprintf|vsprintf|gets|scanf|sscanf|fscanf)\s*\("),
    "input_sources": re.compile(r"\b(fread|recv|recvfrom|fgets|getline|getenv)\s*\("),
    "memory_mgmt": re.compile(r"\b(malloc|calloc|realloc|free|mmap|munmap)\s*\("),
    "pointer_arith": re.compile(r"\*\s*\(\s*\w+\s*[+\-]|\w+\s*\[\s*[a-zA-Z_]\w*\s*[+\-\*]"),
    "memcpy": re.compile(r"\bmemcpy\s*\("),
}

# Path fragments that indicate high-risk code
_PATH_BONUS_PATTERNS = re.compile(r"(parser|codec|format|demux|mux|decode|encode|compress|decompress|crypt|proto|net)")
# Path fragments that indicate low-risk code
_PATH_PENALTY_PATTERNS = re.compile(
    r"(^test/|/test/|^tests/|/tests/|^doc/|/doc/|^docs/|/docs/|"
    r"^example/|/example/|^examples/|/examples/|^compat/|/compat/)"
)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class FileSignals:
    """Raw signal counts extracted from a single source file."""

    path: str
    loc: int = 0
    unsafe_calls: int = 0
    input_sources: int = 0
    memory_mgmt: int = 0
    pointer_arith: int = 0
    memcpy_count: int = 0
    path_bonus: float = 0.0
    raw_score: float = field(default=0.0, init=False)


# ---------------------------------------------------------------------------
# Core scoring functions (pure, no I/O)
# ---------------------------------------------------------------------------


def _score_path_heuristic(rel_path: str) -> float:
    """Return path-based bonus (+5) or penalty (-3) based on directory names."""
    bonus = 0.0
    if _PATH_BONUS_PATTERNS.search(rel_path.lower()):
        bonus += 5.0
    if _PATH_PENALTY_PATTERNS.search(rel_path.lower()):
        bonus -= 3.0
    return bonus


def _extract_signals(rel_path: str, content: str) -> FileSignals:
    """Extract all vulnerability signals from file content."""
    signals = FileSignals(path=rel_path)
    signals.loc = content.count("\n") + 1
    signals.unsafe_calls = len(_PATTERNS["unsafe_calls"].findall(content))
    signals.input_sources = len(_PATTERNS["input_sources"].findall(content))
    signals.memory_mgmt = len(_PATTERNS["memory_mgmt"].findall(content))
    signals.pointer_arith = len(_PATTERNS["pointer_arith"].findall(content))
    signals.memcpy_count = len(_PATTERNS["memcpy"].findall(content))
    signals.path_bonus = _score_path_heuristic(rel_path)
    return signals


def _compute_raw_score(signals: FileSignals) -> float:
    """Apply weights and multipliers to produce a raw score."""
    score = (
        signals.unsafe_calls * 3.0
        + signals.input_sources * 3.0
        + signals.memory_mgmt * 2.0
        + signals.pointer_arith * 2.0
        + signals.memcpy_count * 2.0
        + math.log2(signals.loc + 1) * 1.0
        + signals.path_bonus
    )

    # Source+sink multiplier: file reads input AND does unsafe operations
    if signals.input_sources > 0 and (signals.unsafe_calls > 0 or signals.memcpy_count > 0):
        score *= 1.5

    # Memory+pointer multiplier: manual memory AND pointer arithmetic
    if signals.memory_mgmt > 0 and signals.pointer_arith > 0:
        score *= 1.3

    return score


def _build_reason(signals: FileSignals) -> str:
    """Build a human-readable reason string from signal counts."""
    parts = []
    if signals.unsafe_calls:
        parts.append(f"{signals.unsafe_calls} unsafe calls")
    if signals.input_sources:
        parts.append(f"{signals.input_sources} input sources")
    if signals.memcpy_count:
        parts.append(f"{signals.memcpy_count} memcpy")
    if signals.memory_mgmt:
        parts.append(f"{signals.memory_mgmt} memory ops")
    if signals.pointer_arith:
        parts.append(f"{signals.pointer_arith} pointer arith")

    # Note multipliers
    has_source_sink = signals.input_sources > 0 and (signals.unsafe_calls > 0 or signals.memcpy_count > 0)
    has_mem_ptr = signals.memory_mgmt > 0 and signals.pointer_arith > 0
    if has_source_sink:
        parts.append("source+sink boost")
    if has_mem_ptr:
        parts.append("mem+ptr boost")

    parts.append(f"{signals.loc} LOC")

    reason = ", ".join(parts)
    return reason[:120]


def _normalize_scores(signals_list: list[FileSignals]) -> list[RankedFile]:
    """Normalize raw scores to 1-5 scale and produce RankedFile list."""
    if not signals_list:
        return []

    min_raw = min(s.raw_score for s in signals_list)
    max_raw = max(s.raw_score for s in signals_list)

    results = []
    for s in signals_list:
        if max_raw == min_raw:
            score = 3
        else:
            normalized = 1.0 + 4.0 * (s.raw_score - min_raw) / (max_raw - min_raw)
            score = max(1, min(5, round(normalized)))

        results.append(
            RankedFile(
                path=s.path,
                score=score,
                reason=_build_reason(s),
            )
        )

    return results


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

_MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


def _read_file_safe(file_path: Path) -> str | None:
    """Read file content safely. Returns None for binary or unreadable files."""
    try:
        raw = file_path.read_bytes()
    except (OSError, PermissionError):
        return None

    if len(raw) > _MAX_FILE_SIZE:
        return None

    # Binary detection: null bytes in first 8KB
    if b"\x00" in raw[:8192]:
        return None

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def rank_files_static(
    run_id: str,
    repo_path: Path,
    exclude_patterns: list[str],
    max_files_to_scan: int | None,
    audit: AuditLog,
) -> list[RankedFile]:
    """Rank source files by static analysis signals.

    Drop-in replacement for the LLM-based rank_files(). Reads actual file
    content and scores based on vulnerability-relevant code patterns.
    """
    all_files = _enumerate_source_files(repo_path, exclude_patterns)

    if not all_files:
        return []

    signals_list: list[FileSignals] = []
    skipped = 0

    for rel_path in all_files:
        full_path = repo_path / rel_path
        content = _read_file_safe(full_path)

        if content is None:
            signals_list.append(FileSignals(path=rel_path))
            skipped += 1
            continue

        signals = _extract_signals(rel_path, content)
        signals.raw_score = _compute_raw_score(signals)
        signals_list.append(signals)

    ranked = _normalize_scores(signals_list)
    ranked.sort(key=lambda r: (-r.score, r.path))

    if max_files_to_scan is not None:
        ranked = ranked[:max_files_to_scan]

    audit.write(
        run_id=run_id,
        event_type="llm_call",  # reuse event type for consistency
        actor="orchestrator",
        payload={
            "stage": "ranking",
            "model": "static-analysis",
            "backend": "static",
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_usd": 0.0,
            "total_files": len(all_files),
            "skipped_files": skipped,
            "ranked_files": len(ranked),
        },
    )

    logger.info(
        "Static ranking complete: %d files scored, %d skipped, top %d selected",
        len(all_files),
        skipped,
        len(ranked),
    )

    return ranked
