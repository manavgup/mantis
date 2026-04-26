"""Stage 4: ASAN output parser and triage."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

ASAN_PATTERNS = {
    "heap-buffer-overflow": r"ERROR: AddressSanitizer: heap-buffer-overflow",
    "stack-buffer-overflow": r"ERROR: AddressSanitizer: stack-buffer-overflow",
    "use-after-free": r"ERROR: AddressSanitizer: heap-use-after-free",
    "use-after-return": r"ERROR: AddressSanitizer: stack-use-after-return",
    "null-dereference": r"ERROR: AddressSanitizer: null-dereference",
    "memory-leak": r"ERROR: LeakSanitizer: detected memory leaks",
    "global-buffer-overflow": r"ERROR: AddressSanitizer: global-buffer-overflow",
}

UBSAN_PATTERNS = {
    "signed-integer-overflow": r"runtime error: signed integer overflow",
    "unsigned-integer-overflow": r"runtime error: unsigned integer overflow",
    "shift-out-of-bounds": r"runtime error: shift exponent",
    "divide-by-zero": r"runtime error: division by zero",
    "null-pointer-use": r"runtime error: .*null pointer",
    "type-mismatch": r"runtime error: .*type mismatch",
    "invalid-bool-load": r"runtime error: load of value .* which is not a valid value for type 'bool'",
    "vla-bound-not-positive": r"runtime error: variable length array bound evaluates to non-positive",
    "float-cast-overflow": r"runtime error: .* is outside the range of representable values",
    "alignment-violation": r"runtime error: .* misaligned address",
}

MSAN_PATTERNS = {
    "use-of-uninitialized-value": r"WARNING: MemorySanitizer: use-of-uninitialized-value",
}

TSAN_PATTERNS = {
    "data-race": r"WARNING: ThreadSanitizer: data race",
    "thread-leak": r"WARNING: ThreadSanitizer: thread leak",
    "lock-order-inversion": r"WARNING: ThreadSanitizer: lock-order-inversion",
    "signal-unsafe-call": r"WARNING: ThreadSanitizer: signal-unsafe call",
}

READ_WRITE_PATTERN = r"(READ|WRITE) of size \d+"
LOCATION_PATTERN = r"in (\w+) ([^\s:]+):(\d+)"

# Severity tier mapping
SEVERITY_MAP = {
    # ASAN
    "heap-buffer-overflow": {"READ": 3, "WRITE": 4},
    "stack-buffer-overflow": {"READ": 3, "WRITE": 4},
    "use-after-free": {"READ": 3, "WRITE": 4},
    "use-after-return": {"READ": 3, "WRITE": 4},
    "null-dereference": {"READ": 2, "WRITE": 2},
    "global-buffer-overflow": {"READ": 3, "WRITE": 4},
    "memory-leak": {"READ": 1, "WRITE": 1},
    # UBSan
    "signed-integer-overflow": {"READ": 3, "WRITE": 3},
    "unsigned-integer-overflow": {"READ": 2, "WRITE": 2},
    "shift-out-of-bounds": {"READ": 2, "WRITE": 2},
    "divide-by-zero": {"READ": 2, "WRITE": 2},
    "null-pointer-use": {"READ": 2, "WRITE": 2},
    "type-mismatch": {"READ": 3, "WRITE": 3},
    "invalid-bool-load": {"READ": 2, "WRITE": 2},
    "vla-bound-not-positive": {"READ": 2, "WRITE": 2},
    "float-cast-overflow": {"READ": 2, "WRITE": 2},
    "alignment-violation": {"READ": 2, "WRITE": 2},
    # MSan
    "use-of-uninitialized-value": {"READ": 3, "WRITE": 3},
    # TSan
    "data-race": {"READ": 3, "WRITE": 3},
    "thread-leak": {"READ": 1, "WRITE": 1},
    "lock-order-inversion": {"READ": 2, "WRITE": 2},
    "signal-unsafe-call": {"READ": 2, "WRITE": 2},
}

# CVSS ranges by tier
CVSS_RANGES = {
    5: (9.0, 10.0),
    4: (7.5, 9.0),
    3: (5.0, 7.5),
    2: (3.5, 5.0),
    1: (1.0, 3.5),
}


@dataclass
class ParsedFinding:
    job_id: str
    run_id: str
    file: str | None
    line: int | None
    function: str | None
    vuln_type: str | None
    crash_rw: str | None
    severity_tier: int
    cvss_estimate: float
    asan_summary: str | None
    reproduction: str | None
    candidate_patch: str | None
    agent_confidence: str | None
    agent_reasoning: str | None
    description: str | None
    raw_agent_output: dict


def _detect_vuln_type(asan_text: str) -> str | None:
    for patterns in (ASAN_PATTERNS, UBSAN_PATTERNS, MSAN_PATTERNS, TSAN_PATTERNS):
        for vuln_type, pattern in patterns.items():
            if re.search(pattern, asan_text):
                return vuln_type
    return None


def _detect_rw(asan_text: str) -> str | None:
    m = re.search(READ_WRITE_PATTERN, asan_text)
    return m.group(1) if m else None


def _extract_location(asan_text: str) -> tuple[str | None, str | None, int | None]:
    m = re.search(LOCATION_PATTERN, asan_text)
    if m:
        return m.group(1), m.group(2), int(m.group(3))
    return None, None, None


def _assign_severity(vuln_type: str | None, rw: str | None) -> int:
    if vuln_type is None:
        return 2  # default crash tier
    mapping = SEVERITY_MAP.get(vuln_type, {"READ": 2, "WRITE": 2})
    return mapping.get(rw or "READ", 2)


def _estimate_cvss(tier: int) -> float:
    low, high = CVSS_RANGES.get(tier, (3.5, 5.0))
    return round((low + high) / 2, 1)


def _extract_agent_json(stdout: str) -> dict:
    """Extract the agent's finding JSON from stdout.

    Claude Code with --output-format json wraps output in:
      {"type":"result","result":"...text with embedded JSON..."}
    We need to unwrap that and find the inner JSON with the verdict.
    """
    outer: dict = {}
    try:
        outer = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        pass

    # If outer parse succeeded, check for Claude Code wrapper
    if outer.get("type") == "result" and "result" in outer:
        # The 'result' field is the agent's text output — extract JSON from it
        result_text = outer["result"]
        if isinstance(result_text, str):
            # Try to find a JSON code block first
            code_block = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", result_text, re.DOTALL)
            if code_block:
                try:
                    return json.loads(code_block.group(1))
                except json.JSONDecodeError:
                    pass
            # Fall back to finding any JSON object with a verdict field
            for m in re.finditer(r"\{[^{}]*\"verdict\"[^{}]*\}", result_text, re.DOTALL):
                try:
                    return json.loads(m.group(0))
                except json.JSONDecodeError:
                    continue
            # Last resort: find the largest JSON object
            match = re.search(r"\{.*\}", result_text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass
        elif isinstance(result_text, dict):
            return result_text

    # If outer itself has verdict, it's direct agent output
    if "verdict" in outer:
        return outer

    # Fall back to searching for JSON in raw stdout
    match = re.search(r"\{.*\}", stdout, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return {}


def parse_result(
    stdout: str,
    stderr: str,
    job_id: str = "",
    run_id: str = "",
) -> ParsedFinding | None:
    """Parse agent JSON output and stderr. Returns None if verdict is not 'found'."""
    agent_json = _extract_agent_json(stdout)

    verdict = agent_json.get("verdict", "not_found")
    if verdict != "found":
        return None

    # Get ASAN output — prefer agent's copy, fall back to stderr
    asan_output = agent_json.get("asan_output") or stderr or ""

    vuln_type = agent_json.get("vuln_type") or _detect_vuln_type(asan_output)
    rw = _detect_rw(asan_output)

    # Location — prefer agent's explicit values, fall back to ASAN parsing
    func_name, file_path, line_num = _extract_location(asan_output)
    file_path = agent_json.get("file") or file_path
    line_num = agent_json.get("line") or line_num
    func_name = agent_json.get("function") or func_name

    tier = _assign_severity(vuln_type, rw)
    cvss = _estimate_cvss(tier)

    # Build ASAN summary line
    asan_summary = None
    if vuln_type and asan_output:
        rw_str = f" {rw}" if rw else ""
        loc_str = f" in {func_name} {file_path}:{line_num}" if func_name else ""
        asan_summary = f"{vuln_type}{rw_str}{loc_str}"

    return ParsedFinding(
        job_id=job_id,
        run_id=run_id,
        file=file_path,
        line=line_num,
        function=func_name,
        vuln_type=vuln_type,
        crash_rw=rw,
        severity_tier=tier,
        cvss_estimate=cvss,
        asan_summary=asan_summary,
        reproduction=agent_json.get("reproduction"),
        candidate_patch=agent_json.get("candidate_patch"),
        agent_confidence=agent_json.get("confidence"),
        agent_reasoning=agent_json.get("reasoning"),
        description=agent_json.get("description"),
        raw_agent_output=agent_json,
    )
