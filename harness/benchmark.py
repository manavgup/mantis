"""Benchmark metrics extraction, aggregation, and comparison table generation."""

from __future__ import annotations

import json
import re
import statistics
from pathlib import Path

MODEL_PATTERN = re.compile(r"^[a-z][a-z0-9_-]*/[a-zA-Z0-9._:-]+$")


def validate_model_string(model: str) -> bool:
    """Validate a litellm model string matches provider/model format.

    Rejects empty strings, strings > 100 chars, and non-matching patterns.
    """
    return bool(model) and len(model) <= 100 and bool(MODEL_PATTERN.match(model))


def extract_run_metrics(audit_path: Path) -> dict:
    """Extract benchmark metrics from a single run's audit log.

    Handles both old-format (no telemetry) and new-format audit logs gracefully.
    """
    events = []
    with open(audit_path) as f:
        for line in f:
            stripped = line.strip()
            if stripped:
                events.append(json.loads(stripped))

    jobs_dispatched = 0
    findings_count = 0
    validated_count = 0
    rejected_count = 0
    total_wall_clock = 0.0
    total_worker_cost = 0.0
    total_validation_cost = 0.0
    total_input_tokens = 0
    total_output_tokens = 0
    turn_counts: list[float] = []

    for event in events:
        et = event["event_type"]
        payload = event.get("payload", {})

        if et == "job_dispatch":
            jobs_dispatched += 1

        elif et == "container_exit":
            total_wall_clock += payload.get("wall_clock_seconds", 0.0)
            turns = payload.get("turns_used")
            if turns is not None:
                turn_counts.append(turns)
            total_worker_cost += payload.get("cost_usd", 0.0)
            total_input_tokens += payload.get("input_tokens", 0)
            total_output_tokens += payload.get("output_tokens", 0)
            # Only count as finding if verdict is "found" (not timeout, not not_found)
            if payload.get("verdict") == "found":
                findings_count += 1

        elif et == "llm_call" and payload.get("stage") == "validation":
            total_validation_cost += payload.get("cost_usd", 0.0)

        elif et == "finding_validated":
            verdict = payload.get("verdict", "")
            if verdict == "VALIDATE":
                validated_count += 1
            elif verdict == "REJECT":
                rejected_count += 1

    total_judged = validated_count + rejected_count
    fp_rate = (rejected_count / total_judged * 100) if total_judged > 0 else 0.0

    return {
        "jobs_dispatched": jobs_dispatched,
        "findings_count": findings_count,
        "validated_count": validated_count,
        "rejected_count": rejected_count,
        "false_positive_rate": round(fp_rate, 1),
        "total_wall_clock_seconds": total_wall_clock,
        "total_worker_cost_usd": total_worker_cost,
        "total_validation_cost_usd": total_validation_cost,
        "total_cost_usd": round(total_worker_cost + total_validation_cost, 6),
        "avg_turns_per_job": round(statistics.mean(turn_counts), 1) if turn_counts else 0.0,
        "total_input_tokens": total_input_tokens,
        "total_output_tokens": total_output_tokens,
    }


def aggregate_trials(trials: list[dict]) -> dict:
    """Aggregate metrics across multiple trials of the same model."""
    n = len(trials)
    if n == 0:
        return {"trials": 0}

    def avg(key: str) -> float:
        return round(sum(t.get(key, 0) for t in trials) / n, 2)

    def std(key: str) -> float:
        if n < 2:
            return 0.0
        values = [t.get(key, 0) for t in trials]
        return round(statistics.stdev(values), 2)

    return {
        "trials": n,
        "avg_findings": avg("findings_count"),
        "avg_validated": avg("validated_count"),
        "avg_cost_usd": round(avg("total_cost_usd"), 4),
        "avg_turns_per_job": avg("avg_turns_per_job"),
        "avg_wall_clock_seconds": avg("total_wall_clock_seconds"),
        "std_findings": std("findings_count"),
        "std_cost_usd": std("total_cost_usd"),
    }


def format_comparison_table(results: dict[str, dict], known_findings: int = 3) -> str:
    """Format aggregated results as a markdown comparison table."""
    lines = [
        "| Model | Trials | Avg Findings | Discovery Rate | FP Rate | Avg Cost | Avg Turns/Job | Avg Time (s) |",
        "|-------|--------|-------------|----------------|---------|----------|---------------|--------------|",
    ]
    for model, agg in sorted(results.items(), key=lambda x: x[1].get("avg_validated", 0), reverse=True):
        if known_findings > 0:
            rate = f"{agg['avg_validated'] / known_findings * 100:.0f}%"
        else:
            rate = "N/A"
        lines.append(
            f"| {model} | {agg['trials']} | {agg['avg_findings']:.1f} | "
            f"{rate} | {agg.get('avg_fp_rate', 0.0):.0f}% | ${agg['avg_cost_usd']:.4f} | "
            f"{agg['avg_turns_per_job']:.1f} | {agg['avg_wall_clock_seconds']:.0f} |"
        )
    return "\n".join(lines)
