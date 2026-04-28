"""Tests for harness.benchmark — metric extraction, aggregation, and validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.benchmark import (
    aggregate_trials,
    extract_run_metrics,
    format_comparison_table,
    validate_model_string,
)

# --- Model string validation ---


@pytest.mark.parametrize(
    "model",
    [
        "anthropic/claude-sonnet-4-6",
        "openai/gpt-5.4",
        "ollama/granite-code:8b",
        "ollama/qwen3-coder:32b",
        "openai/gpt-4o",
    ],
)
def test_validate_model_string_valid(model):
    assert validate_model_string(model) is True


@pytest.mark.parametrize(
    "model",
    [
        "gpt-5.4",  # no provider
        "anthropic/",  # no model
        "foo bar/baz",  # space
        "",  # empty
        "/model",  # no provider
        "UPPER/case",  # uppercase provider
    ],
)
def test_validate_model_string_invalid(model):
    assert validate_model_string(model) is False


def test_validate_model_string_too_long():
    """Model strings over 100 chars are rejected."""
    long_model = "anthropic/" + "a" * 100
    assert validate_model_string(long_model) is False


# --- Metric extraction ---


def _write_audit(tmp_path: Path, entries: list[dict]) -> Path:
    path = tmp_path / "audit.jsonl"
    with open(path, "w") as f:
        for e in entries:
            f.write(json.dumps(e, sort_keys=True) + "\n")
    return path


def test_extract_run_metrics_full(tmp_path):
    entries = [
        {"seq": 1, "ts": "2026-04-26T10:00:00.000Z", "run_id": "r1", "job_id": None,
         "event_type": "run_start", "actor": "orchestrator",
         "payload": {"command": "run"}, "prev_hash": "genesis", "this_hash": "a"},
        {"seq": 2, "ts": "2026-04-26T10:00:01.000Z", "run_id": "r1", "job_id": "j1",
         "event_type": "job_dispatch", "actor": "orchestrator",
         "payload": {"job_id": "j1", "file_path": "dgif_lib.c", "image": "img"},
         "prev_hash": "a", "this_hash": "b"},
        {"seq": 3, "ts": "2026-04-26T10:01:01.000Z", "run_id": "r1", "job_id": "j1",
         "event_type": "container_exit", "actor": "orchestrator",
         "payload": {"job_id": "j1", "exit_code": 0, "stdout_len": 5000,
                     "wall_clock_seconds": 60.0, "turns_used": 15,
                     "cost_usd": 0.05, "input_tokens": 10000, "output_tokens": 2000,
                     "verdict": "found"},
         "prev_hash": "b", "this_hash": "c"},
        {"seq": 4, "ts": "2026-04-26T10:01:05.000Z", "run_id": "r1", "job_id": "j1",
         "event_type": "llm_call", "actor": "validation_agent",
         "payload": {"stage": "validation", "model": "openai/gpt-5.4",
                     "input_tokens": 4000, "output_tokens": 200, "cost_usd": 0.01},
         "prev_hash": "c", "this_hash": "d"},
        {"seq": 5, "ts": "2026-04-26T10:01:06.000Z", "run_id": "r1", "job_id": "j1",
         "event_type": "finding_validated", "actor": "validation_agent",
         "payload": {"finding_job_id": "j1", "verdict": "VALIDATE",
                     "asan_real": True, "repro_plausible": True, "security_meaningful": True},
         "prev_hash": "d", "this_hash": "e"},
    ]
    metrics = extract_run_metrics(_write_audit(tmp_path, entries))
    assert metrics["jobs_dispatched"] == 1
    assert metrics["findings_count"] == 1
    assert metrics["validated_count"] == 1
    assert metrics["rejected_count"] == 0
    assert metrics["false_positive_rate"] == pytest.approx(0.0)
    assert metrics["total_wall_clock_seconds"] == pytest.approx(60.0)
    assert metrics["total_worker_cost_usd"] == pytest.approx(0.05)
    assert metrics["total_validation_cost_usd"] == pytest.approx(0.01)
    assert metrics["total_cost_usd"] == pytest.approx(0.06)
    assert metrics["avg_turns_per_job"] == pytest.approx(15.0)
    assert metrics["total_input_tokens"] == 10000
    assert metrics["total_output_tokens"] == 2000


def test_extract_run_metrics_no_findings(tmp_path):
    entries = [
        {"seq": 1, "ts": "2026-04-26T10:00:00.000Z", "run_id": "r1", "job_id": None,
         "event_type": "run_start", "actor": "orchestrator",
         "payload": {"command": "run"}, "prev_hash": "genesis", "this_hash": "a"},
        {"seq": 2, "ts": "2026-04-26T10:00:01.000Z", "run_id": "r1", "job_id": "j1",
         "event_type": "job_dispatch", "actor": "orchestrator",
         "payload": {"job_id": "j1", "file_path": "test.c", "image": "img"},
         "prev_hash": "a", "this_hash": "b"},
        {"seq": 3, "ts": "2026-04-26T10:00:30.000Z", "run_id": "r1", "job_id": "j1",
         "event_type": "container_exit", "actor": "orchestrator",
         "payload": {"job_id": "j1", "exit_code": 0, "stdout_len": 100,
                     "wall_clock_seconds": 29.0, "turns_used": 5, "verdict": "not_found"},
         "prev_hash": "b", "this_hash": "c"},
    ]
    metrics = extract_run_metrics(_write_audit(tmp_path, entries))
    assert metrics["jobs_dispatched"] == 1
    assert metrics["findings_count"] == 0
    assert metrics["validated_count"] == 0
    assert metrics["total_cost_usd"] == pytest.approx(0.0)


def test_extract_run_metrics_backward_compat(tmp_path):
    """Old audit logs without telemetry fields don't crash."""
    entries = [
        {"seq": 1, "ts": "2026-04-26T10:00:00.000Z", "run_id": "r1", "job_id": None,
         "event_type": "run_start", "actor": "orchestrator",
         "payload": {"command": "run"}, "prev_hash": "genesis", "this_hash": "a"},
        {"seq": 2, "ts": "2026-04-26T10:00:01.000Z", "run_id": "r1", "job_id": "j1",
         "event_type": "job_dispatch", "actor": "orchestrator",
         "payload": {"job_id": "j1", "file_path": "test.c", "image": "img"},
         "prev_hash": "a", "this_hash": "b"},
        # Old format: only exit_code and stdout_len, no telemetry
        {"seq": 3, "ts": "2026-04-26T10:00:30.000Z", "run_id": "r1", "job_id": "j1",
         "event_type": "container_exit", "actor": "orchestrator",
         "payload": {"job_id": "j1", "exit_code": 0, "stdout_len": 100},
         "prev_hash": "b", "this_hash": "c"},
    ]
    metrics = extract_run_metrics(_write_audit(tmp_path, entries))
    assert metrics["jobs_dispatched"] == 1
    assert metrics["findings_count"] == 0
    assert metrics["total_wall_clock_seconds"] == pytest.approx(0.0)
    assert metrics["avg_turns_per_job"] == pytest.approx(0.0)


def test_extract_run_metrics_timeout(tmp_path):
    """Timed-out containers count as dispatched but not as findings."""
    entries = [
        {"seq": 1, "ts": "2026-04-26T10:00:00.000Z", "run_id": "r1", "job_id": None,
         "event_type": "run_start", "actor": "orchestrator",
         "payload": {"command": "run"}, "prev_hash": "genesis", "this_hash": "a"},
        {"seq": 2, "ts": "2026-04-26T10:00:01.000Z", "run_id": "r1", "job_id": "j1",
         "event_type": "job_dispatch", "actor": "orchestrator",
         "payload": {"job_id": "j1", "file_path": "test.c", "image": "img"},
         "prev_hash": "a", "this_hash": "b"},
        {"seq": 3, "ts": "2026-04-26T10:20:01.000Z", "run_id": "r1", "job_id": "j1",
         "event_type": "container_exit", "actor": "orchestrator",
         "payload": {"job_id": "j1", "exit_code": -1, "reason": "timeout",
                     "stdout_len": 0, "wall_clock_seconds": 1200.0},
         "prev_hash": "b", "this_hash": "c"},
    ]
    metrics = extract_run_metrics(_write_audit(tmp_path, entries))
    assert metrics["jobs_dispatched"] == 1
    assert metrics["findings_count"] == 0  # timeout != finding
    assert metrics["total_wall_clock_seconds"] == pytest.approx(1200.0)


# --- Aggregation ---


def test_aggregate_trials():
    trials = [
        {"findings_count": 3, "validated_count": 2, "rejected_count": 1,
         "total_cost_usd": 0.10, "avg_turns_per_job": 12.0, "total_wall_clock_seconds": 120.0,
         "false_positive_rate": 33.3},
        {"findings_count": 2, "validated_count": 2, "rejected_count": 0,
         "total_cost_usd": 0.08, "avg_turns_per_job": 10.0, "total_wall_clock_seconds": 100.0,
         "false_positive_rate": 0.0},
        {"findings_count": 3, "validated_count": 3, "rejected_count": 0,
         "total_cost_usd": 0.12, "avg_turns_per_job": 14.0, "total_wall_clock_seconds": 140.0,
         "false_positive_rate": 0.0},
    ]
    agg = aggregate_trials(trials)
    assert agg["trials"] == 3
    assert agg["avg_findings"] == pytest.approx(2.67, abs=0.01)
    assert agg["avg_validated"] == pytest.approx(2.33, abs=0.01)
    assert agg["avg_cost_usd"] == pytest.approx(0.10, abs=0.01)
    assert agg["avg_turns_per_job"] == pytest.approx(12.0)
    assert agg["avg_wall_clock_seconds"] == pytest.approx(120.0)
    assert "std_findings" in agg
    assert "std_cost_usd" in agg


def test_aggregate_single_trial():
    trials = [{"findings_count": 3, "validated_count": 3, "rejected_count": 0,
               "total_cost_usd": 0.10, "avg_turns_per_job": 12.0,
               "total_wall_clock_seconds": 120.0, "false_positive_rate": 0.0}]
    agg = aggregate_trials(trials)
    assert agg["trials"] == 1
    assert agg["std_findings"] == pytest.approx(0.0)


def test_aggregate_zero_trials():
    agg = aggregate_trials([])
    assert agg["trials"] == 0


# --- Table formatting ---


def test_format_comparison_table():
    results = {
        "openai/gpt-5.4": {"trials": 3, "avg_findings": 8.0, "avg_validated": 6.0,
                           "avg_cost_usd": 0.11, "avg_turns_per_job": 15.0,
                           "avg_wall_clock_seconds": 300.0},
        "openai/gpt-4o": {"trials": 3, "avg_findings": 0.0, "avg_validated": 0.0,
                          "avg_cost_usd": 0.00, "avg_turns_per_job": 5.0,
                          "avg_wall_clock_seconds": 120.0},
    }
    table = format_comparison_table(results, known_findings=3)
    assert "gpt-5.4" in table
    assert "gpt-4o" in table
    assert "Discovery" in table
    assert "200%" in table  # 6.0/3 = 200%


def test_format_comparison_table_zero_known():
    results = {"openai/gpt-4o": {"trials": 1, "avg_findings": 2.0, "avg_validated": 1.0,
                                  "avg_cost_usd": 0.05, "avg_turns_per_job": 10.0,
                                  "avg_wall_clock_seconds": 60.0}}
    table = format_comparison_table(results, known_findings=0)
    assert "N/A" in table
