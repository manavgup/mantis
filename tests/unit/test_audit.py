"""Tests for harness.audit — hash-chained JSONL audit log."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from harness.audit import AuditLog, verify_chain


@pytest.fixture()
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


def test_single_entry_written_and_readable(audit_path: Path):
    log = AuditLog(audit_path)
    h = log.write("run-1", "run_start", "orchestrator", {"msg": "hello"})

    assert audit_path.exists()
    lines = [l for l in audit_path.read_text().splitlines() if l.strip()]
    assert len(lines) == 1

    entry = json.loads(lines[0])
    assert entry["seq"] == 1
    assert entry["run_id"] == "run-1"
    assert entry["event_type"] == "run_start"
    assert entry["actor"] == "orchestrator"
    assert entry["payload"] == {"msg": "hello"}
    assert entry["prev_hash"] == "genesis"
    assert entry["this_hash"] == h
    assert entry["ts"].endswith("Z")


def test_two_entries_chain_correctly(audit_path: Path):
    log = AuditLog(audit_path)
    h1 = log.write("run-1", "run_start", "orchestrator", {"step": 1})
    h2 = log.write("run-1", "job_dispatch", "orchestrator", {"step": 2}, job_id="job-1")

    lines = [l for l in audit_path.read_text().splitlines() if l.strip()]
    assert len(lines) == 2

    e1 = json.loads(lines[0])
    e2 = json.loads(lines[1])

    assert e1["this_hash"] == h1
    assert e2["prev_hash"] == h1
    assert e2["this_hash"] == h2
    assert e2["seq"] == 2
    assert e2["job_id"] == "job-1"


def test_tampered_entry_breaks_chain(audit_path: Path):
    log = AuditLog(audit_path)
    log.write("run-1", "run_start", "orchestrator", {"x": 1})
    log.write("run-1", "job_dispatch", "orchestrator", {"x": 2})

    # Tamper with the first entry
    lines = audit_path.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["payload"]["x"] = 999  # modify payload
    lines[0] = json.dumps(entry, sort_keys=True)
    audit_path.write_text("\n".join(lines) + "\n")

    valid, broken_seq = verify_chain(audit_path)
    assert not valid
    assert broken_seq == 1


def test_concurrent_writes_do_not_corrupt(audit_path: Path):
    log = AuditLog(audit_path)
    n_threads = 8
    n_writes_per_thread = 20

    def writer(thread_id: int):
        for i in range(n_writes_per_thread):
            log.write(
                "run-1",
                "tool_call",
                f"thread-{thread_id}",
                {"thread": thread_id, "i": i},
            )

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = [l for l in audit_path.read_text().splitlines() if l.strip()]
    expected = n_threads * n_writes_per_thread
    assert len(lines) == expected

    # Verify chain integrity
    valid, broken_seq = verify_chain(audit_path)
    assert valid, f"Chain broken at seq={broken_seq}"

    # Verify sequential numbering
    seqs = [json.loads(l)["seq"] for l in lines]
    assert seqs == list(range(1, expected + 1))


def test_verify_chain_valid(audit_path: Path):
    log = AuditLog(audit_path)
    for i in range(5):
        log.write("run-1", "event", "actor", {"i": i})
    valid, seq = verify_chain(audit_path)
    assert valid
    assert seq is None


def test_verify_chain_empty_file(audit_path: Path):
    audit_path.write_text("")
    valid, seq = verify_chain(audit_path)
    assert valid
    assert seq is None


def test_verify_chain_nonexistent_file(tmp_path: Path):
    valid, seq = verify_chain(tmp_path / "nope.jsonl")
    assert valid
    assert seq is None
