"""Tests for harness.ranker — file ranking via LLM."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from harness.audit import AuditLog
from harness.llm import LLMResponse
from harness.ranker import RankedFile, _enumerate_source_files, _parse_ranking_response, rank_files


@pytest.fixture()
def sample_response_text() -> str:
    return json.dumps([
        {"path": "src/parser.c", "score": 5, "reason": "parses untrusted data"},
        {"path": "src/alloc.c", "score": 4, "reason": "memory allocator"},
        {"path": "src/util.c", "score": 2, "reason": "low surface"},
        {"path": "src/crypto.c", "score": 5, "reason": "crypto ops"},
        {"path": "src/config.h", "score": 1, "reason": "constants"},
        {"path": "src/io.c", "score": 4, "reason": "file I/O"},
        {"path": "src/log.c", "score": 2, "reason": "logging"},
        {"path": "src/net.c", "score": 5, "reason": "network I/O"},
        {"path": "src/hash.c", "score": 3, "reason": "hashing"},
        {"path": "src/main.c", "score": 3, "reason": "entry point"},
    ])


@pytest.fixture()
def ten_files() -> list[str]:
    return [
        "src/parser.c", "src/alloc.c", "src/util.c", "src/crypto.c",
        "src/config.h", "src/io.c", "src/log.c", "src/net.c",
        "src/hash.c", "src/main.c",
    ]


@pytest.fixture()
def audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def test_ten_files_correct_sorted_order(sample_response_text: str, ten_files: list[str]):
    ranked = _parse_ranking_response(sample_response_text, ten_files)
    assert len(ranked) == 10
    ranked.sort(key=lambda r: (-r.score, r.path))
    assert ranked[0].score == 5
    assert ranked[0].path == "src/crypto.c"
    assert ranked[1].path == "src/net.c"
    assert ranked[2].path == "src/parser.c"


def test_missing_score_defaults_to_3(ten_files: list[str]):
    response = json.dumps([
        {"path": "src/parser.c", "score": 5, "reason": "parses data"},
        {"path": "src/util.c", "score": 2, "reason": "utils"},
        {"path": "src/config.h", "score": 1, "reason": "constants"},
    ])
    ranked = _parse_ranking_response(response, ten_files)
    assert len(ranked) == 10
    missing_files = {"src/alloc.c", "src/crypto.c", "src/io.c", "src/log.c",
                     "src/net.c", "src/hash.c", "src/main.c"}
    for r in ranked:
        if r.path in missing_files:
            assert r.score == 3


@pytest.mark.asyncio
async def test_api_failure_retries_then_raises(audit_log: AuditLog):
    mock_call = AsyncMock(side_effect=Exception("LLM error"))

    with patch("harness.ranker.call_llm", mock_call):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "test.c").write_text("int main() {}")

            with pytest.raises(Exception, match="LLM error"):
                await rank_files(
                    run_id="test-run",
                    repo_path=repo,
                    exclude_patterns=[],
                    ranking_model="claude-opus-4-6",
                    max_files_to_scan=None,
                    audit=audit_log,
                )

    assert mock_call.call_count == 3


def test_exclusion_patterns_applied(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.c").write_text("")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "test_main.c").write_text("")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.c").write_text("")

    files = _enumerate_source_files(tmp_path, ["*/test/*", "*/vendor/*"])
    assert files == ["src/main.c"]


@pytest.mark.asyncio
async def test_rank_files_end_to_end(
    tmp_path: Path, sample_response_text: str, audit_log: AuditLog
):
    src = tmp_path / "repo" / "src"
    src.mkdir(parents=True)
    for name in ["parser.c", "alloc.c", "util.c", "crypto.c", "config.h",
                  "io.c", "log.c", "net.c", "hash.c", "main.c"]:
        (src / name).write_text("")

    mock_response = LLMResponse(
        text=sample_response_text,
        input_tokens=100,
        output_tokens=200,
        cost_usd=0.01,
    )
    mock_call = AsyncMock(return_value=mock_response)

    with patch("harness.ranker.call_llm", mock_call):
        ranked = await rank_files(
            run_id="test-run",
            repo_path=tmp_path / "repo",
            exclude_patterns=[],
            ranking_model="claude-opus-4-6",
            max_files_to_scan=None,
            audit=audit_log,
        )

    assert len(ranked) == 10
    assert ranked[0].score >= ranked[-1].score
    assert audit_log.path.exists()
