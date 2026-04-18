"""Tests for the static analysis file ranker."""

import asyncio
import tempfile
from pathlib import Path

import pytest

from harness.static_ranker import (
    FileSignals,
    _build_reason,
    _compute_raw_score,
    _extract_signals,
    _normalize_scores,
    _read_file_safe,
    _score_path_heuristic,
    rank_files_static,
)
from harness.ranker import RankedFile


# ---------------------------------------------------------------------------
# _score_path_heuristic
# ---------------------------------------------------------------------------


def test_path_bonus_parser():
    assert _score_path_heuristic("libavcodec/h264_parser.c") > 0


def test_path_bonus_codec():
    assert _score_path_heuristic("libavcodec/aac.c") > 0


def test_path_bonus_format():
    assert _score_path_heuristic("libavformat/mov.c") > 0


def test_path_penalty_test():
    assert _score_path_heuristic("tests/test_utils.c") < 0


def test_path_penalty_doc():
    assert _score_path_heuristic("doc/examples/helper.c") < 0


def test_path_neutral():
    assert _score_path_heuristic("libavutil/version.h") == 0


# ---------------------------------------------------------------------------
# _extract_signals
# ---------------------------------------------------------------------------


SAMPLE_UNSAFE = """
#include <string.h>
void foo(char *dst, const char *src) {
    strcpy(dst, src);
    strcat(dst, "suffix");
    sprintf(dst, "%s", src);
}
"""

SAMPLE_INPUT_SOURCES = """
#include <stdio.h>
void read_data(FILE *f, char *buf) {
    fread(buf, 1, 1024, f);
    fgets(buf, 1024, f);
}
"""

SAMPLE_MEMORY = """
#include <stdlib.h>
void alloc_stuff() {
    char *p = malloc(1024);
    p = realloc(p, 2048);
    free(p);
}
"""

SAMPLE_POINTER_ARITH = """
void process(char *buf, int offset) {
    char c = *(buf + offset);
    buf[offset + 1] = 0;
}
"""

SAMPLE_COMPLEX = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void parse_input(FILE *f) {
    char *buf = malloc(4096);
    fread(buf, 1, 4096, f);
    strcpy(buf, "header");
    memcpy(buf + 10, buf, 100);
    char c = *(buf + 5);
    free(buf);
}
"""


def test_extract_unsafe_calls():
    signals = _extract_signals("test.c", SAMPLE_UNSAFE)
    assert signals.unsafe_calls == 3  # strcpy, strcat, sprintf


def test_extract_input_sources():
    signals = _extract_signals("test.c", SAMPLE_INPUT_SOURCES)
    assert signals.input_sources == 2  # fread, fgets


def test_extract_memory_mgmt():
    signals = _extract_signals("test.c", SAMPLE_MEMORY)
    assert signals.memory_mgmt == 3  # malloc, realloc, free


def test_extract_pointer_arith():
    signals = _extract_signals("test.c", SAMPLE_POINTER_ARITH)
    assert signals.pointer_arith >= 2  # *(buf + offset), buf[offset + 1]


def test_extract_memcpy():
    signals = _extract_signals("test.c", SAMPLE_COMPLEX)
    assert signals.memcpy_count == 1


def test_extract_loc():
    signals = _extract_signals("test.c", SAMPLE_UNSAFE)
    assert signals.loc == SAMPLE_UNSAFE.count("\n") + 1


def test_extract_complex_has_all_signals():
    signals = _extract_signals("test.c", SAMPLE_COMPLEX)
    assert signals.unsafe_calls >= 1
    assert signals.input_sources >= 1
    assert signals.memory_mgmt >= 2
    assert signals.memcpy_count >= 1


# ---------------------------------------------------------------------------
# _compute_raw_score
# ---------------------------------------------------------------------------


def test_score_empty_file():
    signals = FileSignals(path="empty.c", loc=0)
    score = _compute_raw_score(signals)
    assert score >= 0


def test_source_sink_multiplier():
    """Files with both input sources and unsafe calls get a 1.5x multiplier."""
    base = FileSignals(path="test.c", loc=100, input_sources=2, unsafe_calls=3)
    no_sink = FileSignals(path="test.c", loc=100, input_sources=2, unsafe_calls=0)

    base.raw_score = _compute_raw_score(base)
    no_sink.raw_score = _compute_raw_score(no_sink)

    # source+sink should score higher than input-only
    assert base.raw_score > no_sink.raw_score * 1.3


def test_memory_pointer_multiplier():
    """Files with both memory mgmt and pointer arith get a 1.3x multiplier."""
    both = FileSignals(path="test.c", loc=100, memory_mgmt=5, pointer_arith=3)
    mem_only = FileSignals(path="test.c", loc=100, memory_mgmt=5, pointer_arith=0)

    both_score = _compute_raw_score(both)
    mem_only_score = _compute_raw_score(mem_only)

    assert both_score > mem_only_score


def test_path_bonus_affects_score():
    parser = FileSignals(path="codec/parser.c", loc=100, unsafe_calls=1, path_bonus=5.0)
    plain = FileSignals(path="util/helper.c", loc=100, unsafe_calls=1, path_bonus=0.0)

    assert _compute_raw_score(parser) > _compute_raw_score(plain)


# ---------------------------------------------------------------------------
# _normalize_scores
# ---------------------------------------------------------------------------


def test_normalize_empty():
    assert _normalize_scores([]) == []


def test_normalize_single_file():
    signals = [FileSignals(path="test.c", loc=100)]
    signals[0].raw_score = 50.0
    result = _normalize_scores(signals)
    assert len(result) == 1
    assert result[0].score == 3  # single file gets default


def test_normalize_range():
    signals = []
    for i, raw in enumerate([0, 25, 50, 75, 100]):
        s = FileSignals(path=f"file{i}.c", loc=100)
        s.raw_score = raw
        signals.append(s)

    result = _normalize_scores(signals)
    scores = [r.score for r in result]
    assert scores[0] == 1  # lowest
    assert scores[-1] == 5  # highest
    # All scores in valid range
    assert all(1 <= s <= 5 for s in scores)


def test_normalize_all_same():
    signals = []
    for i in range(5):
        s = FileSignals(path=f"file{i}.c", loc=100)
        s.raw_score = 42.0
        signals.append(s)

    result = _normalize_scores(signals)
    assert all(r.score == 3 for r in result)


# ---------------------------------------------------------------------------
# _build_reason
# ---------------------------------------------------------------------------


def test_reason_includes_signals():
    signals = FileSignals(path="test.c", loc=200, unsafe_calls=5, input_sources=3)
    reason = _build_reason(signals)
    assert "5 unsafe calls" in reason
    assert "3 input sources" in reason


def test_reason_truncated():
    signals = FileSignals(
        path="test.c", loc=200,
        unsafe_calls=99, input_sources=99, memory_mgmt=99,
        pointer_arith=99, memcpy_count=99,
    )
    reason = _build_reason(signals)
    assert len(reason) <= 120


# ---------------------------------------------------------------------------
# _read_file_safe
# ---------------------------------------------------------------------------


def test_read_normal_file(tmp_path):
    f = tmp_path / "test.c"
    f.write_text("int main() { return 0; }\n")
    assert _read_file_safe(f) is not None


def test_read_binary_file(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"\x00\x01\x02\x03" * 100)
    assert _read_file_safe(f) is None


def test_read_nonexistent():
    assert _read_file_safe(Path("/nonexistent/file.c")) is None


def test_read_oversized(tmp_path):
    f = tmp_path / "huge.c"
    f.write_bytes(b"x" * (3 * 1024 * 1024))  # 3MB
    assert _read_file_safe(f) is None


def test_read_latin1(tmp_path):
    f = tmp_path / "test.c"
    f.write_bytes(b"/* \xe9\xe8\xea */ int main() { return 0; }\n")
    content = _read_file_safe(f)
    assert content is not None
    assert "int main()" in content


# ---------------------------------------------------------------------------
# rank_files_static (integration)
# ---------------------------------------------------------------------------


def test_rank_files_static_integration(tmp_path):
    """End-to-end test with synthetic C files."""
    from harness.audit import AuditLog

    # Create a high-risk file
    risky = tmp_path / "parser.c"
    risky.write_text(SAMPLE_COMPLEX)

    # Create a low-risk file
    safe = tmp_path / "version.h"
    safe.write_text('#define VERSION "1.0"\n')

    audit = AuditLog(tmp_path / "audit.jsonl")

    result = asyncio.run(rank_files_static(
        run_id="test-run",
        repo_path=tmp_path,
        exclude_patterns=[],
        max_files_to_scan=None,
        audit=audit,
    ))

    assert len(result) == 2
    # parser.c should rank higher than version.h
    assert result[0].path == "parser.c"
    assert result[0].score > result[1].score


def test_rank_files_static_max_files(tmp_path):
    """max_files_to_scan limits output."""
    from harness.audit import AuditLog

    for i in range(10):
        (tmp_path / f"file{i}.c").write_text(f"void func{i}() {{ }}\n")

    audit = AuditLog(tmp_path / "audit.jsonl")

    result = asyncio.run(rank_files_static(
        run_id="test-run",
        repo_path=tmp_path,
        exclude_patterns=[],
        max_files_to_scan=3,
        audit=audit,
    ))

    assert len(result) == 3
