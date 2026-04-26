"""Tests for sanitizer validation and flag generation."""

from __future__ import annotations

import pytest

from harness.sanitizers import build_sanitizer_flags, validate_sanitizers


def test_build_flags_for_asan():
    flags = build_sanitizer_flags(["asan"])
    assert flags.sanitize_flag == "-fsanitize=address"
    assert "-fno-omit-frame-pointer" in flags.cflags
    assert flags.ldflags == "-fsanitize=address"


def test_build_flags_for_asan_ubsan():
    flags = build_sanitizer_flags(["asan", "ubsan"])
    assert flags.sanitize_flag == "-fsanitize=address,undefined"
    assert "-fno-sanitize-recover=all" in flags.cflags
    assert flags.ldflags == "-fsanitize=address,undefined"


def test_build_flags_for_msan():
    flags = build_sanitizer_flags(["msan"])
    assert flags.sanitize_flag == "-fsanitize=memory"
    assert "-fPIE" in flags.cflags
    assert "-pie" in flags.ldflags


def test_build_flags_for_tsan():
    flags = build_sanitizer_flags(["tsan"])
    assert flags.sanitize_flag == "-fsanitize=thread"
    assert flags.ldflags == "-fsanitize=thread"


@pytest.mark.parametrize(
    ("sanitizers", "message"),
    [
        (["asan", "msan"], "asan and msan"),
        (["asan", "tsan"], "asan and tsan"),
        (["msan", "tsan"], "msan and tsan"),
    ],
)
def test_invalid_sanitizer_combinations_raise(sanitizers: list[str], message: str):
    with pytest.raises(ValueError, match=message):
        validate_sanitizers(sanitizers)


def test_unknown_sanitizer_raises():
    with pytest.raises(ValueError, match="unsupported sanitizer"):
        validate_sanitizers(["foo"])


def test_duplicate_sanitizers_are_deduplicated():
    assert validate_sanitizers(["asan", "ubsan", "asan"]) == ["asan", "ubsan"]
