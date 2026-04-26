"""Tests for builder command sanitizer wiring."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def test_build_sanitized_binaries_passes_multi_sanitizer_env(tmp_path: Path):
    from harness.cli import _build_sanitized_binaries

    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    built_binary = bin_dir / "demo-bin"
    built_binary.write_text("x")

    cfg = SimpleNamespace(
        project_name="demo",
        worker_memory_gb=4,
        worker_cpus=2,
        binary_name="demo-bin",
        configure_flags="",
        worker_image="vuln-harness-worker:latest",
        sanitizers=["asan", "ubsan"],
    )

    seen_cmd: list[str] = []

    class Result:
        returncode = 0
        stderr = ""

    def fake_run(cmd, capture_output, text):
        seen_cmd.extend(cmd)
        return Result()

    with patch("subprocess.run", side_effect=fake_run):
        _build_sanitized_binaries(cfg, repo_path, bin_dir, "run-123")

    assert "SANITIZERS=asan,ubsan" in seen_cmd
    cflags_entry = next(part for part in seen_cmd if part.startswith("FULL_CFLAGS="))
    ldflags_entry = next(part for part in seen_cmd if part.startswith("FULL_LDFLAGS="))
    assert "-fsanitize=address,undefined" in cflags_entry
    assert "-fno-sanitize-recover=all" in cflags_entry
    assert "-fsanitize=address,undefined" in ldflags_entry
