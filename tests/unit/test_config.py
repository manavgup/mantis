"""Tests for harness.config."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml


@pytest.fixture()
def minimal_yaml(tmp_path: Path) -> Path:
    data = {
        "repo_url": "https://github.com/test/repo",
        "binary_name": "testbin",
        "project_name": "testproject",
        "project_description": "A test project",
        "postgres_url": "postgresql://localhost:5432/test",
    }
    p = tmp_path / "harness.yaml"
    p.write_text(yaml.dump(data))
    return p


def test_loads_minimal_valid_config(minimal_yaml: Path, monkeypatch):
    """Config loads with defaults — litellm model strings, no use_claude_code flag."""
    monkeypatch.setenv("HARNESS_CONFIG", str(minimal_yaml))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("FINDINGS_ENC_KEY", raising=False)

    from harness.config import Config

    cfg = Config()
    assert cfg.repo_url == "https://github.com/test/repo"
    assert cfg.binary_name == "testbin"
    assert cfg.ranking_model == "anthropic/claude-opus-4-6"
    assert cfg.worker_model == "anthropic/claude-opus-4-6"
    assert cfg.validation_model == "anthropic/claude-opus-4-6"


def test_custom_model_strings(tmp_path: Path, monkeypatch):
    """Config accepts any litellm model string."""
    data = {
        "repo_url": "https://github.com/test/repo",
        "binary_name": "testbin",
        "project_name": "testproject",
        "project_description": "A test project",
        "postgres_url": "postgresql://localhost:5432/test",
        "ranking_model": "openai/gpt-4o",
        "worker_model": "ollama/llama3",
        "validation_model": "anthropic/claude-sonnet-4-6",
    }
    p = tmp_path / "harness.yaml"
    p.write_text(yaml.dump(data))
    monkeypatch.setenv("HARNESS_CONFIG", str(p))

    from harness.config import Config

    cfg = Config()
    assert cfg.ranking_model == "openai/gpt-4o"
    assert cfg.worker_model == "ollama/llama3"
    assert cfg.validation_model == "anthropic/claude-sonnet-4-6"


def test_missing_required_field_raises(tmp_path: Path, monkeypatch):
    data = {
        "repo_url": "https://github.com/test/repo",
        "project_name": "testproject",
        "project_description": "A test project",
        "postgres_url": "postgresql://localhost:5432/test",
    }
    p = tmp_path / "harness.yaml"
    p.write_text(yaml.dump(data))
    monkeypatch.setenv("HARNESS_CONFIG", str(p))

    from harness.config import Config

    with pytest.raises(Exception):
        Config()


def test_default_sanitizers(minimal_yaml: Path, monkeypatch):
    """Default config has sanitizers: ['asan']."""
    monkeypatch.setenv("HARNESS_CONFIG", str(minimal_yaml))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("FINDINGS_ENC_KEY", raising=False)

    from harness.config import Config

    cfg = Config()
    assert cfg.sanitizers == ["asan"]


def test_multi_sanitizers(tmp_path: Path, monkeypatch):
    """Config accepts multiple sanitizers."""
    data = {
        "repo_url": "https://github.com/test/repo",
        "binary_name": "testbin",
        "project_name": "testproject",
        "project_description": "A test project",
        "postgres_url": "postgresql://localhost:5432/test",
        "sanitizers": ["asan", "ubsan"],
    }
    p = tmp_path / "harness.yaml"
    p.write_text(yaml.dump(data))
    monkeypatch.setenv("HARNESS_CONFIG", str(p))

    from harness.config import Config

    cfg = Config()
    assert cfg.sanitizers == ["asan", "ubsan"]
