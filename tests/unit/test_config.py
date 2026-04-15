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


def test_loads_minimal_valid_config_claude_code_mode(minimal_yaml: Path, monkeypatch):
    """With use_claude_code=true (default), no API key needed."""
    monkeypatch.setenv("HARNESS_CONFIG", str(minimal_yaml))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("FINDINGS_ENC_KEY", raising=False)

    from harness.config import Config

    cfg = Config()
    assert cfg.repo_url == "https://github.com/test/repo"
    assert cfg.binary_name == "testbin"
    assert cfg.use_claude_code is True
    assert cfg.anthropic_api_key is None


def test_api_mode_requires_api_key(tmp_path: Path, monkeypatch):
    """With use_claude_code=false, ANTHROPIC_API_KEY is required."""
    data = {
        "repo_url": "https://github.com/test/repo",
        "binary_name": "testbin",
        "project_name": "testproject",
        "project_description": "A test project",
        "postgres_url": "postgresql://localhost:5432/test",
        "use_claude_code": False,
    }
    p = tmp_path / "harness.yaml"
    p.write_text(yaml.dump(data))
    monkeypatch.setenv("HARNESS_CONFIG", str(p))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    from harness.config import Config

    with pytest.raises(SystemExit):
        Config()


def test_api_mode_works_with_key(tmp_path: Path, monkeypatch):
    """With use_claude_code=false and API key set, config loads fine."""
    data = {
        "repo_url": "https://github.com/test/repo",
        "binary_name": "testbin",
        "project_name": "testproject",
        "project_description": "A test project",
        "postgres_url": "postgresql://localhost:5432/test",
        "use_claude_code": False,
    }
    p = tmp_path / "harness.yaml"
    p.write_text(yaml.dump(data))
    monkeypatch.setenv("HARNESS_CONFIG", str(p))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-key")

    from harness.config import Config

    cfg = Config()
    assert cfg.use_claude_code is False
    assert cfg.anthropic_api_key == "sk-test-key"


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
