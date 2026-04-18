"""Loads and validates harness.yaml configuration."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict


class YamlSettingsSource(PydanticBaseSettingsSource):
    def get_field_value(self, field, field_name):
        return self._yaml_data.get(field_name), field_name, False

    def __init__(self, settings_cls):
        super().__init__(settings_cls)
        config_path = os.environ.get("HARNESS_CONFIG", "./harness.yaml")
        path = Path(config_path)
        if path.exists():
            with open(path) as f:
                self._yaml_data = yaml.safe_load(f) or {}
        else:
            self._yaml_data = {}

    def __call__(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        for field_name, field_info in self.settings_cls.model_fields.items():
            val, key, _ = self.get_field_value(field_info, field_name)
            if val is not None:
                d[field_name] = val
        return d


class Config(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="",
        extra="ignore",
    )

    # Target
    repo_url: str
    repo_commit: str = "main"
    binary_name: str
    project_name: str
    project_description: str

    # Build
    configure_flags: str = ""  # extra flags for ./configure (e.g. FFmpeg's --extra-cflags)

    # Ranking strategy: "static" (regex-based, free, instant) | "llm" (LLM-based)
    ranking_strategy: str = "static"

    # Scan scope
    exclude_patterns: list[str] = []
    max_files_to_scan: int | None = None

    # Agent — model strings use litellm format: "provider/model"
    # e.g. "anthropic/claude-opus-4-6", "openai/gpt-4o", "ollama/llama3"
    ranking_model: str = "anthropic/claude-opus-4-6"
    worker_model: str = "anthropic/claude-opus-4-6"
    validation_model: str = "anthropic/claude-opus-4-6"
    max_turns_per_worker: int = 50

    # Parallelism
    max_parallel_workers: int = 4

    # Spend limits
    max_run_spend_usd: float = 100.0
    max_day_spend_usd: float = 500.0

    # Container
    worker_image: str = "vuln-harness-worker:latest"
    container_timeout_seconds: int = 1800
    worker_memory_gb: int = 4
    worker_cpus: int = 2

    # Storage
    redis_url: str = "redis://localhost:6379"
    postgres_url: str
    run_output_dir: Path = Path("./runs")
    findings_encryption_key_env: str = "FINDINGS_ENC_KEY"

    # Secrets — API keys are read from env vars by litellm automatically
    # (ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY, etc.)
    findings_enc_key: str | None = Field(default=None, alias="FINDINGS_ENC_KEY")

    @classmethod
    def settings_customise_sources(cls, settings_cls, **kwargs):
        return (
            kwargs.get("init_settings"),
            kwargs.get("env_settings"),
            YamlSettingsSource(settings_cls),
        )
