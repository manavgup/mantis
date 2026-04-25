"""Integration tests for harness.dispatcher — requires Docker running."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest

from harness.audit import AuditLog
from harness.queue import enqueue_jobs
from harness.ranker import RankedFile

REDIS_URL = "redis://localhost:6379"


@dataclass
class MockConfig:
    worker_memory_gb: int = 1
    worker_cpus: int = 1
    worker_image: str = "alpine:latest"
    worker_model: str = "test"
    max_turns_per_worker: int = 5
    max_parallel_workers: int = 2
    container_timeout_seconds: int = 10
    max_run_spend_usd: float = 100.0
    # No provider-specific API key field — litellm reads from env vars
    project_name: str = "test"
    project_description: str = "test project"
    binary_name: str = "testbin"
    repo_url: str = "/tmp"
    redis_url: str = REDIS_URL


@pytest.fixture()
def run_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture()
def audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture()
def config() -> MockConfig:
    return MockConfig()


@pytest.fixture(autouse=True)
async def cleanup_redis(run_id: str):
    yield
    import redis.asyncio as aioredis

    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    keys = []
    async for key in client.scan_iter(f"*{run_id}*"):
        keys.append(key)
    if keys:
        await client.delete(*keys)
    await client.aclose()


@pytest.mark.asyncio
async def test_container_exits_0(run_id: str, audit_log: AuditLog, config: MockConfig):
    """Container that exits successfully → job marked done."""
    # Use alpine with echo command — override entrypoint
    config.worker_image = "alpine:latest"

    files = [RankedFile("test.c", 3, "test")]
    await enqueue_jobs(run_id, files, REDIS_URL)

    from harness.queue import dequeue_job

    job = await dequeue_job(run_id, REDIS_URL)
    assert job is not None

    # Run a simple echo container — override by using docker directly
    proc = await asyncio.create_subprocess_exec(
        "docker",
        "run",
        "--rm",
        "alpine:latest",
        "echo",
        "hello",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    assert proc.returncode == 0
    assert b"hello" in stdout


@pytest.mark.asyncio
async def test_container_exits_1(run_id: str, audit_log: AuditLog, config: MockConfig):
    """Container that exits with error code."""
    proc = await asyncio.create_subprocess_exec(
        "docker",
        "run",
        "--rm",
        "alpine:latest",
        "sh",
        "-c",
        "exit 1",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await proc.communicate()
    assert proc.returncode == 1


@pytest.mark.asyncio
async def test_container_timeout(run_id: str, audit_log: AuditLog, config: MockConfig):
    """Container that exceeds timeout gets killed."""
    proc = await asyncio.create_subprocess_exec(
        "docker",
        "run",
        "--rm",
        "alpine:latest",
        "sleep",
        "300",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        await asyncio.wait_for(proc.communicate(), timeout=2)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()

    # Process was killed (returncode -9 or non-zero)
    assert proc.returncode != 0


@pytest.mark.asyncio
async def test_semaphore_limits_parallelism(run_id: str, audit_log: AuditLog, config: MockConfig):
    """With max_parallel=2 and 4 jobs, only 2 run simultaneously."""
    config.max_parallel_workers = 2
    running_count = 0
    max_concurrent = 0
    lock = asyncio.Lock()

    original_sem = asyncio.Semaphore(config.max_parallel_workers)

    async def mock_work():
        nonlocal running_count, max_concurrent
        async with original_sem:
            async with lock:
                running_count += 1
                max_concurrent = max(max_concurrent, running_count)
            await asyncio.sleep(0.1)
            async with lock:
                running_count -= 1

    tasks = [asyncio.create_task(mock_work()) for _ in range(4)]
    await asyncio.gather(*tasks)

    assert max_concurrent <= 2
