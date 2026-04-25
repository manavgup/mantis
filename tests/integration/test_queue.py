"""Integration tests for harness.queue — requires Redis running."""

from __future__ import annotations

import asyncio
import uuid

import pytest
import redis.asyncio as aioredis

from harness.queue import (
    dequeue_job,
    enqueue_jobs,
    get_queue_depth,
    get_run_spend,
    increment_spend,
    update_job_status,
)
from harness.ranker import RankedFile

REDIS_URL = "redis://localhost:6379"


@pytest.fixture()
def run_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture(autouse=True)
async def cleanup_redis(run_id: str):
    """Clean up Redis keys after each test."""
    yield
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    # Clean up all keys for this run
    keys = []
    async for key in client.scan_iter(f"*{run_id}*"):
        keys.append(key)
    if keys:
        await client.delete(*keys)
    await client.aclose()


def _make_ranked(path: str, score: int) -> RankedFile:
    return RankedFile(path=path, score=score, reason="test")


@pytest.mark.asyncio
async def test_enqueue_dequeue_priority_order(run_id: str):
    files = [
        _make_ranked("low.c", 1),
        _make_ranked("high.c", 5),
        _make_ranked("mid.c", 3),
        _make_ranked("higher.c", 4),
        _make_ranked("mid2.c", 3),
    ]
    count = await enqueue_jobs(run_id, files, REDIS_URL)
    assert count == 5

    # Dequeue should return highest priority first
    job = await dequeue_job(run_id, REDIS_URL)
    assert job is not None
    assert job.priority_score == 5
    assert job.file_path == "high.c"

    job = await dequeue_job(run_id, REDIS_URL)
    assert job is not None
    assert job.priority_score == 4

    job = await dequeue_job(run_id, REDIS_URL)
    assert job is not None
    assert job.priority_score == 3


@pytest.mark.asyncio
async def test_update_job_status(run_id: str):
    files = [_make_ranked("test.c", 3)]
    await enqueue_jobs(run_id, files, REDIS_URL)

    job = await dequeue_job(run_id, REDIS_URL)
    assert job is not None

    await update_job_status(
        run_id,
        job.job_id,
        REDIS_URL,
        status="running",
        container_id="abc123",
    )

    # Read back
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    data = await client.hgetall(f"job:{run_id}:{job.job_id}")
    await client.aclose()

    assert data["status"] == "running"
    assert data["container_id"] == "abc123"


@pytest.mark.asyncio
async def test_increment_spend_concurrent(run_id: str):
    files = [_make_ranked("test.c", 3)]
    await enqueue_jobs(run_id, files, REDIS_URL)

    # Concurrent increments
    tasks = [increment_spend(run_id, 0.5, REDIS_URL) for _ in range(10)]
    await asyncio.gather(*tasks)

    total = await get_run_spend(run_id, REDIS_URL)
    assert abs(total - 5.0) < 0.01


@pytest.mark.asyncio
async def test_get_queue_depth(run_id: str):
    files = [
        _make_ranked("a.c", 1),
        _make_ranked("b.c", 2),
        _make_ranked("c.c", 3),
    ]
    await enqueue_jobs(run_id, files, REDIS_URL)

    depth = await get_queue_depth(run_id, REDIS_URL)
    assert depth == 3

    await dequeue_job(run_id, REDIS_URL)
    depth = await get_queue_depth(run_id, REDIS_URL)
    assert depth == 2
