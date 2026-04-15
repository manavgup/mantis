"""Stage 2: Redis-backed job queue management."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import redis.asyncio as aioredis

from harness.ranker import RankedFile


@dataclass
class Job:
    job_id: str
    run_id: str
    file_path: str
    priority_score: int
    status: str = "pending"
    container_id: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    cost_usd: float = 0.0
    result_path: str | None = None
    error: str | None = None


async def _get_client(redis_url: str) -> aioredis.Redis:
    return aioredis.from_url(redis_url, decode_responses=True)


async def enqueue_jobs(
    run_id: str, ranked_files: list[RankedFile], redis_url: str
) -> int:
    """Create job records and add to priority queue. Returns count enqueued."""
    client = await _get_client(redis_url)
    try:
        count = 0
        for rf in ranked_files:
            job_id = str(uuid.uuid4())
            job = Job(
                job_id=job_id,
                run_id=run_id,
                file_path=rf.path,
                priority_score=rf.score,
            )
            # Store job as a hash
            key = f"job:{run_id}:{job_id}"
            await client.hset(key, mapping={
                "job_id": job.job_id,
                "run_id": job.run_id,
                "file_path": job.file_path,
                "priority_score": str(job.priority_score),
                "status": job.status,
                "container_id": "",
                "started_at": "",
                "completed_at": "",
                "cost_usd": "0.0",
                "result_path": "",
                "error": "",
            })
            # Add to sorted set (score = priority for descending order)
            await client.zadd(f"queue:{run_id}", {job_id: rf.score})
            count += 1

        # Initialize spend counter
        await client.set(f"spend:{run_id}", "0.0")
        return count
    finally:
        await client.aclose()


async def dequeue_job(run_id: str, redis_url: str) -> Job | None:
    """Pop highest-priority pending job. Returns None if queue empty."""
    client = await _get_client(redis_url)
    try:
        # Get highest score member (ZPOPMAX returns [(member, score)])
        result = await client.zpopmax(f"queue:{run_id}", count=1)
        if not result:
            return None

        job_id, score = result[0]
        key = f"job:{run_id}:{job_id}"
        data = await client.hgetall(key)
        if not data:
            return None

        return Job(
            job_id=data["job_id"],
            run_id=data["run_id"],
            file_path=data["file_path"],
            priority_score=int(data["priority_score"]),
            status=data["status"],
        )
    finally:
        await client.aclose()


async def update_job_status(
    run_id: str, job_id: str, redis_url: str, **kwargs
) -> None:
    """Update fields on a job hash."""
    client = await _get_client(redis_url)
    try:
        key = f"job:{run_id}:{job_id}"
        updates = {k: str(v) if v is not None else "" for k, v in kwargs.items()}
        if updates:
            await client.hset(key, mapping=updates)
    finally:
        await client.aclose()


async def get_run_spend(run_id: str, redis_url: str) -> float:
    """Get current run spend total."""
    client = await _get_client(redis_url)
    try:
        val = await client.get(f"spend:{run_id}")
        return float(val) if val else 0.0
    finally:
        await client.aclose()


async def increment_spend(run_id: str, amount: float, redis_url: str) -> float:
    """Atomically increment run spend. Returns new total."""
    client = await _get_client(redis_url)
    try:
        new_val = await client.incrbyfloat(f"spend:{run_id}", amount)
        return float(new_val)
    finally:
        await client.aclose()


async def get_queue_depth(run_id: str, redis_url: str) -> int:
    """Get number of remaining jobs in the priority queue."""
    client = await _get_client(redis_url)
    try:
        return await client.zcard(f"queue:{run_id}")
    finally:
        await client.aclose()
