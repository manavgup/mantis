"""Stage 2: container dispatch and lifecycle management."""

from __future__ import annotations

import asyncio
import json as _json
import logging
import os
import time
from datetime import datetime, timezone

from harness.audit import AuditLog
from harness.queue import dequeue_job, get_run_spend, update_job_status

logger = logging.getLogger(__name__)


def _save_stderr(run_dir: str | None, job_id: str, stderr_bytes: bytes) -> None:
    """Save worker stderr to file for trace analysis. Non-fatal on failure."""
    if not run_dir:
        logger.warning("run_dir is None — stderr persistence disabled for job %s", job_id)
        return
    try:
        from pathlib import Path

        path = Path(run_dir) / f"{job_id}.stderr.log"
        # Sync write is fine: ~0.1ms for 100KB, negligible vs. container runtime (30-1200s).
        path.write_bytes(stderr_bytes)
    except OSError as e:
        logger.warning("Failed to save stderr for job %s: %s", job_id, e)


def _extract_telemetry(stdout: str, job_id: str) -> dict:
    """Extract agent telemetry from stdout JSON. Returns dict of fields or empty dict on failure."""
    try:
        agent_out = _json.loads(stdout)
        if isinstance(agent_out, dict) and agent_out.get("type") == "result":
            import re

            inner = agent_out.get("result", "")
            if isinstance(inner, str):
                m = re.search(r"\{.*\}", inner, re.DOTALL)
                if m:
                    agent_out = _json.loads(m.group(0))
        if isinstance(agent_out, dict):
            return {
                key: agent_out.get(key)
                for key in ("turns_used", "cost_usd", "input_tokens", "output_tokens", "verdict")
                if agent_out.get(key) is not None
            }
    except (ValueError, TypeError) as e:
        logger.warning("Failed to extract telemetry from job %s: %s", job_id, e)
    return {}


async def _run_container(
    job_id: str,
    run_id: str,
    file_path: str,
    config,
    audit: AuditLog,
    repo_path: str | None = None,
    bin_path: str | None = None,
    run_dir: str | None = None,
) -> tuple[str, str, str, int]:
    """Launch a single worker container. Returns (job_id, stdout, stderr, exit_code)."""
    repo = repo_path or config.repo_url
    # Resolve symlinks so container runtimes (e.g. Podman on macOS) can access the path.
    # macOS /tmp -> /private/tmp; Podman shares /private but not the symlink.
    repo = os.path.realpath(repo)

    cmd = [
        "docker",
        "run",
        "--rm",
        "--name",
        f"worker-{job_id[:12]}",
        "--memory",
        f"{config.worker_memory_gb}g",
        "--cpus",
        str(config.worker_cpus),
        "--tmpfs",
        "/tmp:size=4g",
        "-v",
        f"{repo}:/target/src:ro",
    ]
    # Mount pre-compiled binaries if available (skips compilation in entrypoint)
    if bin_path:
        bin_real = os.path.realpath(bin_path)
        cmd.extend(["-v", f"{bin_real}:/target/bin:ro"])
    # Mount custom prompts if configured (overrides baked-in /prompts/)
    if config.worker_prompts_dir:
        prompts_real = os.path.realpath(config.worker_prompts_dir)
        cmd.extend(["-v", f"{prompts_real}:/prompts:ro"])
    # Pass through provider API keys from environment (litellm reads them automatically)
    for key_name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY"):
        key_val = os.environ.get(key_name)
        if key_val:
            cmd.extend(["-e", f"{key_name}={key_val}"])
    cmd += [
        "-e",
        f"MODEL={config.worker_model}",
        "-e",
        f"MAX_TURNS={config.max_turns_per_worker}",
        "-e",
        f"FILE_PATH={file_path}",
        "-e",
        f"PROJECT_NAME={config.project_name}",
        "-e",
        f"PROJECT_DESCRIPTION={config.project_description}",
        "-e",
        f"BINARY_NAME={config.binary_name}",
        "-e",
        f"CONFIGURE_FLAGS={config.configure_flags}",
        "-e",
        f"SANITIZERS={','.join(config.sanitizers)}",
        "--security-opt",
        "no-new-privileges",
        "--cap-drop",
        "ALL",
        config.worker_image,
    ]

    # Log dispatch
    audit.write(
        run_id=run_id,
        event_type="job_dispatch",
        actor="orchestrator",
        payload={
            "job_id": job_id,
            "file_path": file_path,
            "image": config.worker_image,
        },
        job_id=job_id,
    )

    await update_job_status(
        run_id,
        job_id,
        config.redis_url,
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
    )

    start_time = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=config.container_timeout_seconds,
            )
            exit_code = proc.returncode or 0
        except asyncio.TimeoutError:
            wall_clock = round(time.monotonic() - start_time, 2)
            container_name = f"worker-{job_id[:12]}"
            logger.warning("Container for job %s timed out, killing container %s", job_id, container_name)
            # Use docker kill to forcefully stop the container (more reliable than proc.kill)
            try:
                kill_proc = await asyncio.create_subprocess_exec(
                    "docker",
                    "kill",
                    container_name,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(kill_proc.communicate(), timeout=10)
            except Exception:
                pass
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            stdout_bytes, stderr_bytes = b"", b""
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=15)
            except (asyncio.TimeoutError, Exception):
                pass
            exit_code = -1
            _save_stderr(run_dir, job_id, stderr_bytes)
            await update_job_status(
                run_id,
                job_id,
                config.redis_url,
                status="timeout",
                completed_at=datetime.now(timezone.utc).isoformat(),
            )
            audit.write(
                run_id=run_id,
                event_type="container_exit",
                actor="orchestrator",
                payload={
                    "job_id": job_id,
                    "exit_code": exit_code,
                    "reason": "timeout",
                    "stdout_len": len(stdout_bytes),
                    "wall_clock_seconds": wall_clock,
                },
                job_id=job_id,
            )
            return job_id, stdout_bytes.decode(errors="replace"), stderr_bytes.decode(errors="replace"), exit_code

        stdout = stdout_bytes.decode(errors="replace")
        stderr = stderr_bytes.decode(errors="replace")
        wall_clock = round(time.monotonic() - start_time, 2)
        _save_stderr(run_dir, job_id, stderr_bytes)
        agent_telemetry = _extract_telemetry(stdout, job_id)

        status = "done" if exit_code == 0 else "failed"
        await update_job_status(
            run_id,
            job_id,
            config.redis_url,
            status=status,
            completed_at=datetime.now(timezone.utc).isoformat(),
        )

        audit.write(
            run_id=run_id,
            event_type="container_exit",
            actor="orchestrator",
            payload={
                "job_id": job_id,
                "exit_code": exit_code,
                "stdout_len": len(stdout),
                "wall_clock_seconds": wall_clock,
                **{k: v for k, v in agent_telemetry.items() if v is not None},
            },
            job_id=job_id,
        )

        return job_id, stdout, stderr, exit_code

    except Exception as e:
        logger.error("Container launch failed for job %s: %s", job_id, e)
        await update_job_status(
            run_id,
            job_id,
            config.redis_url,
            status="failed",
            completed_at=datetime.now(timezone.utc).isoformat(),
            error=str(e),
        )
        audit.write(
            run_id=run_id,
            event_type="container_exit",
            actor="orchestrator",
            payload={"job_id": job_id, "error": str(e)},
            job_id=job_id,
        )
        return job_id, "", str(e), 1


async def dispatch_run(
    run_id: str,
    config,
    audit: AuditLog,
    repo_path: str | None = None,
    bin_path: str | None = None,
    run_dir: str | None = None,
) -> list[tuple[str, str, str, int]]:
    """Dispatch all queued jobs with concurrency control.

    Returns list of (job_id, stdout, stderr, exit_code) tuples.
    """
    if run_dir is None:
        logger.warning("run_dir is None — stderr persistence and trace analysis will be disabled")

    sem = asyncio.Semaphore(config.max_parallel_workers)
    results: list[tuple[str, str, str, int]] = []

    async def worker(job):
        async with sem:
            result = await _run_container(
                job.job_id,
                run_id,
                job.file_path,
                config,
                audit,
                repo_path,
                bin_path,
                run_dir,
            )
            results.append(result)

    tasks = []
    while True:
        # Check spend limit
        current_spend = await get_run_spend(run_id, config.redis_url)
        if current_spend >= config.max_run_spend_usd:
            logger.warning("Spend limit reached: $%.2f >= $%.2f", current_spend, config.max_run_spend_usd)
            audit.write(
                run_id=run_id,
                event_type="spend_limit_reached",
                actor="orchestrator",
                payload={
                    "current_spend": current_spend,
                    "limit": config.max_run_spend_usd,
                },
            )
            break

        job = await dequeue_job(run_id, config.redis_url)
        if job is None:
            break

        task = asyncio.create_task(worker(job))
        tasks.append(task)

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    return results
