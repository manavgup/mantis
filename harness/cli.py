"""CLI entry point for vuln-harness."""

from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path

import click

from harness.audit import AuditLog, verify_chain
from harness.sanitizers import build_sanitizer_flags


@click.group()
def cli():
    """Mantis — autonomous vulnerability discovery."""
    pass


@cli.command()
@click.option("--config", "config_path", default="./harness.yaml", help="Path to harness.yaml")
def rank(config_path: str):
    """Stage 1 only: rank files by vulnerability likelihood."""
    os.environ.setdefault("HARNESS_CONFIG", config_path)
    from harness.config import Config

    cfg = Config()
    run_id = str(uuid.uuid4())
    run_dir = cfg.run_output_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    audit = AuditLog(run_dir / "audit.jsonl")
    audit.write(
        run_id=run_id, event_type="run_start", actor="orchestrator", payload={"command": "rank", "config": config_path}
    )

    repo_path = Path(cfg.repo_url) if Path(cfg.repo_url).exists() else None
    if repo_path is None:
        # Clone the repo
        import subprocess

        repo_path = run_dir / "repo"
        click.echo(f"Cloning {cfg.repo_url} ...")
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", cfg.repo_commit, cfg.repo_url, str(repo_path)],
            check=True,
        )

    from harness.ranker import rank_files, write_rankings_json

    ranked = asyncio.run(
        rank_files(
            run_id=run_id,
            repo_path=repo_path,
            exclude_patterns=cfg.exclude_patterns,
            ranking_model=cfg.ranking_model,
            max_files_to_scan=cfg.max_files_to_scan,
            audit=audit,
            strategy=cfg.ranking_strategy,
        )
    )

    write_rankings_json(
        run_dir=run_dir,
        run_id=run_id,
        repo_url=cfg.repo_url,
        repo_commit=cfg.repo_commit,
        ranked_files=ranked,
        total_files=len(ranked),
        excluded=0,
        cost=0.0,
    )

    # Pretty-print table
    click.echo(f"\n{'Rank':<6}{'Score':<7}{'Path':<50}{'Reason'}")
    click.echo("-" * 100)
    for i, rf in enumerate(ranked, 1):
        click.echo(f"{i:<6}{rf.score:<7}{rf.path:<50}{rf.reason}")

    click.echo(f"\nTotal ranked: {len(ranked)}")
    click.echo(f"Rankings written to: {run_dir / 'file_rankings.json'}")
    click.echo(f"Run ID: {run_id}")


def _clone_repo(cfg, run_dir: Path) -> Path:
    """Clone or resolve repo path. Returns local path."""
    repo_path = Path(cfg.repo_url) if Path(cfg.repo_url).exists() else None
    if repo_path is None:
        import subprocess

        repo_path = run_dir / "repo"
        if not repo_path.exists():
            click.echo(f"Cloning {cfg.repo_url} ...")
            subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", cfg.repo_commit, cfg.repo_url, str(repo_path)],
                check=True,
            )
    return repo_path


def _build_sanitized_binaries(cfg, repo_path: Path, bin_dir: Path, run_id: str, audit: AuditLog | None = None) -> None:
    """Run the builder container once and collect sanitized binaries into *bin_dir*.

    Raises ``SystemExit(1)`` if the build fails.
    """
    import subprocess

    repo_real = os.path.realpath(str(repo_path))
    bin_real = os.path.realpath(str(bin_dir))
    sanitizer_flags = build_sanitizer_flags(cfg.sanitizers)
    sanitizer_list = ",".join(sanitizer_flags.sanitizers)

    click.echo(f"Building {cfg.project_name} with sanitizers: {sanitizer_list}...")

    cmd = [
        "docker",
        "run",
        "--rm",
        "--name",
        f"builder-{run_id[:12]}",
        "--memory",
        f"{cfg.worker_memory_gb}g",
        "--cpus",
        str(cfg.worker_cpus),
        "--tmpfs",
        "/tmp:size=4g",
        "-v",
        f"{repo_real}:/target/src:ro",
        "-v",
        f"{bin_real}:/output",
        "-e",
        f"BINARY_NAME={cfg.binary_name}",
        "-e",
        f"CONFIGURE_FLAGS={cfg.configure_flags}",
        "-e",
        f"SANITIZERS={sanitizer_list}",
        "-e",
        f"FULL_CFLAGS={sanitizer_flags.cflags}",
        "-e",
        f"FULL_LDFLAGS={sanitizer_flags.ldflags}",
        "--entrypoint",
        "/bin/bash",
        cfg.worker_image,
        "-c",
        _BUILD_SCRIPT,
    ]

    if audit is not None:
        audit.write(
            run_id=run_id,
            event_type="build_start",
            actor="orchestrator",
            payload={
                "image": cfg.worker_image,
                "bin_dir": str(bin_dir),
                "sanitizers": list(sanitizer_flags.sanitizers),
            },
        )

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        click.echo(f"Build failed (exit {result.returncode}):")
        click.echo(result.stderr[-2000:] if len(result.stderr) > 2000 else result.stderr)
        if audit is not None:
            audit.write(
                run_id=run_id,
                event_type="build_failed",
                actor="orchestrator",
                payload={"exit_code": result.returncode},
            )
        raise SystemExit(1)

    binaries = list(bin_dir.iterdir())
    click.echo(f"Build complete. {len(binaries)} binaries collected:")
    for b in sorted(binaries):
        size_mb = b.stat().st_size / (1024 * 1024)
        click.echo(f"  {b.name} ({size_mb:.1f} MB)")

    if audit is not None:
        audit.write(
            run_id=run_id,
            event_type="build_complete",
            actor="orchestrator",
            payload={"binary_count": len(binaries)},
        )


@cli.command()
@click.option("--config", "config_path", default="./harness.yaml", help="Path to harness.yaml")
def build(config_path: str):
    """Compile target with configured sanitizers in a single container. Saves binaries for worker reuse."""
    os.environ.setdefault("HARNESS_CONFIG", config_path)
    from harness.config import Config

    cfg = Config()
    run_id = str(uuid.uuid4())
    run_dir = cfg.run_output_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    bin_dir = run_dir / "bin"
    bin_dir.mkdir(exist_ok=True)

    repo_path = _clone_repo(cfg, run_dir)

    _build_sanitized_binaries(cfg, repo_path, bin_dir, run_id)

    click.echo(f"\nBin dir: {bin_dir}")
    click.echo(f"Run ID: {run_id}")
    click.echo(f"\nTo scan: vuln-harness run --config {config_path} --bin-dir {bin_dir}")


# Build script executed inside the builder container
_BUILD_SCRIPT = r"""
set -euo pipefail

cp -a /target/src /tmp/src
cd /tmp/src
git submodule update --init --recursive 2>/dev/null || true

export CC=clang
export SANITIZERS="${SANITIZERS:-asan}"
export CFLAGS="${FULL_CFLAGS}"
export LDFLAGS="${FULL_LDFLAGS}"

echo "=== active sanitizers: ${SANITIZERS} ===" >&2
echo "=== sanitize flags: ${CFLAGS} / ${LDFLAGS} ===" >&2

if [ -n "${CONFIGURE_FLAGS:-}" ]; then
    CONF_CMD="./configure $CONFIGURE_FLAGS"
else
    CONF_CMD="./configure --disable-shared"
fi

if [ -f ./configure ]; then
    echo "Build system: configure" >&2
    eval "$CONF_CMD" >&2 && make -j"$(nproc)" >&2
elif [ -f ./configure.ac ] || [ -f ./configure.in ]; then
    echo "Build system: autotools" >&2
    autoreconf -fi >&2 && eval "$CONF_CMD" >&2 && make -j"$(nproc)" >&2
elif [ -f CMakeLists.txt ]; then
    echo "Build system: cmake" >&2
    mkdir -p build && cd build
    cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CFLAGS" \
        -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" -DCMAKE_SHARED_LINKER_FLAGS="$LDFLAGS" \
        -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF .. >&2
    make -j"$(nproc)" >&2
    cd ..
elif [ -f Makefile ] || [ -f makefile ] || [ -f GNUmakefile ]; then
    echo "Build system: Makefile" >&2
    make CC=clang CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" -j"$(nproc)" >&2 || true
fi

# Collect binaries to /output (mounted from host)
find /tmp/src -type f -executable \
    ! -name '*.sh' ! -name '*.py' ! -name '*.pl' ! -name '*.cmake' \
    ! -name '*.sample' ! -name '*.so*' ! -name '*.o' \
    ! -path '*/CMakeFiles/*' ! -path '*/.git/*' \
    -exec cp -n {} /output/ \; 2>/dev/null || true

echo "=== collected binaries ===" >&2
ls /output/ >&2
"""


@cli.command()
@click.option("--config", "config_path", default="./harness.yaml", help="Path to harness.yaml")
@click.option("--bin-dir", "bin_dir", default=None, help="Pre-compiled binaries dir (from 'build' command)")
def run(config_path: str, bin_dir: str | None):
    """Full pipeline: rank, dispatch workers, parse, validate, report."""
    os.environ.setdefault("HARNESS_CONFIG", config_path)
    from harness.config import Config

    cfg = Config()
    run_id = str(uuid.uuid4())
    run_dir = cfg.run_output_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "findings").mkdir(exist_ok=True)

    audit = AuditLog(run_dir / "audit.jsonl")
    audit.write(
        run_id=run_id,
        event_type="run_start",
        actor="orchestrator",
        payload={"command": "run", "config": config_path, "bin_dir": bin_dir},
    )

    # Step 1: Clone or use local repo
    repo_path = _clone_repo(cfg, run_dir)

    # Step 1b: Auto-build ASAN binaries if not pre-supplied
    if bin_dir is None:
        auto_bin_dir = run_dir / "bin"
        auto_bin_dir.mkdir(exist_ok=True)
        _build_sanitized_binaries(cfg, repo_path, auto_bin_dir, run_id, audit=audit)
        bin_dir = str(auto_bin_dir)
        click.echo(f"  Auto-built binaries: {bin_dir}")

    # Step 2: Rank files
    click.echo("Stage 1: Ranking files...")
    from harness.ranker import rank_files, write_rankings_json

    ranked = asyncio.run(
        rank_files(
            run_id=run_id,
            repo_path=repo_path,
            exclude_patterns=cfg.exclude_patterns,
            ranking_model=cfg.ranking_model,
            max_files_to_scan=cfg.max_files_to_scan,
            audit=audit,
            strategy=cfg.ranking_strategy,
        )
    )
    write_rankings_json(
        run_dir=run_dir,
        run_id=run_id,
        repo_url=cfg.repo_url,
        repo_commit=cfg.repo_commit,
        ranked_files=ranked,
        total_files=len(ranked),
        excluded=0,
        cost=0.0,
    )
    click.echo(f"  Ranked {len(ranked)} files")

    # Step 3: Enqueue jobs
    click.echo("Stage 2: Enqueueing jobs...")
    from harness.queue import enqueue_jobs

    asyncio.run(enqueue_jobs(run_id, ranked, cfg.redis_url))
    click.echo(f"  Enqueued {len(ranked)} jobs")

    # Step 4: Dispatch workers
    if bin_dir:
        click.echo(f"Stage 3: Dispatching workers (pre-compiled: {bin_dir})...")
    else:
        click.echo("Stage 3: Dispatching workers (compiling per container)...")
    from harness.dispatcher import dispatch_run

    results = asyncio.run(dispatch_run(run_id, cfg, audit, repo_path=repo_path, bin_path=bin_dir, run_dir=str(run_dir)))
    click.echo(f"  Completed {len(results)} containers")

    # Step 5: Parse and validate
    click.echo("Stages 4-5: Parsing and validating...")
    from harness.crypto import load_key_from_env
    from harness.findings import ensure_job_exists, ensure_run_exists, generate_report, store_finding
    from harness.parser import parse_result
    from harness.validator import validate_finding

    try:
        enc_key = load_key_from_env(cfg.findings_encryption_key_env)
    except (ValueError, KeyError):
        enc_key = None
        click.echo("  WARNING: FINDINGS_ENC_KEY not set — findings will not be stored to Postgres")
    findings_count = 0
    validated_count = 0
    rejected_count = 0

    # Ensure run record exists in Postgres for FK constraints
    if enc_key:
        asyncio.run(ensure_run_exists(run_id, cfg.repo_url, cfg.repo_commit, cfg.postgres_url))

    for job_id, stdout, stderr, exit_code in results:
        finding = parse_result(stdout, stderr, job_id=job_id, run_id=run_id)
        if finding is None:
            continue
        findings_count += 1

        validation = asyncio.run(validate_finding(finding, cfg, audit))
        if validation.verdict == "VALIDATE":
            validated_count += 1
        elif validation.verdict == "REJECT":
            rejected_count += 1

        import uuid as _uuid

        finding_id = str(_uuid.uuid4())

        # Store to Postgres if encryption key available
        if enc_key:
            asyncio.run(
                ensure_job_exists(
                    job_id,
                    run_id,
                    finding.file or "",
                    finding.severity_tier,
                    cfg.postgres_url,
                )
            )
            finding_id = asyncio.run(
                store_finding(
                    finding,
                    validation,
                    run_id,
                    job_id,
                    enc_key,
                    cfg.postgres_url,
                )
            )

        report = generate_report(finding, validation, run_id, finding_id)
        report_path = run_dir / "findings" / f"{finding_id}.md"
        report_path.write_text(report)

    # Summary
    click.echo(f"\n{'=' * 60}")
    click.echo(f"Run complete: {run_id}")
    click.echo(f"  Jobs dispatched: {len(results)}")
    click.echo(f"  Findings: {findings_count}")
    click.echo(f"  Validated: {validated_count}")
    click.echo(f"  Rejected: {rejected_count}")
    click.echo(f"  Output: {run_dir}")


@cli.command("review")
@click.option("--run-id", required=True, help="Run ID to review")
@click.option("--config", "config_path", default="./harness.yaml", help="Path to harness.yaml")
def review_cmd(run_id: str, config_path: str):
    """List findings awaiting human review."""
    os.environ.setdefault("HARNESS_CONFIG", config_path)
    from harness.config import Config
    from harness.findings import list_pending_review

    cfg = Config()
    findings = asyncio.run(list_pending_review(run_id, cfg.postgres_url))
    if not findings:
        click.echo("No findings awaiting review.")
        return

    click.echo(f"\n{'ID':<38}{'Tier':<6}{'CVSS':<7}{'Type':<25}{'File':<40}{'Verdict'}")
    click.echo("-" * 120)
    for f in findings:
        click.echo(
            f"{f['finding_id']!s:<38}{f['severity_tier']:<6}{f['cvss_estimate']:<7}"
            f"{f['vuln_type'] or '':<25}{f['file_path'] or '':<40}{f['validation_verdict']}"
        )


@cli.command()
@click.option("--finding-id", required=True, help="Finding ID to approve")
@click.option("--reviewer", required=True, help="Reviewer name")
@click.option("--cvss", required=True, type=float, help="Confirmed CVSS score")
@click.option("--approve-disclosure", is_flag=True, default=False, help="Approve disclosure")
@click.option("--config", "config_path", default="./harness.yaml", help="Path to harness.yaml")
def approve(finding_id: str, reviewer: str, cvss: float, approve_disclosure: bool, config_path: str):
    """Record human sign-off on a finding."""
    os.environ.setdefault("HARNESS_CONFIG", config_path)
    from harness.config import Config
    from harness.findings import record_human_review

    cfg = Config()

    run_dir = cfg.run_output_dir
    # Find the run containing this finding
    audit = None
    for d in run_dir.iterdir():
        if d.is_dir() and (d / "audit.jsonl").exists():
            audit = AuditLog(d / "audit.jsonl")
            break

    asyncio.run(
        record_human_review(
            finding_id,
            reviewer,
            cvss,
            approve_disclosure,
            cfg.postgres_url,
            audit,
        )
    )
    click.echo(f"Finding {finding_id} reviewed by {reviewer}. CVSS: {cvss}. Disclosure: {approve_disclosure}")


@cli.command("audit-verify")
@click.option("--run-id", required=True, help="Run ID to verify")
@click.option("--config", "config_path", default="./harness.yaml", help="Path to harness.yaml")
def audit_verify(run_id: str, config_path: str):
    """Verify audit log hash chain integrity."""
    os.environ.setdefault("HARNESS_CONFIG", config_path)
    from harness.config import Config

    cfg = Config()
    audit_path = cfg.run_output_dir / run_id / "audit.jsonl"
    if not audit_path.exists():
        click.echo(f"Audit log not found: {audit_path}")
        raise SystemExit(1)

    valid, broken_seq = verify_chain(audit_path)
    if valid:
        click.echo("Chain valid")
    else:
        click.echo(f"Chain broken at entry seq={broken_seq}")
        raise SystemExit(1)


@cli.command()
@click.option("--run-id", required=True, help="Run ID")
@click.option("--config", "config_path", default="./harness.yaml", help="Path to harness.yaml")
def cost(run_id: str, config_path: str):
    """Print cost breakdown for a run."""
    os.environ.setdefault("HARNESS_CONFIG", config_path)
    import json

    from harness.config import Config

    cfg = Config()
    audit_path = cfg.run_output_dir / run_id / "audit.jsonl"
    if not audit_path.exists():
        click.echo(f"Audit log not found: {audit_path}")
        raise SystemExit(1)

    total = 0.0
    by_stage: dict[str, float] = {}
    with open(audit_path) as f:
        for line in f:
            entry = json.loads(line.strip())
            if entry["event_type"] == "llm_call":
                c = entry["payload"].get("cost_usd", 0.0)
                stage = entry["payload"].get("stage", "unknown")
                total += c
                by_stage[stage] = by_stage.get(stage, 0.0) + c

    click.echo(f"Cost breakdown for run {run_id}:")
    for stage, c in sorted(by_stage.items()):
        click.echo(f"  {stage}: ${c:.4f}")
    click.echo(f"  Total: ${total:.4f}")
