"""SQLAlchemy models for the results store."""

from __future__ import annotations

import uuid

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    Numeric,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class Run(Base):
    __tablename__ = "runs"

    run_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    repo_url = Column(Text, nullable=False)
    repo_commit = Column(Text, nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=False)
    completed_at = Column(DateTime(timezone=True))
    status = Column(Text, nullable=False)  # running | completed | aborted
    total_jobs = Column(Integer)
    completed_jobs = Column(Integer)
    failed_jobs = Column(Integer)
    total_cost_usd = Column(Numeric(10, 4))
    config = Column(JSONB)


class Job(Base):
    __tablename__ = "jobs"

    job_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id = Column(UUID(as_uuid=True), ForeignKey("runs.run_id"))
    file_path = Column(Text, nullable=False)
    priority_score = Column(Integer, nullable=False)
    status = Column(Text, nullable=False)  # pending | running | done | failed | timeout
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    cost_usd = Column(Numeric(10, 4))
    container_id = Column(Text)
    result_raw = Column(JSONB)


class Finding(Base):
    __tablename__ = "findings"

    finding_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("jobs.job_id"))
    run_id = Column(UUID(as_uuid=True), ForeignKey("runs.run_id"))
    vuln_type = Column(Text)
    file_path = Column(Text)
    line_number = Column(Integer)
    function_name = Column(Text)
    severity_tier = Column(Integer)
    cvss_estimate = Column(Numeric(4, 1))
    cvss_confirmed = Column(Numeric(4, 1))
    validation_verdict = Column(Text)  # VALIDATE | REJECT | NEEDS_HUMAN_TRIAGE
    human_reviewed = Column(Boolean, default=False)
    human_reviewer = Column(Text)
    reviewed_at = Column(DateTime(timezone=True))
    disclosure_approved = Column(Boolean, default=False)
    reproduction_enc = Column(LargeBinary)
    patch_enc = Column(LargeBinary)
    asan_output_enc = Column(LargeBinary)
