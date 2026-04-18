"""Stage 5: validation agent via LLM (provider-agnostic via litellm)."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass

from harness.audit import AuditLog
from harness.llm import call_llm
from harness.parser import ParsedFinding

logger = logging.getLogger(__name__)

VALIDATION_PROMPT = """\
You are a senior security researcher reviewing an automated vulnerability report.
Assess whether this finding is real, exploitable, and worth a human researcher's time.

Finding:
{finding_json}

Answer the following:
1. Is the ASAN output consistent with a real memory safety bug? (yes/no/uncertain)
2. Is the reproduction case plausible and specific? (yes/no)
3. Is this a meaningful security issue (not just a crash in an error path with no attack surface)? (yes/no/uncertain)
4. Overall verdict: VALIDATE | REJECT | NEEDS_HUMAN_TRIAGE

Respond in JSON:
{{
  "asan_real": true | false | null,
  "repro_plausible": true | false,
  "security_meaningful": true | false | null,
  "verdict": "VALIDATE" | "REJECT" | "NEEDS_HUMAN_TRIAGE",
  "reasoning": "..."
}}
"""


@dataclass
class ValidationResult:
    asan_real: bool | None
    repro_plausible: bool
    security_meaningful: bool | None
    verdict: str  # VALIDATE | REJECT | NEEDS_HUMAN_TRIAGE
    reasoning: str


async def validate_finding(
    finding: ParsedFinding,
    config,
    audit: AuditLog,
) -> ValidationResult:
    """Validate a finding using a separate LLM call. Returns ValidationResult."""
    finding_dict = asdict(finding)
    finding_json = json.dumps(finding_dict, indent=2, default=str)
    prompt = VALIDATION_PROMPT.format(finding_json=finding_json)

    last_exc = None
    for attempt in range(3):
        try:
            response = await call_llm(
                prompt=prompt,
                model=config.validation_model,
                max_tokens=2048,
            )
            break
        except Exception as e:
            last_exc = e
            if attempt < 2:
                logger.warning("Validation call failed (attempt %d): %s", attempt + 1, e)
                continue
            raise last_exc from None

    audit.write(
        run_id=finding.run_id,
        event_type="llm_call",
        actor="validation_agent",
        payload={
            "stage": "validation",
            "model": config.validation_model,
            "backend": "litellm",
            "input_tokens": response.input_tokens,
            "output_tokens": response.output_tokens,
            "cost_usd": round(response.cost_usd, 6),
            "finding_job_id": finding.job_id,
        },
        job_id=finding.job_id,
    )

    # Parse JSON response
    text = response.text.strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        text = match.group(0)

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Validation agent returned malformed JSON: {response.text[:200]}") from e

    verdict = data.get("verdict", "NEEDS_HUMAN_TRIAGE")
    if verdict not in ("VALIDATE", "REJECT", "NEEDS_HUMAN_TRIAGE"):
        verdict = "NEEDS_HUMAN_TRIAGE"

    result = ValidationResult(
        asan_real=data.get("asan_real"),
        repro_plausible=data.get("repro_plausible", False),
        security_meaningful=data.get("security_meaningful"),
        verdict=verdict,
        reasoning=data.get("reasoning", ""),
    )

    audit.write(
        run_id=finding.run_id,
        event_type="finding_validated",
        actor="validation_agent",
        payload={
            "finding_job_id": finding.job_id,
            "verdict": result.verdict,
            "asan_real": result.asan_real,
            "repro_plausible": result.repro_plausible,
            "security_meaningful": result.security_meaningful,
        },
        job_id=finding.job_id,
    )

    return result
