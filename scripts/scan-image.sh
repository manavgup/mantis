#!/usr/bin/env bash
# ================================================================
# scan-image.sh — Scan the worker Docker image for vulnerabilities
# ================================================================
set -euo pipefail

IMAGE="${1:-vuln-harness-worker:latest}"

# ── Pre-flight: check for trivy ─────────────────────────────────
if ! command -v trivy &>/dev/null; then
    echo "ERROR: trivy is not installed." >&2
    echo "" >&2
    echo "Install instructions:" >&2
    echo "  brew install trivy          # macOS" >&2
    echo "  sudo apt-get install trivy  # Debian/Ubuntu (add aquasecurity repo first)" >&2
    echo "  https://aquasecurity.github.io/trivy/latest/getting-started/installation/" >&2
    exit 1
fi

# ── Run scan ─────────────────────────────────────────────────────
echo "Scanning ${IMAGE} for CRITICAL and HIGH vulnerabilities..."
echo ""

trivy image --severity CRITICAL,HIGH --exit-code 1 "${IMAGE}"
STATUS=$?

echo ""
if [ $STATUS -eq 0 ]; then
    echo "PASS: No CRITICAL or HIGH vulnerabilities found."
else
    echo "FAIL: Vulnerabilities detected (exit code ${STATUS})."
fi

exit $STATUS
