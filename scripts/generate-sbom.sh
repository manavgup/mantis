#!/usr/bin/env bash
# ================================================================
# generate-sbom.sh — Generate a CycloneDX SBOM for the worker image
# ================================================================
set -euo pipefail

IMAGE="${1:-vuln-harness-worker:latest}"
OUTPUT="sbom.json"

# ── Pre-flight: check for syft ──────────────────────────────────
if ! command -v syft &>/dev/null; then
    echo "ERROR: syft is not installed." >&2
    echo "" >&2
    echo "Install instructions:" >&2
    echo "  brew install syft          # macOS" >&2
    echo "  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin" >&2
    echo "  https://github.com/anchore/syft#installation" >&2
    exit 1
fi

# ── Generate SBOM ────────────────────────────────────────────────
echo "Generating CycloneDX SBOM for ${IMAGE}..."

syft "${IMAGE}" -o cyclonedx-json > "${OUTPUT}"

echo "SBOM written to ${OUTPUT}"
