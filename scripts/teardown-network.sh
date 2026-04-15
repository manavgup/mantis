#!/usr/bin/env bash
# Remove vuln-harness-net Docker bridge network and associated iptables rules.
# Must be run as root (for iptables). Idempotent — safe to run multiple times.
set -euo pipefail

DRY_RUN=false
NETWORK_NAME="vuln-harness-net"
BRIDGE_IF="vulnharness0"

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
    echo "[DRY RUN] Commands will be printed but not executed."
fi

run_cmd() {
    if $DRY_RUN; then
        echo "  [would run] $*"
    else
        echo "  [running] $*"
        "$@"
    fi
}

echo "=== Tearing down vuln-harness network isolation ==="

# Step 1: Remove iptables rules matching our bridge interface
echo "Removing iptables rules for $BRIDGE_IF..."
while iptables -D FORWARD -i "$BRIDGE_IF" -j DROP 2>/dev/null; do
    if $DRY_RUN; then break; fi
done
while iptables -D FORWARD -i "$BRIDGE_IF" -p tcp --dport 443 -j ACCEPT 2>/dev/null; do
    if $DRY_RUN; then break; fi
done
while iptables -D FORWARD -i "$BRIDGE_IF" -p udp --dport 53 -j ACCEPT 2>/dev/null; do
    if $DRY_RUN; then break; fi
done
while iptables -D FORWARD -i "$BRIDGE_IF" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do
    if $DRY_RUN; then break; fi
done
echo "  iptables rules removed."

# Step 2: Remove Docker network (if exists)
if docker network inspect "$NETWORK_NAME" &>/dev/null; then
    echo "Removing Docker network $NETWORK_NAME..."
    run_cmd docker network rm "$NETWORK_NAME"
else
    echo "Network $NETWORK_NAME does not exist, nothing to remove."
fi

echo ""
echo "=== Teardown complete ==="
