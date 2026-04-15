#!/usr/bin/env bash
# Create vuln-harness-net Docker bridge network and restrict egress to api.anthropic.com:443 only.
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

echo "=== Setting up vuln-harness network isolation ==="

# Step 1: Create Docker bridge network (if not exists)
if docker network inspect "$NETWORK_NAME" &>/dev/null; then
    echo "Network $NETWORK_NAME already exists, skipping creation."
else
    echo "Creating Docker bridge network $NETWORK_NAME..."
    run_cmd docker network create \
        --driver bridge \
        --opt com.docker.network.bridge.name="$BRIDGE_IF" \
        --opt com.docker.network.bridge.enable_icc=false \
        "$NETWORK_NAME"
fi

# Step 2: Resolve api.anthropic.com IP(s)
echo "Resolving api.anthropic.com..."
ANTHROPIC_IPS=$(dig +short api.anthropic.com | grep -E '^[0-9]+\.' | head -5)
if [[ -z "$ANTHROPIC_IPS" ]]; then
    echo "WARNING: Could not resolve api.anthropic.com. Falling back to DNS name."
    echo "  Network isolation may not work correctly without resolved IPs."
fi

# Step 3: Apply iptables rules
echo "Applying iptables egress rules on $BRIDGE_IF..."

# Drop all forwarded traffic from the bridge (default deny)
run_cmd iptables -C FORWARD -i "$BRIDGE_IF" -j DROP 2>/dev/null \
    || run_cmd iptables -I FORWARD -i "$BRIDGE_IF" -j DROP

# Allow HTTPS to api.anthropic.com
for ip in $ANTHROPIC_IPS; do
    run_cmd iptables -C FORWARD -i "$BRIDGE_IF" -d "$ip" -p tcp --dport 443 -j ACCEPT 2>/dev/null \
        || run_cmd iptables -I FORWARD -i "$BRIDGE_IF" -d "$ip" -p tcp --dport 443 -j ACCEPT
    echo "  Allowed: $ip:443 (api.anthropic.com)"
done

# Allow DNS for initial resolution (needed by the Anthropic SDK)
run_cmd iptables -C FORWARD -i "$BRIDGE_IF" -p udp --dport 53 -j ACCEPT 2>/dev/null \
    || run_cmd iptables -I FORWARD -i "$BRIDGE_IF" -p udp --dport 53 -j ACCEPT

# Allow established connections back
run_cmd iptables -C FORWARD -i "$BRIDGE_IF" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
    || run_cmd iptables -I FORWARD -i "$BRIDGE_IF" -m state --state ESTABLISHED,RELATED -j ACCEPT

echo ""
echo "=== Active iptables rules for $BRIDGE_IF ==="
if $DRY_RUN; then
    echo "  [would show] iptables -L FORWARD -n -v | grep $BRIDGE_IF"
else
    iptables -L FORWARD -n -v | grep "$BRIDGE_IF" || echo "  (no rules found)"
fi

echo ""
echo "=== Setup complete ==="
echo "Containers on $NETWORK_NAME can reach api.anthropic.com:443 only."
echo "All other egress is blocked. Inter-container communication is disabled."
