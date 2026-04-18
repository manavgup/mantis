#!/usr/bin/env bash
# Create vuln-harness-net Docker bridge network and restrict egress to allowed LLM provider APIs only.
# Must be run as root (for iptables). Idempotent — safe to run multiple times.
#
# Configurable via ALLOWED_API_DOMAINS env var (space-separated).
# Default: api.anthropic.com api.openai.com generativelanguage.googleapis.com
set -euo pipefail

DRY_RUN=false
NETWORK_NAME="vuln-harness-net"
BRIDGE_IF="vulnharness0"
ALLOWED_API_DOMAINS="${ALLOWED_API_DOMAINS:-api.anthropic.com api.openai.com generativelanguage.googleapis.com}"

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
echo "Allowed API domains: $ALLOWED_API_DOMAINS"

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

# Step 2: Resolve allowed API domain IPs
ALL_IPS=""
for domain in $ALLOWED_API_DOMAINS; do
    echo "Resolving $domain..."
    DOMAIN_IPS=$(dig +short "$domain" | grep -E '^[0-9]+\.' | head -5)
    if [[ -z "$DOMAIN_IPS" ]]; then
        echo "  WARNING: Could not resolve $domain. Skipping."
    else
        ALL_IPS="$ALL_IPS $DOMAIN_IPS"
        for ip in $DOMAIN_IPS; do
            echo "  Resolved: $ip"
        done
    fi
done

# Step 3: Apply iptables rules
echo "Applying iptables egress rules on $BRIDGE_IF..."

# Drop all forwarded traffic from the bridge (default deny)
run_cmd iptables -C FORWARD -i "$BRIDGE_IF" -j DROP 2>/dev/null \
    || run_cmd iptables -I FORWARD -i "$BRIDGE_IF" -j DROP

# Allow HTTPS to each resolved API endpoint
for ip in $ALL_IPS; do
    run_cmd iptables -C FORWARD -i "$BRIDGE_IF" -d "$ip" -p tcp --dport 443 -j ACCEPT 2>/dev/null \
        || run_cmd iptables -I FORWARD -i "$BRIDGE_IF" -d "$ip" -p tcp --dport 443 -j ACCEPT
    echo "  Allowed: $ip:443"
done

# Allow DNS for initial resolution
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
echo "Containers on $NETWORK_NAME can reach allowed API endpoints only."
echo "All other egress is blocked. Inter-container communication is disabled."
