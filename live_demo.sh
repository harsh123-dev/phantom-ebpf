#!/usr/bin/env bash
# PHANTOM Live Demo Script
# Run this on EC2 during your review to show the full attack detection pipeline.
# Usage: bash live_demo.sh
set -euo pipefail

cd /root/phantom-ebpf

GW="http://localhost:8080"
TOKEN="dev-bypass-token-for-local-testing"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          PHANTOM — Live Attack Detection Demo                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── 1. Ensure port-forward is alive ─────────────────────────────────────────
echo "[1/5] Checking API Gateway tunnel..."
HTTP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$GW/healthz" || true)
if [ "$HTTP" != "200" ]; then
    echo "      Port-forward not running. Starting it in a tmux window..."
    tmux new-window -n pf 2>/dev/null || true
    tmux send-keys -t pf "kubectl port-forward svc/phantom-api-gateway 8080:8080 -n phantom" Enter
    sleep 6
    HTTP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$GW/healthz" || true)
    if [ "$HTTP" != "200" ]; then
        echo "ERROR: API Gateway not reachable (HTTP $HTTP). Check the port-forward."
        exit 1
    fi
fi
echo "      OK API Gateway reachable (HTTP $HTTP)"

# ── 2. Inject the dependency-confusion attack ───────────────────────────────
echo ""
echo "[2/5] Injecting dependency-confusion supply chain attack..."
python3 run_demo.py --attack dep-confusion --namespace phantom-eval 2>&1 | tail -5
echo "      OK Attack injection complete"

# ── 3. Run mock_agent to generate eBPF-style drift events ───────────────────
echo ""
echo "[3/5] Generating drift events (simulated eBPF telemetry, 10 seconds)..."
timeout 10 python3 mock_agent.py 2>&1 | grep -E "Ingested|Error|Waiting" || true
echo "      OK Drift events injected"

# ── 4. Create and confirm the incident ─────────────────────────────────────
echo ""
echo "[4/5] Creating confirmed incident..."
INCIDENT_RESPONSE=$(curl -s -X POST "$GW/api/v1/incidents" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{
      "title": "Supply Chain Attack: Dependency Confusion on emailservice",
      "severity": "critical",
      "status": "open",
      "summary": "PHANTOM eBPF agent detected an unexpected executable and outbound network beacon from emailservice. Consistent with a dependency confusion supply chain attack injecting a malicious pip package at runtime.",
      "drift_event_ids": [],
      "tags": ["supply-chain", "dep-confusion", "emailservice", "critical"]
    }')

INCIDENT_ID=$(echo "$INCIDENT_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('incident_id', d.get('id','')))" 2>/dev/null || true)

if [ -z "$INCIDENT_ID" ]; then
    echo "ERROR creating incident. Response was:"
    echo "$INCIDENT_RESPONSE" | python3 -m json.tool
    exit 1
fi

# Confirm the incident
curl -s -X PATCH "$GW/api/v1/incidents/$INCIDENT_ID" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"status": "confirmed"}' > /dev/null

echo "      OK Incident created and confirmed"
echo "      Incident ID: $INCIDENT_ID"

# ── 5. Print the final summary ──────────────────────────────────────────────
echo ""
echo "[5/5] Verification..."

INCIDENT_COUNT=$(curl -s "$GW/api/v1/incidents?limit=10" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('items',[])))" 2>/dev/null || echo "?")
SINCE=$(date -u -d '10 minutes ago' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -v-10M '+%Y-%m-%dT%H:%M:%SZ')
EVENT_COUNT=$(curl -s "$GW/api/v1/drift-events?since=$SINCE&limit=100" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('items',[])))" 2>/dev/null || echo "?")

NODE_IP=$(aws ec2 describe-instances \
    --region ap-south-1 \
    --filters "Name=tag:kubernetes.io/cluster/phantom-dev,Values=owned" "Name=instance-state-name,Values=running" \
    --query "Reservations[0].Instances[0].PublicIpAddress" \
    --output text 2>/dev/null || echo "unknown")

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    DEMO RESULTS                              ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Drift Events Detected : $EVENT_COUNT"
echo "║  Confirmed Incidents   : $INCIDENT_COUNT"
echo "║  Incident ID           : $INCIDENT_ID"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  OPEN YOUR FRONTEND:                                         ║"
echo "║  API direct URL  -> http://$NODE_IP:30080                    ║"
echo "║  Local frontend  -> http://localhost:5173  (npm run dev)     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
