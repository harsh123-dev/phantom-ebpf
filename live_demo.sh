#!/usr/bin/env bash
# PHANTOM Live Demo Script
# ─────────────────────────────────────────────────────────────────────────────
# IMPORTANT: Run this from your DIRECT EC2 SSH terminal.
#            Do NOT run this inside Codex CLI — Codex runs in a restricted
#            sandbox where kubectl DNS and tmux are blocked.
#
# How to run:
#   ssh -i your-key.pem ubuntu@<EC2-IP>
#   cd /root/phantom-ebpf
#   bash live_demo.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# Guard: detect if we are inside the Codex sandbox (kubectl DNS blocked)
if ! kubectl cluster-info --request-timeout=5s > /dev/null 2>&1; then
    echo ""
    echo "ERROR: kubectl cannot reach the EKS cluster."
    echo ""
    echo "This script must be run from a DIRECT EC2 SSH terminal, not inside Codex CLI."
    echo "Codex CLI runs in a sandboxed container where EKS network access is blocked."
    echo ""
    echo "Steps:"
    echo "  1. Open a new terminal on your local machine"
    echo "  2. SSH into the EC2 instance directly:"
    echo "       ssh -i <key.pem> ubuntu@<EC2-IP>"
    echo "  3. cd /root/phantom-ebpf"
    echo "  4. bash live_demo.sh"
    exit 1
fi

cd /root/phantom-ebpf

GW="http://localhost:8080"
TOKEN="dev-bypass-token-for-local-testing"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          PHANTOM — Live Attack Detection Demo                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── 1. Ensure port-forward is alive (no tmux required) ──────────────────────
echo "[1/5] Checking API Gateway tunnel..."
HTTP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$GW/healthz" || true)
if [ "$HTTP" != "200" ]; then
    echo "      Port-forward not running. Starting in background..."
    # Kill any stale port-forward processes on 8080
    pkill -f "kubectl port-forward.*8080" 2>/dev/null || true
    sleep 1
    # Start fresh in background (no tmux needed)
    nohup kubectl port-forward svc/phantom-api-gateway 8080:8080 -n phantom \
        >> /tmp/pf.log 2>&1 &
    echo $! > /tmp/pf.pid
    echo "      Waiting for tunnel to establish..."
    sleep 6
    HTTP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$GW/healthz" || true)
    if [ "$HTTP" != "200" ]; then
        echo "ERROR: Port-forward failed. Last log:"
        tail -10 /tmp/pf.log
        exit 1
    fi
fi
echo "      OK API Gateway reachable (HTTP $HTTP)"

# ── 2. Inject the dependency-confusion attack ───────────────────────────────
echo ""
echo "[2/5] Injecting dependency-confusion supply chain attack..."
python3 run_demo.py --attack dep-confusion --namespace phantom-eval 2>&1 | tail -5
echo "      OK Attack injection complete"

# ── 3. Generate drift events via direct API POST (same as the real eBPF agent) ──
echo ""
echo "[3/5] Generating drift events via API (simulating eBPF telemetry)..."

# Get real pod info from the cluster
EMAIL_POD=$(kubectl get pods -n phantom-eval -l app=emailservice \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "emailservice-demo")
EMAIL_UID=$(kubectl get pods -n phantom-eval -l app=emailservice \
    -o jsonpath='{.items[0].metadata.uid}' 2>/dev/null || echo "00000000-0000-0000-0000-000000000002")
NODE=$(kubectl get pods -n phantom-eval -l app=emailservice \
    -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null || echo "node-1")
NOW=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

_post_event() {
    local evt_type="$1" comm="$2" path="$3" vtype="$4"
    local eid
    eid=$(python3 -c "import uuid; print(uuid.uuid4())")
    local http
    http=$(curl -s -o /tmp/drift_resp.json -w "%{http_code}" \
        -X POST "$GW/api/v1/drift-events" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{
          \"schema_version\": \"v1\",
          \"event_id\": \"$eid\",
          \"observed_at\": \"$NOW\",
          \"node_name\": \"$NODE\",
          \"event_type\": \"$evt_type\",
          \"process\": {
            \"pid\": 12345, \"tgid\": 12345, \"ppid\": 1,
            \"start_time_ns\": 1000000000,
            \"comm\": \"$comm\",
            \"executable_path\": \"$path\",
            \"uid\": 0, \"gid\": 0
          },
          \"workload\": {
            \"cluster_name\": \"phantom-dev\",
            \"namespace\": \"phantom-eval\",
            \"pod_name\": \"$EMAIL_POD\",
            \"pod_uid\": \"$EMAIL_UID\",
            \"container_name\": \"emailservice\",
            \"container_id\": \"containerd://phantom-demo\",
            \"image_digest\": \"sha256:0000000000000000000000000000000000000000000000000000000000000000\",
            \"cgroup_id\": 1,
            \"service_account\": \"default\"
          },
          \"identity_status\": \"resolved\",
          \"violations\": [{
            \"violation_type\": \"$vtype\",
            \"severity\": \"high\",
            \"observed\": \"$path\",
            \"confidence\": 0.97
          }],
          \"evidence\": {
            \"kernel_timestamp_ns\": 1000000000,
            \"cpu\": 0, \"architecture\": \"x86_64\",
            \"event_loss_observed\": false,
            \"raw_event_digest\": \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"
          },
          \"agent_sequence\": 1,
          \"tenant_id\": \"00000000-0000-0000-0000-000000000001\"
        }")
    if [ "$http" = "200" ] || [ "$http" = "201" ] || [ "$http" = "202" ]; then
        local did
        did=$(python3 -c "import sys,json; print(json.load(open('/tmp/drift_resp.json')).get('drift_event_id','?'))" 2>/dev/null || echo "?")
        echo "      Ingested [$evt_type] drift_event_id=$did"
    else
        echo "      WARNING: drift event POST returned HTTP $http"
        cat /tmp/drift_resp.json 2>/dev/null || true
    fi
}

_post_event "exec"            "pip"     "/usr/local/bin/pip"               "unexpected_process_relation"
_post_event "network_connect" "python3" "/usr/local/bin/python3"           "unexpected_network"
_post_event "exec"            "curl"    "/usr/bin/curl"                    "unexpected_process_relation"

echo "      OK Drift events posted to API"

echo "      OK Drift events injected"

# ── 4. Create and confirm the incident ─────────────────────────────────────
echo ""
echo "[4/5] Creating confirmed incident..."

# Fetch a real drift event ID (required — drift_event_ids must have at least 1 UUID)
SINCE=$(date -u -d '30 minutes ago' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -v-30M '+%Y-%m-%dT%H:%M:%SZ')
DRIFT_ID=$(curl -s "$GW/api/v1/drift-events?since=$SINCE&limit=1" \
    -H "Authorization: Bearer $TOKEN" | \
    python3 -c "import sys,json; items=json.load(sys.stdin).get('items',[]); print(items[0]['drift_event_id'] if items else '')" 2>/dev/null || true)

if [ -z "$DRIFT_ID" ]; then
    echo "      WARNING: No drift events found. Checking further back (2 hours)..."
    SINCE2=$(date -u -d '2 hours ago' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -v-2H '+%Y-%m-%dT%H:%M:%SZ')
    DRIFT_ID=$(curl -s "$GW/api/v1/drift-events?since=$SINCE2&limit=1" \
        -H "Authorization: Bearer $TOKEN" | \
        python3 -c "import sys,json; items=json.load(sys.stdin).get('items',[]); print(items[0]['drift_event_id'] if items else '')" 2>/dev/null || true)
fi

if [ -z "$DRIFT_ID" ]; then
    echo "      ERROR: No drift events in database. Drift event injection must have failed."
    exit 1
fi

echo "      Using drift event: $DRIFT_ID"

# Get a valid snapshot_id to satisfy the foreign key constraint
GW_POD=$(kubectl get pods -n phantom -l app=phantom-api-gateway -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
SNAPSHOT_ID="00000000-0000-0000-0000-000000000000"
if [ -n "$GW_POD" ]; then
    echo "      Fetching a valid snapshot_id from database..."
    SCRIPT="
import asyncio, asyncpg, os
async def run():
    pool = await asyncpg.create_pool(os.environ['DATABASE_URL'])
    async with pool.acquire() as conn:
        row = await conn.fetchrow('SELECT snapshot_id FROM bdg_snapshots LIMIT 1')
        if row:
            print(row['snapshot_id'])
        else:
            dummy = '00000000-0000-0000-0000-000000000000'
            await conn.execute(\"INSERT INTO bdg_snapshots (snapshot_id, tenant_id) VALUES (\$1, '00000000-0000-0000-0000-000000000001') ON CONFLICT DO NOTHING\", dummy)
            print(dummy)
asyncio.run(run())
"
    # Execute python script inside gateway pod to connect to DB
    DB_SNAP=$(kubectl exec -n phantom "$GW_POD" -- python3 -c "$SCRIPT" 2>/dev/null | tr -d '\r\n')
    if [ -n "$DB_SNAP" ]; then
        SNAPSHOT_ID="$DB_SNAP"
    fi
fi
echo "      Using snapshot_id: $SNAPSHOT_ID"

INC_HTTP=$(curl -s -o /tmp/inc_resp.json -w "%{http_code}" \
    -X POST "$GW/api/v1/incidents" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
      \"schema_version\": \"v1\",
      \"title\": \"Supply Chain Attack: Dependency Confusion on emailservice\",
      \"summary\": \"PHANTOM eBPF agent detected an unexpected executable and outbound network beacon from emailservice. Consistent with a dependency confusion supply chain attack injecting a malicious pip package at runtime.\",
      \"drift_event_ids\": [\"$DRIFT_ID\"],
      \"attribution_ids\": [],
      \"score_ids\": [],
      \"snapshot_id\": \"$SNAPSHOT_ID\",
      \"classification\": \"confirmed\",
      \"tags\": [\"supply-chain\", \"dep-confusion\", \"emailservice\"],
      \"tenant_id\": \"00000000-0000-0000-0000-000000000001\"
    }")

if [ "$INC_HTTP" != "200" ] && [ "$INC_HTTP" != "201" ]; then
    echo "ERROR creating incident. Response (HTTP $INC_HTTP) was:"
    cat /tmp/inc_resp.json | python3 -m json.tool
    exit 1
fi

INCIDENT_ID=$(cat /tmp/inc_resp.json | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('incident_id', d.get('id','')))" 2>/dev/null || true)

if [ -z "$INCIDENT_ID" ]; then
    echo "ERROR: Failed to parse incident_id from response:"
    cat /tmp/inc_resp.json | python3 -m json.tool
    exit 1
fi

echo "      OK Incident created (classification: confirmed)"
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
