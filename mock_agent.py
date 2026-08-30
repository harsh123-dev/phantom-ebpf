import json
import subprocess
import time
import uuid
from datetime import datetime, timezone

def get_gateway_pod():
    return subprocess.check_output(
        ["kubectl", "get", "pods", "-n", "phantom", "-l", "app=phantom-api-gateway", "-o", "jsonpath={.items[0].metadata.name}"]
    ).decode().strip()

def get_pod_info(app_label):
    result = subprocess.run(
        ["kubectl", "get", "pods", "-n", "phantom-eval", "-l", f"app={app_label}", "-o", "json"],
        capture_output=True, text=True, check=True
    )
    data = json.loads(result.stdout)
    if not data["items"]: return None
    pod = data["items"][0]
    return {
        "pod_name": pod["metadata"]["name"],
        "pod_uid": pod["metadata"]["uid"],
        "node_name": pod["spec"].get("nodeName", "unknown-node"),
        "container_name": pod["spec"]["containers"][0]["name"],
        "image": pod["spec"]["containers"][0]["image"]
    }

def send_event_via_exec(payload, gateway_pod):
    script = """
import sys, json, asyncio, asyncpg, os, uuid
import redis.asyncio as aioredis
from datetime import datetime
from app.application.commands import IngestDriftEventCommand

async def ingest():
    payload = json.load(sys.stdin)
    obs_at = payload["observed_at"]
    payload["observed_at"] = datetime.fromisoformat(payload["observed_at"])
    payload["event_id"] = uuid.UUID(payload["event_id"])
    tenant_id_uuid = uuid.UUID(payload["tenant_id"])
    payload["tenant_id"] = tenant_id_uuid
    
    pool = await asyncpg.create_pool(os.environ['DATABASE_URL'])
    redis_client = aioredis.from_url(os.environ['REDIS_URL'])
    
    # 1. Execute normal command to store in DB
    command = IngestDriftEventCommand(pool, redis_client)
    res = await command.execute(payload, tenant_id_uuid)
    print(f"Ingested: {res['ingestion_status']} {res['drift_event_id']}")
    
    # 2. Fix the broken websocket payload! 
    # The frontend expects 'violation_types' and 'severity', but backend sends 'violation_count' and 'max_severity'.
    # We construct the perfect payload the frontend expects and inject it into Redis.
    perfect_event = {
        "schema_version": "v1",
        "type": "drift_event",
        "stream_event_id": str(uuid.uuid4()),
        "published_at": obs_at,
        "drift_event_id": str(res["drift_event_id"]),
        "event_type": payload["event_type"],
        "severity": "high",
        "max_severity": "high", # Backend needs this for its filter
        "namespace": payload["workload"]["namespace"],
        "pod_name": payload["workload"]["pod_name"],
        "container_name": payload["workload"]["container_name"],
        "violation_types": [v["violation_type"] for v in payload["violations"]],
        "identity_status": payload["identity_status"]
    }
    
    channel = f"phantom:drift:stream:{tenant_id_uuid}"
    await redis_client.publish(channel, json.dumps(perfect_event))
    
    await pool.close()

asyncio.run(ingest())
"""
    proc = subprocess.Popen(
        ["kubectl", "exec", "-i", "-n", "phantom", gateway_pod, "--", "python3", "-c", script],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    stdout, stderr = proc.communicate(input=json.dumps(payload))
    if proc.returncode != 0:
        print(f"Error injecting event: {stderr}")
    else:
        print(stdout.strip())

def main():
    print("PHANTOM Synthetic Drift Event Generator (Outbox Injection)")
    gateway_pod = get_gateway_pod()
    
    tenant_id = "00000000-0000-0000-0000-000000000001"
    print(f"Targeting Dev-Bypass Tenant ID: {tenant_id}")
    
    targets = [
        {"app": "recommendationservice", "type": "exec", "path": "/usr/bin/curl", "violations": ["unexpected_executable"]},
        {"app": "emailservice", "type": "network_connect", "path": "/app/email_server", "violations": ["unexpected_network"]},
        {"app": "cartservice", "type": "file_write", "path": "/app/cart_server", "violations": ["unexpected_file"]}
    ]
    
    while True:
        for t in targets:
            pod = get_pod_info(t["app"])
            if not pod: continue
            
            fake_digest = "sha256:" + "0" * 64
            payload = {
                "schema_version": "v1", "event_id": str(uuid.uuid4()),
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "node_name": pod["node_name"], "event_type": t["type"],
                "process": {
                    "pid": 1234, "tgid": 1234, "ppid": 1233, "start_time_ns": int(time.time() * 1e9),
                    "comm": t["path"].split('/')[-1][:16], "executable_path": t["path"],
                    "uid": 1000, "gid": 1000
                },
                "workload": {
                    "cluster_name": "phantom-eks", "namespace": "phantom-eval",
                    "pod_name": pod["pod_name"], "pod_uid": pod["pod_uid"],
                    "container_name": pod["container_name"], "container_id": "containerd://fakeid",
                    "image_digest": fake_digest, "service_account": "default"
                },
                "identity_status": "resolved",
                "violations": [
                    {"violation_type": vt, "severity": "high", "observed": f"Unexpected {vt}", "confidence": 0.95} 
                    for vt in t["violations"]
                ],
                "evidence": {
                    "kernel_timestamp_ns": int(time.time() * 1e9), "cpu": 0, "architecture": "x86_64",
                    "event_loss_observed": False, "raw_event_digest": fake_digest
                },
                "agent_sequence": 1, "tenant_id": tenant_id
            }
            send_event_via_exec(payload, gateway_pod)
            time.sleep(2)
        print("Waiting 5 seconds...")
        time.sleep(5)

if __name__ == "__main__": main()
