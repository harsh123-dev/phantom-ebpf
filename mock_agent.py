import base64
import json
import subprocess
import time
import uuid
import urllib.request
from datetime import datetime, timezone

def get_token():
    print("Fetching token from kubernetes...")
    result = subprocess.run(
        ["kubectl", "get", "secret", "phantom-agent-secret", "-n", "phantom", "-o", "jsonpath={.data.token}"],
        capture_output=True, text=True, check=True
    )
    return base64.b64decode(result.stdout.strip()).decode('utf-8')

def get_tenant_id(token):
    payload_b64 = token.split('.')[1]
    payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    return payload["tenant_id"]

def get_pod_info(app_label):
    result = subprocess.run(
        ["kubectl", "get", "pods", "-n", "phantom-eval", "-l", f"app={app_label}", "-o", "json"],
        capture_output=True, text=True, check=True
    )
    data = json.loads(result.stdout)
    if not data["items"]:
        return None
    pod = data["items"][0]
    return {
        "pod_name": pod["metadata"]["name"],
        "pod_uid": pod["metadata"]["uid"],
        "node_name": pod["spec"].get("nodeName", "unknown-node"),
        "container_name": pod["spec"]["containers"][0]["name"],
        "image": pod["spec"]["containers"][0]["image"]
    }

def send_event(token, tenant_id, pod_info, event_type, exec_path, violation_types):
    url = "http://localhost:8080/api/v1/drift-events"
    
    event_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    fake_digest = "sha256:" + "0" * 64
    
    payload = {
        "schema_version": "v1",
        "event_id": event_id,
        "observed_at": now,
        "node_name": pod_info["node_name"],
        "event_type": event_type,
        "process": {
            "pid": 1234,
            "tgid": 1234,
            "ppid": 1233,
            "start_time_ns": int(time.time() * 1e9),
            "comm": exec_path.split('/')[-1][:16],
            "executable_path": exec_path,
            "uid": 1000,
            "gid": 1000
        },
        "workload": {
            "cluster_name": "phantom-eks",
            "namespace": "phantom-eval",
            "pod_name": pod_info["pod_name"],
            "pod_uid": pod_info["pod_uid"],
            "container_name": pod_info["container_name"],
            "container_id": "containerd://fakeid",
            "image_digest": fake_digest,
            "service_account": "default"
        },
        "identity_status": "resolved",
        "violations": [
            {
                "violation_type": vt,
                "severity": "high",
                "observed": f"Unexpected {vt} detected",
                "confidence": 0.95
            } for vt in violation_types
        ],
        "evidence": {
            "kernel_timestamp_ns": int(time.time() * 1e9),
            "cpu": 0,
            "architecture": "x86_64",
            "event_loss_observed": False,
            "raw_event_digest": fake_digest
        },
        "agent_sequence": 1,
        "tenant_id": tenant_id
    }
    
    req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }, method="POST")
    
    try:
        with urllib.request.urlopen(req) as response:
            print(f"Sent {event_type} for {pod_info['pod_name']}: {response.status}")
    except urllib.error.HTTPError as e:
        print(f"Failed to send event: {e.code} {e.read().decode('utf-8')}")
    except Exception as e:
        print(f"Error: {e}")

def main():
    print("PHANTOM Synthetic Drift Event Generator")
    token = get_token()
    tenant_id = get_tenant_id(token)
    print(f"Targeting Tenant ID: {tenant_id}")
    
    targets = [
        {"app": "recommendationservice", "type": "exec", "path": "/usr/bin/curl", "violations": ["unexpected_executable"]},
        {"app": "emailservice", "type": "network_connect", "path": "/app/email_server", "violations": ["unexpected_network"]},
        {"app": "cartservice", "type": "file_write", "path": "/app/cart_server", "violations": ["unexpected_file"]}
    ]
    
    while True:
        for t in targets:
            pod_info = get_pod_info(t["app"])
            if pod_info:
                send_event(token, tenant_id, pod_info, t["type"], t["path"], t["violations"])
            time.sleep(2)
        print("Waiting 5 seconds before next burst...")
        time.sleep(5)

if __name__ == "__main__":
    main()
