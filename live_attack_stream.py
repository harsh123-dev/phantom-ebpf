#!/usr/bin/env python3
"""
live_attack_stream.py — PHANTOM Live Attack Stream Simulator
Posts realistic dep-confusion + xzutils drift events directly to the API
every 5 seconds so the frontend Live Drift Feed updates continuously.

Usage:
    python3 live_attack_stream.py
    python3 live_attack_stream.py --url http://localhost:8080 --count 20
"""
import argparse
import time
import uuid
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone

ZERO64 = "0" * 64
FAKE_DIGEST = f"sha256:{ZERO64}"
TENANT_ID = "00000000-0000-0000-0000-000000000001"
TOKEN = "dev-bypass-token-for-local-testing"

# Realistic attack scenarios
SCENARIOS = [
    {
        "label": "dep-confusion: pip installs phantom-internal-lib",
        "event_type": "exec",
        "pod": "emailservice-7c4c4b9c75-6879h",
        "container": "emailservice",
        "node": "ip-172-31-31-65.ap-south-1.compute.internal",
        "exec_path": "/usr/local/bin/pip3",
        "comm": "pip3",
        "violation_type": "unexpected_executable",
        "severity": "high",
    },
    {
        "label": "dep-confusion: beacon.py executes and phones home",
        "event_type": "exec",
        "pod": "emailservice-7c4c4b9c75-6879h",
        "container": "emailservice",
        "node": "ip-172-31-31-65.ap-south-1.compute.internal",
        "exec_path": "/tmp/phantom_internal_lib/beacon.py",
        "comm": "beacon.py",
        "violation_type": "unexpected_executable",
        "severity": "critical",
    },
    {
        "label": "dep-confusion: outbound TCP connection to attacker C2",
        "event_type": "network_connect",
        "pod": "emailservice-7c4c4b9c75-6879h",
        "container": "emailservice",
        "node": "ip-172-31-31-65.ap-south-1.compute.internal",
        "exec_path": "/usr/bin/python3",
        "comm": "python3",
        "violation_type": "unexpected_network",
        "severity": "critical",
    },
    {
        "label": "xzutils: backdoored liblzma.so loaded at runtime",
        "event_type": "file_open",
        "pod": "recommendationservice-5d5b9b-xkp9j",
        "container": "recommendationservice",
        "node": "ip-172-31-14-32.ap-south-1.compute.internal",
        "exec_path": "/lib/x86_64-linux-gnu/liblzma.so.5",
        "comm": "sshd",
        "violation_type": "unexpected_executable",
        "severity": "critical",
    },
    {
        "label": "xzutils: unauthorized privilege escalation attempt",
        "event_type": "privilege_transition",
        "pod": "recommendationservice-5d5b9b-xkp9j",
        "container": "recommendationservice",
        "node": "ip-172-31-14-32.ap-south-1.compute.internal",
        "exec_path": "/usr/sbin/sshd",
        "comm": "sshd",
        "violation_type": "privilege_transition",
        "severity": "critical",
    },
    {
        "label": "dep-confusion: cartservice installs malicious wheel",
        "event_type": "exec",
        "pod": "cartservice-6b9c4d-m7tpq",
        "container": "cartservice",
        "node": "ip-172-31-31-65.ap-south-1.compute.internal",
        "exec_path": "/usr/local/bin/pip3",
        "comm": "pip3",
        "violation_type": "unexpected_executable",
        "severity": "high",
    },
]


def build_payload(scenario: dict, seq: int) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    pid = 10000 + seq
    return {
        "tenant_id": TENANT_ID,
        "event_id": str(uuid.uuid4()),
        "event_type": scenario["event_type"],
        "observed_at": ts,
        "node_name": scenario["node"],
        "identity_status": "resolved",
        "agent_sequence": seq,
        "process": {
            "pid": pid,
            "tgid": pid,
            "ppid": pid - 1,
            "start_time_ns": int(time.time() * 1e9),
            "comm": scenario["comm"][:15],
            "executable_path": scenario["exec_path"],
            "uid": 0,
            "gid": 0,
        },
        "workload": {
            "cluster_name": "phantom-eks",
            "namespace": "phantom-eval",
            "pod_name": scenario["pod"],
            "pod_uid": f"00000000-0000-0000-0000-{abs(hash(scenario['pod'])) % 10**12:012d}",
            "container_name": scenario["container"],
            "container_id": f"containerd://{'a' * 64}",
            "image_digest": FAKE_DIGEST,
            "cgroup_id": 1,
            "service_account": "default",
        },
        "evidence": {
            "kernel_timestamp_ns": int(time.time() * 1e9),
            "cpu": 0,
            "architecture": "x86_64",
            "event_loss_observed": False,
            "raw_event_digest": FAKE_DIGEST,
        },
        "violations": [
            {
                "violation_type": scenario["violation_type"],
                "observed": scenario["exec_path"],
                "severity": scenario["severity"],
                "confidence": 0.99,
            }
        ],
    }


def post_event(base_url: str, payload: dict) -> bool:
    url = f"{base_url.rstrip('/')}/api/v1/drift-events"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TOKEN}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            return status in (200, 202)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"    ERROR HTTP {e.code}: {body[:200]}")
        return False
    except Exception as exc:
        print(f"    ERROR: {exc}")
        return False


def main():
    parser = argparse.ArgumentParser(description="PHANTOM Live Attack Stream Simulator")
    parser.add_argument("--url", default="http://localhost:8080", help="API base URL")
    parser.add_argument("--interval", type=float, default=5.0, help="Seconds between events")
    parser.add_argument("--count", type=int, default=0, help="Number of events (0=infinite)")
    args = parser.parse_args()

    print(f"PHANTOM Live Attack Stream posting to {args.url}")
    print(f"Interval: {args.interval}s | Count: {'infinite' if args.count == 0 else args.count}")
    print("Press Ctrl+C to stop\n")

    seq = 1
    scenario_idx = 0
    total_posted = 0

    try:
        while args.count == 0 or seq <= args.count:
            scenario = SCENARIOS[scenario_idx % len(SCENARIOS)]
            payload = build_payload(scenario, seq)

            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            print(f"[{ts}] #{seq} {scenario['severity'].upper():<8} {scenario['label']}")

            ok = post_event(args.url, payload)
            if ok:
                total_posted += 1
                print(f"         OK accepted (total: {total_posted})")

            seq += 1
            scenario_idx += 1
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\nStopped. Total events posted: {total_posted}")


if __name__ == "__main__":
    main()
