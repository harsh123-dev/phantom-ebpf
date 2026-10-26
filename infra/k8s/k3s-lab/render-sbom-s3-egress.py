#!/usr/bin/env python3
"""Render a least-egress policy for SBOM service and regional S3 addresses.

Requires an authenticated AWS CLI and Python stdlib only. The generated
NetworkPolicy allows DNS, the in-cluster Postgres service, and HTTPS only to
the AWS-managed regional S3 prefix list. It does not allow general public
egress or metadata-service access.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import sys


def aws_json(*args: str) -> dict:
    result = subprocess.run(
        ["aws", *args, "--output", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def main() -> int:
    region = os.environ.get("AWS_REGION", "ap-south-1")
    broker_node = os.environ.get("PHANTOM_CREDENTIAL_BROKER_NODE_IP", "")
    try:
        broker_ip = ipaddress.ip_address(broker_node)
    except ValueError as exc:
        raise RuntimeError("PHANTOM_CREDENTIAL_BROKER_NODE_IP must be the lab node's private IPv4 address") from exc
    rfc1918 = tuple(ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    if broker_ip.version != 4 or not any(broker_ip in network for network in rfc1918):
        raise RuntimeError("credential broker must use a private IPv4 node address")

    service_name = f"com.amazonaws.{region}.s3"
    prefixes = aws_json(
        "ec2", "describe-prefix-lists", "--region", region,
        "--filters", "Name=prefix-list-name,Values=" + service_name,
    ).get("PrefixLists", [])
    matching = [item for item in prefixes if item.get("PrefixListName") == service_name]
    if len(matching) != 1 or not matching[0].get("PrefixListId"):
        raise RuntimeError(f"expected one managed prefix list for {service_name}")
    prefix_id = matching[0]["PrefixListId"]
    entries = aws_json(
        "ec2", "get-managed-prefix-list-entries", "--region", region,
        "--prefix-list-id", prefix_id,
    ).get("Entries", [])
    cidrs = sorted({
        str(ipaddress.ip_network(entry["Cidr"], strict=True))
        for entry in entries
        if ":" not in entry.get("Cidr", "")
    })
    if not cidrs:
        raise RuntimeError("regional S3 prefix list contains no IPv4 ranges")

    # Cosign verification needs current TUF trust metadata and log services.
    # NetworkPolicy has no portable FQDN selector, so render current A-record
    # /32s and refresh this policy when DNS changes. TLS hostname verification
    # and Cosign signer/issuer verification remain mandatory.
    sigstore_ips: set[ipaddress.IPv4Address] = set()
    for hostname in (
        "tuf-repo-cdn.sigstore.dev",
        "rekor.sigstore.dev",
        "fulcio.sigstore.dev",
    ):
        try:
            records = socket.getaddrinfo(hostname, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise RuntimeError(f"unable to resolve required Sigstore endpoint {hostname}") from exc
        sigstore_ips.update(ipaddress.IPv4Address(record[4][0]) for record in records)
    if not sigstore_ips:
        raise RuntimeError("Sigstore endpoints resolved to no IPv4 addresses")
    if any(not address.is_global for address in sigstore_ips):
        raise RuntimeError("Sigstore DNS returned a non-global IPv4 address")

    print("apiVersion: networking.k8s.io/v1")
    print("kind: NetworkPolicy")
    print("metadata:")
    print("  name: phantom-sbom-restricted-egress")
    print("  namespace: phantom")
    print("spec:")
    print("  podSelector:")
    print("    matchLabels:")
    print("      app: phantom-sbom-service")
    print("  policyTypes: [Egress]")
    print("  egress:")
    print("    - to:")
    print("        - namespaceSelector:")
    print("            matchLabels:")
    print("              kubernetes.io/metadata.name: kube-system")
    print("      ports:")
    print("        - {protocol: UDP, port: 53}")
    print("        - {protocol: TCP, port: 53}")
    print("    - to:")
    print("        - podSelector:")
    print("            matchLabels:")
    print("              app: phantom-postgres")
    print("      ports:")
    print("        - {protocol: TCP, port: 5432}")
    print("    - to:")
    print("        - ipBlock:")
    print(f"            cidr: {broker_ip}/32")
    print("      ports:")
    print("        - {protocol: TCP, port: 18443}")
    print("    - to:")
    for cidr in sorted(cidrs):
        print("        - ipBlock:")
        print(f"            cidr: {cidr}")
    for ip in sorted(sigstore_ips, key=int):
        print("        - ipBlock:")
        print(f"            cidr: {ip}/32")
    print("      ports:")
    print("        - {protocol: TCP, port: 443}")
    print(
        f"# S3 prefix list: {prefix_id} ({service_name}); IPv4 CIDRs: {len(cidrs)}; "
        f"Sigstore resolved IPv4 addresses: {len(sigstore_ips)}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"cannot render restricted S3 egress policy: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
