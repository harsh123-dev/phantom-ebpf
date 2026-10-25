"""
research/evaluation/attacks/safety.py

Safety preflight gates and validation rules for PHANTOM evaluation scenarios.

Design contract:
- Prevents accidental execution against production or non-evaluation environments.
- Positively identifies and approves disposable lab cluster contexts (defense-in-depth).
- Enforces strict allowlists for Kubernetes namespaces, target services, and sink endpoints.
- In live mode (dry_run=False), accepts only the configured cluster-internal sink
  (phantom-sink.phantom-eval.svc.cluster.local) and scenario-specific ports.
  Loopback/localhost destinations are restricted to non-executing unit tests.
- Requires explicit confirmation (allow_live_execution=True) before any live action.
"""

from __future__ import annotations

import logging
import re
from typing import Final

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowlist and Policy Constants
# ---------------------------------------------------------------------------

ALLOWLISTED_NAMESPACES: Final[frozenset[str]] = frozenset({"phantom-eval"})

ALLOWLISTED_SERVICES: Final[frozenset[str]] = frozenset({
    "recommendationservice",
    "emailservice",
    "cartservice",
})

# Sinks accepted in live cluster execution
LIVE_ALLOWLISTED_SINK_HOSTS: Final[frozenset[str]] = frozenset({
    "phantom-sink.phantom-eval.svc.cluster.local",
    "phantom-sink",
})

# Sinks accepted in offline/dry-run mode (includes loopback for local mocks/tests)
DRY_RUN_ALLOWLISTED_SINK_HOSTS: Final[frozenset[str]] = frozenset({
    "phantom-sink.phantom-eval.svc.cluster.local",
    "phantom-sink",
    "127.0.0.1",
    "localhost",
})

# Backward compatibility alias
ALLOWLISTED_SINK_HOSTS: Final[frozenset[str]] = DRY_RUN_ALLOWLISTED_SINK_HOSTS

ALLOWLISTED_SINK_PORTS: Final[frozenset[int]] = frozenset({8443, 4445, 4446, 8080})

# Expected scenario-specific sink ports
SCENARIO_SINK_PORTS: Final[dict[str, int]] = {
    "xzutils-001": 8443,
    "dep-confusion-001": 4445,
    "solarwinds-001": 4446,
    "proc-spawn-001": 8080,
    "net-egress-001": 8080,
    "file-tamper-001": 8080,
}

# Blocklist for any context containing production keywords
DISALLOWED_CONTEXT_KEYWORDS: Final[tuple[str, ...]] = (
    "prod",
    "production",
    "live",
    "mainnet",
    "stage",
    "staging",
)

# Positively identified approved disposable lab contexts (stale/cloud contexts removed)
APPROVED_DISPOSABLE_CONTEXTS: Final[frozenset[str]] = frozenset({
    "minikube",
    "kind-phantom-eval",
    "kind-kind",
    "docker-desktop",
    "phantom-eval-cluster",
    "phantom-lab",
    "disposable-lab",
})

APPROVED_CONTEXT_PATTERNS: Final[tuple[str, ...]] = (
    r"^minikube$",
    r"^kind-.*$",
    r"^docker-desktop$",
    r"^.*phantom.*lab.*$",
    r"^.*phantom.*eval.*$",
    r"^.*disposable.*$",
)

# Untrusted or cloud provider domains that must not be used as disposable lab endpoints
DISALLOWED_ENDPOINT_DOMAINS: Final[tuple[str, ...]] = (
    "eks.amazonaws.com",
    "azmk8s.io",
    "container.googleapis.com",
)

# Approved disposable lab cluster endpoint patterns
APPROVED_CLUSTER_ENDPOINT_PATTERNS: Final[tuple[str, ...]] = (
    r"^https?://(127\.0\.0\.1|localhost)(:\d+)?/?.*$",
    r"^https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?/?.*$",
    r"^https?://192\.168\.\d{1,3}\.\d{1,3}(:\d+)?/?.*$",
    r"^https?://172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}(:\d+)?/?.*$",
    r"^https?://.*\.local(:\d+)?/?.*$",
    r"^https?://.*\.lab(:\d+)?/?.*$",
    r"^https?://.*\.internal(:\d+)?/?.*$",
)


class SafetyCheckError(RuntimeError):
    """Raised when a safety preflight check fails."""


class SafetyPreflight:
    """Preflight validator enforcing safety constraints before scenario execution."""

    @staticmethod
    def check_namespace(namespace: str) -> None:
        """Verify the namespace is explicitly allowlisted for evaluation.

        Args:
            namespace: Kubernetes namespace name.

        Raises:
            SafetyCheckError: If namespace is not in ALLOWLISTED_NAMESPACES.
        """
        if namespace not in ALLOWLISTED_NAMESPACES:
            raise SafetyCheckError(
                f"Safety violation: namespace '{namespace}' is not allowlisted for evaluation. "
                f"Allowed namespaces: {sorted(ALLOWLISTED_NAMESPACES)}"
            )

    @staticmethod
    def check_service(service: str) -> None:
        """Verify the target service is in the approved evaluation workload list.

        Args:
            service: Target deployment/service name.

        Raises:
            SafetyCheckError: If service is not in ALLOWLISTED_SERVICES.
        """
        if service not in ALLOWLISTED_SERVICES:
            raise SafetyCheckError(
                f"Safety violation: service '{service}' is not allowlisted for evaluation. "
                f"Allowed services: {sorted(ALLOWLISTED_SERVICES)}"
            )

    @classmethod
    def check_control_endpoint(
        cls,
        endpoint: str,
        dry_run: bool = True,
        scenario_id: str | None = None,
    ) -> None:
        """Verify that the control/beacon endpoint is cluster-internal and allowlisted.

        In live mode (dry_run=False), only cluster-internal sinks are allowed,
        localhost/loopback is strictly forbidden, and the port must match the scenario's
        specified port.

        Args:
            endpoint: host:port or URL string.
            dry_run: Whether running in dry-run mode.
            scenario_id: Optional scenario ID to enforce scenario-specific port matching.

        Raises:
            SafetyCheckError: If endpoint host or port is not allowlisted.
        """
        if not endpoint:
            return  # Benign scenarios have empty control_endpoint

        cleaned = endpoint.replace("http://", "").replace("https://", "").split("/")[0]
        if ":" not in cleaned:
            raise SafetyCheckError(
                f"Safety violation: control endpoint '{endpoint}' missing port specification."
            )

        host, port_str = cleaned.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            raise SafetyCheckError(
                f"Safety violation: invalid port '{port_str}' in control endpoint '{endpoint}'."
            )

        if dry_run:
            if host not in DRY_RUN_ALLOWLISTED_SINK_HOSTS:
                raise SafetyCheckError(
                    f"Safety violation: control endpoint host '{host}' is not allowlisted. "
                    f"Allowed dry-run hosts: {sorted(DRY_RUN_ALLOWLISTED_SINK_HOSTS)}"
                )
            if port not in ALLOWLISTED_SINK_PORTS:
                raise SafetyCheckError(
                    f"Safety violation: control endpoint port '{port}' is not allowlisted. "
                    f"Allowed ports: {sorted(ALLOWLISTED_SINK_PORTS)}"
                )
        else:
            # Live execution mode constraints:
            if host in {"127.0.0.1", "localhost"}:
                raise SafetyCheckError(
                    f"Safety violation: Loopback sink '{host}' is disallowed in live cluster mode. "
                    f"Must use the configured cluster-internal sink: {sorted(LIVE_ALLOWLISTED_SINK_HOSTS)}"
                )
            if host not in LIVE_ALLOWLISTED_SINK_HOSTS:
                raise SafetyCheckError(
                    f"Safety violation: live control endpoint host '{host}' is not an approved cluster-internal sink. "
                    f"Allowed live sink hosts: {sorted(LIVE_ALLOWLISTED_SINK_HOSTS)}"
                )
            if port not in ALLOWLISTED_SINK_PORTS:
                raise SafetyCheckError(
                    f"Safety violation: control endpoint port '{port}' is not allowlisted. "
                    f"Allowed ports: {sorted(ALLOWLISTED_SINK_PORTS)}"
                )
            # Enforce scenario-specific port matching in live mode
            if scenario_id and scenario_id in SCENARIO_SINK_PORTS:
                expected_port = SCENARIO_SINK_PORTS[scenario_id]
                if port != expected_port:
                    raise SafetyCheckError(
                        f"Safety violation: Port {port} does not match the designated scenario sink port "
                        f"{expected_port} for scenario '{scenario_id}'."
                    )

    @classmethod
    def check_context(
        cls,
        context: str | None,
        dry_run: bool = True,
        approved_contexts: frozenset[str] | set[str] | None = None,
    ) -> None:
        """Verify kubectl context is a positively identified disposable lab cluster.

        Does not rely solely on substring blacklisting; in live mode, strictly requires
        positive identification against approved disposable cluster patterns or lists.

        Args:
            context: Kubernetes context name.
            dry_run: Whether running in dry-run mode.
            approved_contexts: Optional additional set of approved lab contexts.

        Raises:
            SafetyCheckError: If context name indicates a production cluster or is not an approved lab context.
        """
        if not context:
            if not dry_run:
                raise SafetyCheckError(
                    "Safety violation: In live execution mode, an explicit kubectl context "
                    "must be provided and positively verified against approved disposable lab contexts."
                )
            return

        ctx_lower = context.lower()

        # 1. Defense-in-depth keyword blocklist
        for kw in DISALLOWED_CONTEXT_KEYWORDS:
            if kw in ctx_lower:
                raise SafetyCheckError(
                    f"Safety violation: kubectl context '{context}' contains forbidden keyword '{kw}'. "
                    f"Refusing execution on potentially production or non-lab cluster."
                )

        # 2. Positive identification requirement in live execution mode
        if not dry_run:
            effective_allowlist = set(APPROVED_DISPOSABLE_CONTEXTS)
            if approved_contexts:
                effective_allowlist.update(approved_contexts)

            if context in effective_allowlist or ctx_lower in effective_allowlist:
                return

            # Check regex patterns for disposable lab clusters
            matches_pattern = any(
                re.match(pattern, context, re.IGNORECASE) for pattern in APPROVED_CONTEXT_PATTERNS
            )
            if not matches_pattern:
                raise SafetyCheckError(
                    f"Safety violation: kubectl context '{context}' is not a positively approved "
                    f"disposable lab cluster context. Allowed contexts: {sorted(effective_allowlist)}"
                )

    @staticmethod
    def check_execution_permission(dry_run: bool, allow_live_execution: bool) -> None:
        """Verify live execution is explicitly permitted when dry_run is False.

        Args:
            dry_run: Whether dry-run mode is active.
            allow_live_execution: Explicit opt-in flag.

        Raises:
            SafetyCheckError: If dry_run is False but allow_live_execution is False.
        """
        if not dry_run and not allow_live_execution:
            raise SafetyCheckError(
                "Safety violation: Live execution requested (dry_run=False) but "
                "allow_live_execution is False. Explicit confirmation is required to run live attacks."
            )

    @classmethod
    def check_cluster_endpoint(
        cls,
        server_url: str,
        approved_endpoints: frozenset[str] | set[str] | None = None,
    ) -> None:
        """Verify that the cluster server endpoint is a valid disposable lab endpoint.

        Rejects cloud provider domains (e.g. AWS EKS, Azure AKS, GCP GKE) unless
        explicitly allowlisted.

        Args:
            server_url: The API server URL (e.g., https://127.0.0.1:6443).
            approved_endpoints: Optional additional approved endpoints.

        Raises:
            SafetyCheckError: If endpoint is unapproved, empty, or points to cloud provider.
        """
        if not server_url:
            raise SafetyCheckError("Safety violation: Cluster server endpoint URL is empty or missing.")

        url_lower = server_url.lower()

        # 1. Block known cloud domains
        for domain in DISALLOWED_ENDPOINT_DOMAINS:
            if domain in url_lower:
                raise SafetyCheckError(
                    f"Safety violation: Cluster server endpoint '{server_url}' contains cloud provider domain '{domain}'. "
                    "Stale or production cloud endpoints are strictly blocked from evaluation execution."
                )

        # 2. Check explicitly approved endpoints
        if approved_endpoints and (server_url in approved_endpoints or url_lower in approved_endpoints):
            return

        # 3. Check approved disposable lab patterns
        matches_pattern = any(
            re.match(p, server_url, re.IGNORECASE) for p in APPROVED_CLUSTER_ENDPOINT_PATTERNS
        )
        if not matches_pattern:
            raise SafetyCheckError(
                f"Safety violation: Cluster server endpoint '{server_url}' is not an approved disposable lab endpoint "
                "(must be localhost, private lab IP 10.*, 192.168.*, 172.16-31.*, or .lab/.local domain)."
            )

    @classmethod
    def verify_live_cluster_readiness(
        cls,
        context: str | None,
        namespace: str = "phantom-eval",
        approved_endpoints: frozenset[str] | set[str] | None = None,
        kubectl_cmd: str = "kubectl",
        timeout: int = 10,
    ) -> dict[str, Any]:
        """Verify the live cluster endpoint, authoritative identity, node OS/kernel,
        namespace, and internal test sink configuration before any live execution.

        Fails closed if any prerequisite is unverified or cannot be determined.

        Args:
            context: kubectl context name.
            namespace: Target Kubernetes namespace.
            approved_endpoints: Optional set of allowed cluster endpoints.
            kubectl_cmd: Path to kubectl binary.
            timeout: Timeout in seconds for kubectl probe calls.

        Returns:
            Dict summarizing verified live cluster readiness.

        Raises:
            SafetyCheckError: If any verification check fails.
        """
        import json
        import shutil
        import subprocess

        if not context:
            raise SafetyCheckError(
                "Safety violation: In live execution mode, an explicit kubectl context must be provided."
            )

        if not shutil.which(kubectl_cmd):
            raise SafetyCheckError(
                f"Safety violation: kubectl command '{kubectl_cmd}' not found on system PATH."
            )

        # 1. Retrieve configured cluster endpoint for this context from kubeconfig
        cmd_cfg = [kubectl_cmd, "config", "view", "--minify", "--context", context, "-o", "json"]
        try:
            res_cfg = subprocess.run(
                cmd_cfg, capture_output=True, text=True, timeout=timeout, check=False
            )
        except Exception as exc:
            raise SafetyCheckError(
                f"Safety violation: Failed to inspect kubeconfig for context '{context}': {exc}"
            )

        if res_cfg.returncode != 0:
            raise SafetyCheckError(
                f"Safety violation: Failed to read cluster config for context '{context}': {res_cfg.stderr.strip()}"
            )

        try:
            cfg_data = json.loads(res_cfg.stdout)
            clusters = cfg_data.get("clusters", [])
            if not clusters:
                raise ValueError("No cluster definition found in minified kubeconfig")
            server_url = clusters[0].get("cluster", {}).get("server", "")
        except Exception as exc:
            raise SafetyCheckError(
                f"Safety violation: Could not parse cluster server URL for context '{context}': {exc}"
            )

        # Verify the cluster endpoint is an approved lab endpoint
        cls.check_cluster_endpoint(server_url, approved_endpoints)

        # 2. Test live cluster API connectivity
        cmd_conn = [kubectl_cmd, "--context", context, "get", "--raw=/livez"]
        try:
            res_conn = subprocess.run(
                cmd_conn, capture_output=True, text=True, timeout=timeout, check=False
            )
        except Exception as exc:
            raise SafetyCheckError(
                f"Safety violation: Cluster API connectivity probe failed for '{context}' ({server_url}): {exc}"
            )

        if res_conn.returncode != 0 or res_conn.stdout.strip().lower() != "ok":
            # Fallback to get nodes or version if livez is restricted by RBAC
            cmd_ver = [kubectl_cmd, "--context", context, "version", "-o", "json"]
            try:
                res_ver = subprocess.run(
                    cmd_ver, capture_output=True, text=True, timeout=timeout, check=False
                )
            except Exception as exc:
                raise SafetyCheckError(
                    f"Safety violation: Cluster API probe failed for '{context}' ({server_url}): {exc}"
                )
            if res_ver.returncode != 0:
                err_msg = res_conn.stderr.strip() or res_ver.stderr.strip()
                raise SafetyCheckError(
                    f"Safety violation: Target cluster is unreachable or unresponsive for context '{context}' "
                    f"at endpoint '{server_url}': {err_msg}"
                )

        # 3. Verify Linux kernel and eBPF prerequisites on nodes
        cmd_nodes = [kubectl_cmd, "--context", context, "get", "nodes", "-o", "json"]
        try:
            res_nodes = subprocess.run(
                cmd_nodes, capture_output=True, text=True, timeout=timeout, check=False
            )
        except Exception as exc:
            raise SafetyCheckError(
                f"Safety violation: Failed to query nodes for context '{context}': {exc}"
            )

        if res_nodes.returncode != 0:
            raise SafetyCheckError(
                f"Safety violation: Failed to query nodes for context '{context}': {res_nodes.stderr.strip()}"
            )

        try:
            nodes_data = json.loads(res_nodes.stdout)
            items = nodes_data.get("items", [])
            if not items:
                raise ValueError("Zero nodes found in cluster")

            for node in items:
                node_name = node.get("metadata", {}).get("name", "unknown")
                node_info = node.get("status", {}).get("nodeInfo", {})
                os_name = node_info.get("operatingSystem", "").lower()
                kernel_ver = node_info.get("kernelVersion", "")

                if os_name != "linux":
                    raise SafetyCheckError(
                        f"Safety violation: Node '{node_name}' OS is '{os_name}'. "
                        "Live eBPF evaluation requires Linux worker nodes."
                    )

                # Parse kernel version major.minor
                km = re.match(r"^(\d+)\.(\d+)", kernel_ver)
                if km:
                    major, minor = int(km.group(1)), int(km.group(2))
                    if (major < 5) or (major == 5 and minor < 15):
                        raise SafetyCheckError(
                            f"Safety violation: Node '{node_name}' kernel is '{kernel_ver}'. "
                            "Linux kernel >= 5.15 with BTF is required for PHANTOM eBPF probes."
                        )
                else:
                    raise SafetyCheckError(
                        f"Safety violation: Node '{node_name}' reports unrecognized kernel version '{kernel_ver}'."
                    )
        except SafetyCheckError:
            raise
        except Exception as exc:
            raise SafetyCheckError(f"Safety violation: Error evaluating node kernel/eBPF prerequisites: {exc}")

        # 4. Verify namespace exists and is Active
        cmd_ns = [kubectl_cmd, "--context", context, "get", "namespace", namespace, "-o", "json"]
        try:
            res_ns = subprocess.run(
                cmd_ns, capture_output=True, text=True, timeout=timeout, check=False
            )
        except Exception as exc:
            raise SafetyCheckError(
                f"Safety violation: Failed to query namespace '{namespace}': {exc}"
            )

        if res_ns.returncode != 0:
            raise SafetyCheckError(
                f"Safety violation: Evaluation namespace '{namespace}' does not exist or is not accessible "
                f"in context '{context}': {res_ns.stderr.strip()}"
            )

        try:
            ns_data = json.loads(res_ns.stdout)
            phase = ns_data.get("status", {}).get("phase", "")
            if phase.lower() != "active":
                raise SafetyCheckError(
                    f"Safety violation: Namespace '{namespace}' is in phase '{phase}', expected 'Active'."
                )
        except SafetyCheckError:
            raise
        except Exception as exc:
            raise SafetyCheckError(f"Safety violation: Error verifying namespace '{namespace}': {exc}")

        # 5. Verify internal sink phantom-sink is deployed with ClusterIP and designated ports
        cmd_svc = [
            kubectl_cmd, "--context", context, "get", "service", "phantom-sink", "-n", namespace, "-o", "json"
        ]
        try:
            res_svc = subprocess.run(
                cmd_svc, capture_output=True, text=True, timeout=timeout, check=False
            )
        except Exception as exc:
            raise SafetyCheckError(
                f"Safety violation: Failed to query service 'phantom-sink' in namespace '{namespace}': {exc}"
            )

        if res_svc.returncode != 0:
            raise SafetyCheckError(
                f"Safety violation: Internal test sink Service 'phantom-sink' not found in namespace '{namespace}'. "
                "Preflight requires mock sink deployment before scenario execution."
            )

        try:
            svc_data = json.loads(res_svc.stdout)
            svc_type = svc_data.get("spec", {}).get("type", "")
            if svc_type != "ClusterIP":
                raise SafetyCheckError(
                    f"Safety violation: Service 'phantom-sink' type is '{svc_type}', must be 'ClusterIP'."
                )

            ports = {p.get("port") for p in svc_data.get("spec", {}).get("ports", []) if "port" in p}
            required_ports = {8443, 4445, 4446, 8080}
            missing_ports = required_ports - ports
            if missing_ports:
                raise SafetyCheckError(
                    f"Safety violation: Service 'phantom-sink' is missing required scenario ports: {sorted(missing_ports)}."
                )
        except SafetyCheckError:
            raise
        except Exception as exc:
            raise SafetyCheckError(f"Safety violation: Error parsing 'phantom-sink' Service spec: {exc}")

        return {
            "context": context,
            "server_url": server_url,
            "namespace": namespace,
            "node_count": len(items),
            "sink_service": "phantom-sink",
            "status": "READY",
        }

    @classmethod
    def validate(
        cls,
        namespace: str,
        service: str | None = None,
        endpoint: str | None = None,
        context: str | None = None,
        dry_run: bool = True,
        allow_live_execution: bool = False,
        scenario_id: str | None = None,
        approved_contexts: frozenset[str] | set[str] | None = None,
        approved_endpoints: frozenset[str] | set[str] | None = None,
        verify_cluster: bool = True,
    ) -> None:
        """Run all safety preflight checks.

        In dry-run mode, validates configuration without making cluster or network calls.
        In live execution mode, performs deep preflight verification against cluster endpoint,
        authoritative identity, node OS/kernel, namespace, and internal test sink.

        Args:
            namespace: Target Kubernetes namespace.
            service: Target workload name (optional).
            endpoint: Control/beacon endpoint (optional).
            context: kubectl context name (optional).
            dry_run: Whether dry-run mode is active.
            allow_live_execution: Explicit opt-in flag.
            scenario_id: Scenario ID for port verification (optional).
            approved_contexts: Additional approved context names (optional).
            approved_endpoints: Additional approved cluster endpoint URLs (optional).
            verify_cluster: Whether to probe live cluster in live execution mode.

        Raises:
            SafetyCheckError: If any safety condition is violated.
        """
        cls.check_execution_permission(dry_run, allow_live_execution)
        cls.check_namespace(namespace)
        if service is not None:
            cls.check_service(service)
        if endpoint is not None:
            cls.check_control_endpoint(endpoint, dry_run=dry_run, scenario_id=scenario_id)
        cls.check_context(context, dry_run=dry_run, approved_contexts=approved_contexts)

        # In live execution mode, verify authoritative cluster identity & prerequisites
        if not dry_run and verify_cluster:
            cls.verify_live_cluster_readiness(
                context=context,
                namespace=namespace,
                approved_endpoints=approved_endpoints,
            )
