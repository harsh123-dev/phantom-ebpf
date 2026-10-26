from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]


def _manifests(path: Path) -> list[dict]:
    return [doc for doc in yaml.safe_load_all(path.read_text()) if doc]


def test_sink_deployment_is_single_writer_private_and_persistent():
    docs = _manifests(ROOT / "research/evaluation/k8s/target-workloads.yaml")
    deployment = next(d for d in docs if d.get("kind") == "Deployment"
                      and d["metadata"]["name"] == "phantom-sink")
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    pvc = next(d for d in docs if d.get("kind") == "PersistentVolumeClaim"
               and d["metadata"]["name"] == "phantom-evidence-data")
    service = next(d for d in docs if d.get("kind") == "Service"
                   and d["metadata"]["name"] == "phantom-sink")
    assert deployment["spec"]["replicas"] == 1
    assert deployment["spec"]["strategy"]["type"] == "Recreate"
    assert any(mount["mountPath"] == "/data" and mount["name"] == "evidence-data"
               for mount in container["volumeMounts"])
    assert pvc["spec"]["accessModes"] == ["ReadWriteOnce"]
    assert container["securityContext"]["runAsNonRoot"] is True
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert service["spec"].get("type", "ClusterIP") == "ClusterIP"


def test_sink_api_is_limited_to_collector_and_gateway_labels():
    target_docs = _manifests(ROOT / "research/evaluation/k8s/target-workloads.yaml")
    policy = next(d for d in target_docs if d.get("kind") == "NetworkPolicy"
                  and d["metadata"]["name"] == "phantom-sink-private-ingress")
    api_rule = next(rule for rule in policy["spec"]["ingress"]
                    if any(port["port"] == 9191 for port in rule["ports"]))
    allowed_apps = {
        peer["podSelector"]["matchLabels"]["app"] for peer in api_rule["from"]
    }
    assert allowed_apps == {"phantom-evidence-collector", "phantom-api-gateway"}
    beacon_rule = next(rule for rule in policy["spec"]["ingress"]
                       if any(port["port"] == 8443 for port in rule["ports"]))
    assert all(port["port"] != 9191 for port in beacon_rule["ports"])


def test_collector_has_scoped_api_egress_policy():
    docs = _manifests(ROOT / "infra/k8s/k3s-lab/06-network-policies.yaml")
    policy = next(d for d in docs if d.get("kind") == "NetworkPolicy"
                  and d["metadata"]["name"] == "phantom-evidence-collector-egress")
    assert policy["spec"]["podSelector"]["matchLabels"]["app"] == "phantom-evidence-collector"
    assert policy["spec"]["egress"][0]["to"][0]["podSelector"]["matchLabels"]["app"] == "phantom-sink"
    assert policy["spec"]["egress"][0]["ports"] == [{"protocol": "TCP", "port": 9191}]
