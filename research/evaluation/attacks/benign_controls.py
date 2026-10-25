"""Bounded, harmless controls with independent Kubernetes/workload receipts."""

from __future__ import annotations

import json
import subprocess
import uuid
from typing import Any

from research.evaluation.attacks.base_attack import AttackManifest, BaseAttack


class BenignControl(BaseAttack):
    """Shared bounded kubectl wrapper for the three approved controls."""

    manifest: AttackManifest

    def __init__(self, manifest: AttackManifest, kubectl_context: str | None = None,
                 dry_run: bool = True, allow_live_execution: bool = False) -> None:
        super().__init__(kubectl_context, dry_run, allow_live_execution)
        self.manifest = manifest
        self.run_token = uuid.uuid4().hex
        self._evidence: dict[str, Any] = {}

    def _kubectl(self, *args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
        command = ["kubectl"]
        if self.kubectl_context:
            command += ["--context", self.kubectl_context]
        command.extend(args)
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)

    def evidence(self) -> dict[str, Any]:
        return dict(self._evidence)


class BenignUpdateControl(BenignControl):
    """Apply and roll out a harmless, run-tagged Deployment metadata update.

    This exercises a normal Deployment change and pod replacement. It does not
    pretend to perform a package update; the current lab images do not contain
    the declared dependency fixture or a verified local package source.
    """

    annotation = "phantom.io/benign-control-run"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._previous_annotation: str | None = None
        self._image_refs: list[str] = []

    def inject(self, target_namespace: str, pod_name: str) -> bool:
        deploy = self._kubectl("get", "deployment", self.manifest.target_service, "-n", target_namespace, "-o", "json")
        if deploy.returncode:
            return False
        data = json.loads(deploy.stdout)
        template = data["spec"]["template"]
        annotations = template.get("metadata", {}).get("annotations", {}) or {}
        self._previous_annotation = annotations.get(self.annotation)
        self._image_refs = [c.get("image", "") for c in template["spec"]["containers"]]
        patch = {"spec": {"template": {"metadata": {"annotations": {self.annotation: self.run_token}}}}}
        changed = self._kubectl("patch", "deployment", self.manifest.target_service, "-n", target_namespace,
                                "--type=merge", "-p", json.dumps(patch))
        if changed.returncode:
            return False
        rollout = self._kubectl("rollout", "status", f"deployment/{self.manifest.target_service}",
                                "-n", target_namespace, "--timeout=120s", timeout=130)
        self._evidence = {"kind": "deployment_annotation_rollout", "run_token": self.run_token,
                          "original_images": self._image_refs, "rollout_status": rollout.stdout.strip()}
        return rollout.returncode == 0

    def verify_injection(self, target_namespace: str, pod_name: str) -> bool:
        result = self._kubectl("get", "deployment", self.manifest.target_service, "-n", target_namespace, "-o", "json")
        if result.returncode:
            return False
        template = json.loads(result.stdout)["spec"]["template"]
        annotations = template.get("metadata", {}).get("annotations", {}) or {}
        images = [c.get("image", "") for c in template["spec"]["containers"]]
        self._evidence.update({"verified_annotation": annotations.get(self.annotation), "verified_images": images})
        return annotations.get(self.annotation) == self.run_token and images == self._image_refs

    def recover(self, target_namespace: str, pod_name: str) -> bool:
        value: str | None = self._previous_annotation
        patch = {"spec": {"template": {"metadata": {"annotations": {self.annotation: value}}}}}
        result = self._kubectl("patch", "deployment", self.manifest.target_service, "-n", target_namespace,
                              "--type=merge", "-p", json.dumps(patch))
        if result.returncode:
            return False
        rollout = self._kubectl("rollout", "status", f"deployment/{self.manifest.target_service}",
                                "-n", target_namespace, "--timeout=120s", timeout=130)
        return rollout.returncode == 0


class BenignLoadControl(BenignControl):
    """Issue a finite burst of 200 HTTP GETs to the paired in-cluster service."""

    request_count = 200

    def inject(self, target_namespace: str, pod_name: str) -> bool:
        script = (
            "import concurrent.futures,json,sys,urllib.request; "
            "host,ns,token,count=sys.argv[1:5]; count=int(count); "
            "url=f'http://{host}.{ns}.svc.cluster.local:8080/?phantom_control={token}'; "
            "defreq=lambda _: urllib.request.urlopen(url,timeout=5).status; "
            "pool=concurrent.futures.ThreadPoolExecutor(max_workers=5); "
            "statuses=list(pool.map(defreq,range(count))); "
            "print(json.dumps({'requests':len(statuses),'successes':sum(s==200 for s in statuses),'token':token})); "
            "sys.exit(0 if len(statuses)==count and all(s==200 for s in statuses) else 2)"
        )
        result = self._kubectl("exec", "-n", target_namespace, pod_name, "--", "python", "-c", script,
                               self.manifest.target_service, target_namespace, self.run_token,
                               str(self.request_count), timeout=60)
        if result.stdout:
            try:
                self._evidence = json.loads(result.stdout.strip().splitlines()[-1])
            except (ValueError, IndexError):
                self._evidence = {"command_output": result.stdout[-1000:]}
        return result.returncode == 0

    def verify_injection(self, target_namespace: str, pod_name: str) -> bool:
        logs = self._kubectl("logs", "-n", target_namespace, pod_name, "-c", "server", "--since=3m")
        verified = logs.returncode == 0 and self.run_token in logs.stdout
        self._evidence["server_access_log_token_seen"] = verified
        return verified

    def recover(self, target_namespace: str, pod_name: str) -> bool:
        return True  # The finite request burst exits after exactly 200 requests.


class BenignRestartControl(BenignControl):
    """Delete one allowlisted target pod and verify its replacement is Ready."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._old_uid: str | None = None

    def inject(self, target_namespace: str, pod_name: str) -> bool:
        old = self._kubectl("get", "pod", pod_name, "-n", target_namespace, "-o", "json")
        if old.returncode:
            return False
        self._old_uid = json.loads(old.stdout)["metadata"]["uid"]
        deleted = self._kubectl("delete", "pod", pod_name, "-n", target_namespace, "--wait=true", "--timeout=60s", timeout=70)
        if deleted.returncode:
            return False
        rollout = self._kubectl("rollout", "status", f"deployment/{self.manifest.target_service}",
                                "-n", target_namespace, "--timeout=120s", timeout=130)
        self._evidence = {"kind": "pod_replacement", "old_pod_uid": self._old_uid,
                          "delete_output": deleted.stdout.strip(), "rollout_status": rollout.stdout.strip()}
        return rollout.returncode == 0

    def verify_injection(self, target_namespace: str, pod_name: str) -> bool:
        result = self._kubectl("get", "pods", "-n", target_namespace, "-l", f"app={self.manifest.target_service}", "-o", "json")
        if result.returncode:
            return False
        items = json.loads(result.stdout).get("items", [])
        replacements = [p for p in items if p.get("metadata", {}).get("uid") != self._old_uid
                       and p.get("status", {}).get("phase") == "Running"
                       and any(c.get("type") == "Ready" and c.get("status") == "True"
                               for c in p.get("status", {}).get("conditions", []))]
        self._evidence["replacement_pod_uids"] = [p["metadata"]["uid"] for p in replacements]
        return bool(replacements)

    def recover(self, target_namespace: str, pod_name: str) -> bool:
        return True  # The Deployment has already restored the desired replica.
