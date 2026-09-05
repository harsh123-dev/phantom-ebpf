#!/usr/bin/env bash
# research/evaluation/run_full_evaluation.sh
#
# Master script for the PHANTOM full evaluation pipeline.
#
# This script orchestrates all evaluation phases in sequence:
#   1. Cluster readiness check
#   2. Attack scenario runs (3 attacks × 3 reps + 3 benign controls × 3 reps)
#   3. Baseline comparisons (Falco, Trivy, IsoForest)
#   4. Dataset packaging (traces.parquet + labels.parquet + manifest.json)
#   5. Metric computation and LaTeX/CSV table generation
#   6. Notebook execution (paper figures and tables)
#
# Usage:
#   chmod +x research/evaluation/run_full_evaluation.sh
#   bash research/evaluation/run_full_evaluation.sh [OPTIONS]
#
# Options (as environment variables):
#   NAMESPACE          Kubernetes namespace for experiments (default: phantom-eval)
#   PHANTOM_API_URL    PHANTOM API Gateway URL (default: http://localhost:8080)
#   PROMETHEUS_URL     Prometheus query API URL (default: http://localhost:9090/api/v1/query)
#   FALCO_LOG          Falco alert log path (default: /var/log/falco/events.jsonl)
#   API_TOKEN          PHANTOM API bearer token (default: "")
#   BASELINE_DURATION  Baseline phase duration in seconds (default: 300)
#   ATTACK_DURATION    Attack observation phase in seconds (default: 300)
#   RECOVERY_DURATION  Post-recovery phase in seconds (default: 120)
#   DRY_RUN            Set to "1" to run without executing kubectl/subprocess calls
#   SKIP_NOTEBOOKS     Set to "1" to skip notebook execution (faster CI runs)
#
# Environment requirements:
#   - kubectl configured and pointing at the evaluation cluster
#   - python3 with evaluation requirements installed:
#     pip install -r research/evaluation/requirements.txt
#   - helm installed (for Falco baseline)
#   - docker installed (for SolarWinds image build)
#   - trivy 0.70.0 on PATH (for Trivy baseline)
#   - jupyter installed (for notebook execution, unless SKIP_NOTEBOOKS=1)
#
# Version pins (from handoff §3):
#   Falco:      0.44.1 (chart falcosecurity/falco 4.3.1)
#   Trivy:      0.70.0
#   Kubernetes: 1.36.2 (eks.6 platform)
#
# Reproducibility:
#   Each run records PHANTOM git commit, container image digests, Helm chart
#   versions, and Prometheus snapshot timestamps in the dataset manifest.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NAMESPACE="${NAMESPACE:-phantom-eval}"
PHANTOM_API_URL="${PHANTOM_API_URL:-http://localhost:8080}"
PROMETHEUS_URL="${PROMETHEUS_URL:-http://localhost:9090/api/v1/query}"
FALCO_LOG="${FALCO_LOG:-/var/log/falco/events.jsonl}"
API_TOKEN="${API_TOKEN:-}"
BASELINE_DURATION="${BASELINE_DURATION:-300}"
ATTACK_DURATION="${ATTACK_DURATION:-300}"
RECOVERY_DURATION="${RECOVERY_DURATION:-120}"
DRY_RUN="${DRY_RUN:-0}"
SKIP_NOTEBOOKS="${SKIP_NOTEBOOKS:-0}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESULTS_DIR="${REPO_ROOT}/research/datasets/raw"
DATASET_DIR="${REPO_ROOT}/research/datasets/phantom-v1"
TABLES_DIR="${REPO_ROOT}/research/evaluation/results"
NOTEBOOKS_DIR="${REPO_ROOT}/research/notebooks"

DRY_RUN_FLAG=""
if [[ "${DRY_RUN}" == "1" ]]; then
    DRY_RUN_FLAG="--dry-run"
    echo "[WARN] DRY_RUN=1: kubectl/subprocess calls will be logged but not executed."
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*"
}

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

check_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' not found on PATH. Install it first."
}

# ---------------------------------------------------------------------------
# Step 0: Pre-flight checks
# ---------------------------------------------------------------------------

log "=== PHANTOM Full Evaluation Pipeline ==="
log "Repository: ${REPO_ROOT}"
log "Namespace:  ${NAMESPACE}"
log "PHANTOM API: ${PHANTOM_API_URL}"
log "Prometheus: ${PROMETHEUS_URL}"

check_cmd kubectl
check_cmd python3

# Auto-install python requirements (bypass PEP 668 and system uninstall errors on EC2)
log "Installing Python dependencies..."
python3 -m pip install -r "${REPO_ROOT}/research/evaluation/requirements.txt" --break-system-packages --ignore-installed --quiet || log "[WARN] pip install failed."

mkdir -p "${RESULTS_DIR}" "${DATASET_DIR}" "${TABLES_DIR}" "${NOTEBOOKS_DIR}"

# ---------------------------------------------------------------------------
# Step 1: Verify cluster readiness
# ---------------------------------------------------------------------------

log ""
log "=== Step 1: Verify cluster is ready ==="

if [[ "${DRY_RUN}" != "1" ]]; then
    kubectl get nodes --no-headers | grep -q Ready || die "No Ready nodes found in cluster."
    log "Cluster nodes: OK"

    # Verify PHANTOM services are running
    for svc in phantom-ebpf-agent phantom-api-gateway; do
        if kubectl get pods -n "phantom" -l "app=${svc}" --field-selector=status.phase=Running \
            --no-headers 2>/dev/null | grep -q .; then
            log "Service ${svc}: Running"
        else
            log "[WARN] Service ${svc} not found. Continuing anyway (some metrics may be empty)."
        fi
    done

    # Record PHANTOM version
    PHANTOM_VERSION=$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo "unknown")
    log "PHANTOM version: ${PHANTOM_VERSION}"
else
    log "DRY_RUN: skipping cluster check."
fi

# ---------------------------------------------------------------------------
# Step 2: Run attack and benign scenarios
# ---------------------------------------------------------------------------

log ""
log "=== Step 2: Run attack scenarios (3 attacks × 3 reps + 3 benign × 3 reps) ==="

python3 "${REPO_ROOT}/research/evaluation/scenarios/run_all_scenarios.py" \
    --namespace "${NAMESPACE}" \
    --phantom-api "${PHANTOM_API_URL}" \
    --prometheus "${PROMETHEUS_URL}" \
    --falco-log "${FALCO_LOG}" \
    --token "${API_TOKEN}" \
    --baseline-duration "${BASELINE_DURATION}" \
    --attack-duration "${ATTACK_DURATION}" \
    --recovery-duration "${RECOVERY_DURATION}" \
    --repetitions 3 \
    ${DRY_RUN_FLAG}

log "Scenario results written to: ${RESULTS_DIR}"

# ---------------------------------------------------------------------------
# Step 3: Run baseline comparisons
# ---------------------------------------------------------------------------

log ""
log "=== Step 3: Run baseline comparisons (Falco, Trivy, IsoForest) ==="

python3 "${REPO_ROOT}/research/evaluation/baselines/run_baselines.py" \
    --namespace "${NAMESPACE}" \
    --raw-dir "${RESULTS_DIR}" \
    --prometheus "${PROMETHEUS_URL}" \
    --falco-log "${FALCO_LOG}" \
    --output-dir "${TABLES_DIR}" \
    ${DRY_RUN_FLAG} \
    || log "[WARN] run_baselines.py failed or not yet implemented — continuing."

# ---------------------------------------------------------------------------
# Step 4: Package dataset
# ---------------------------------------------------------------------------

log ""
log "=== Step 4: Package dataset (traces.parquet + labels.parquet) ==="

python3 "${REPO_ROOT}/research/evaluation/dataset/packager.py" \
    --raw-dir "${RESULTS_DIR}" \
    --output-dir "${DATASET_DIR}" \
    --compression snappy

log "Dataset written to: ${DATASET_DIR}"
log "  traces.parquet"
log "  labels.parquet"
log "  manifest.json"
log "  README.md"
log "  splits/train.txt, validation.txt, test.txt"

# ---------------------------------------------------------------------------
# Step 5: Compute metrics and generate tables
# ---------------------------------------------------------------------------

log ""
log "=== Step 5: Compute metrics and generate LaTeX/CSV tables ==="

python3 "${REPO_ROOT}/research/evaluation/metrics/comparison_table.py" \
    --output-dir "${TABLES_DIR}" \
    || log "[WARN] comparison_table.py: no pre-computed reports found — run evaluator first."

log "Tables written to: ${TABLES_DIR}"
log "  table_1_detection_performance.tex"
log "  table_1_detection_performance_extended.tex"
log "  table_1_detection_performance.csv"

# ---------------------------------------------------------------------------
# Step 6: Generate and execute notebooks
# ---------------------------------------------------------------------------

log ""
log "=== Step 6: Generate and execute analysis notebooks ==="

# (Re-)generate notebook files from source.
python3 "${REPO_ROOT}/research/evaluation/dataset/generate_notebooks.py" \
    --output-dir "${NOTEBOOKS_DIR}"

if [[ "${SKIP_NOTEBOOKS}" == "1" ]]; then
    log "SKIP_NOTEBOOKS=1: skipping notebook execution."
else
    check_cmd jupyter

    for nb in \
        "${NOTEBOOKS_DIR}/01_causal_attribution_analysis.ipynb" \
        "${NOTEBOOKS_DIR}/02_pceps_calibration.ipynb" \
        "${NOTEBOOKS_DIR}/03_overhead_measurement.ipynb" \
        "${NOTEBOOKS_DIR}/04_bdg_topology_analysis.ipynb"
    do
        log "Executing notebook: $(basename "${nb}")"
        jupyter nbconvert \
            --to notebook \
            --execute \
            --ExecutePreprocessor.timeout=600 \
            --inplace \
            "${nb}" \
            || log "[WARN] Notebook $(basename "${nb}") failed — check for missing data."
    done
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

log ""
log "=== Evaluation complete ==="
log ""
log "Results:"
log "  Raw scenario results:  ${RESULTS_DIR}/"
log "  Dataset artifact:      ${DATASET_DIR}/"
log "  LaTeX/CSV tables:      ${TABLES_DIR}/"
log "  Executed notebooks:    ${NOTEBOOKS_DIR}/"
log ""
log "Next steps:"
log "  1. Check ${TABLES_DIR}/table_1_detection_performance.tex for TABLE_1."
log "  2. Open notebooks in ${NOTEBOOKS_DIR}/ for interactive figure inspection."
log "  3. Upload ${DATASET_DIR}/ to Zenodo with reserved DOI before paper submission."
log "  4. Record PHANTOM version, EKS cluster config, and run timestamps in run manifest."
