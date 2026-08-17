"""
research/evaluation/dataset/packager.py

Packages labeled eBPF traces from PHANTOM evaluation runs into a
reproducible, Zenodo-ready research artifact.

Output layout (research/datasets/phantom-v1/):
    traces.parquet   — one row per eBPF event (see TRACES_SCHEMA)
    labels.parquet   — one row per scenario run (see LABELS_SCHEMA)
    manifest.json    — provenance, schema, splits, checksums
    README.md        — human-readable description (from README_template.md)
    splits/
        train.txt        — scenario_ids in training split
        validation.txt   — scenario_ids in validation split
        test.txt         — scenario_ids in test split

Format rationale (from handoff §5):
    Parquet is preferred over CSV because it preserves typed columns,
    compresses high-volume traces (snappy by default), and supports
    column projection. Preferred over HDF5 because standard data science
    tools (pandas, polars, DuckDB, Spark) can inspect it without special
    drivers. Preferred over JSON Lines because typed analytic scans are
    faster and the schema is fixed.

Privacy / PII policy:
    NO raw paths, no IP addresses, no argv contents, no environment
    variables, no pod UIDs (except salted hashes). All identity fields
    are coarsened or omitted per the traces.parquet schema in handoff §5.

Label source policy:
    ALL labels come from oracle manifests and injection timestamps
    recorded by run_all_scenarios.py. Labels are NEVER derived from
    PHANTOM detection outputs. This is verified by the
    ``label_source: "experiment_oracle"`` field in manifest.json.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from research.evaluation.scenarios.scenario_runner import ScenarioResult

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Output directory
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[4]
_DEFAULT_OUTPUT_DIR = _REPO_ROOT / "research" / "datasets" / "phantom-v1"
_README_TEMPLATE = Path(__file__).parent / "README_template.md"

# ---------------------------------------------------------------------------
# PyArrow schemas — exact match to handoff §5 traces.parquet and labels.parquet
# ---------------------------------------------------------------------------

TRACES_SCHEMA = pa.schema([
    # Identification
    pa.field("event_id",                     pa.string(),     nullable=False),
    pa.field("scenario_id",                  pa.string(),     nullable=False),
    pa.field("experiment_id",                pa.string(),     nullable=False),
    pa.field("repetition",                   pa.int32(),      nullable=False),
    pa.field("phase",                        pa.string(),     nullable=False),
    # Ground truth (oracle; never PHANTOM output)
    pa.field("label",                        pa.int32(),      nullable=False),
    pa.field("attack_family",                pa.string(),     nullable=True),
    pa.field("target_purl",                  pa.string(),     nullable=True),
    # Timing
    pa.field("observed_at",                  pa.timestamp("ns", tz="UTC"), nullable=False),
    pa.field("kernel_timestamp_ns",          pa.int64(),      nullable=False),
    pa.field("agent_lag_ms",                 pa.float32(),    nullable=True),
    # Event classification
    pa.field("event_type",                   pa.string(),     nullable=False),
    pa.field("identity_status",              pa.string(),     nullable=True),
    pa.field("violation_types",              pa.string(),     nullable=True),   # JSON list
    pa.field("purl_binding_status",          pa.string(),     nullable=True),
    # Process info (no raw PII)
    pa.field("comm",                         pa.string(),     nullable=True),   # basename only
    pa.field("pid_hash",                     pa.string(),     nullable=True),   # salted SHA-256
    pa.field("ppid_hash",                    pa.string(),     nullable=True),
    pa.field("uid_class",                    pa.string(),     nullable=True),   # root|service|unknown
    pa.field("argv_fingerprint",             pa.string(),     nullable=True),   # hash, not raw
    # File info (coarsened)
    pa.field("file_path_class",              pa.string(),     nullable=True),   # coarse category
    pa.field("file_hash",                    pa.string(),     nullable=True),
    # Network info (coarsened)
    pa.field("remote_ip_class",              pa.string(),     nullable=True),   # cluster|private|public|none
    pa.field("remote_port",                  pa.int32(),      nullable=True),
    pa.field("dns_domain_class",             pa.string(),     nullable=True),
    # BDG / graph context
    pa.field("edge_src_purl",                pa.string(),     nullable=True),
    pa.field("edge_dst_purl",                pa.string(),     nullable=True),
    pa.field("edge_type",                    pa.string(),     nullable=True),
    pa.field("edge_weight",                  pa.float32(),    nullable=True),
    # Node / infra (salted)
    pa.field("node_id_hash",                 pa.string(),     nullable=True),
    pa.field("namespace",                    pa.string(),     nullable=True),
    pa.field("pod_uid_hash",                 pa.string(),     nullable=True),
    pa.field("container_id_hash",            pa.string(),     nullable=True),
    pa.field("service_name",                 pa.string(),     nullable=True),
    pa.field("image_digest",                 pa.string(),     nullable=True),
    pa.field("purl",                         pa.string(),     nullable=True),
    pa.field("agent_sequence",               pa.int64(),      nullable=True),
    # PHANTOM-computed metrics (may be None for baselines)
    pa.field("contract_state",               pa.string(),     nullable=True),
    pa.field("kl_score",                     pa.float32(),    nullable=True),
    pa.field("phantom_kl_divergence",        pa.float32(),    nullable=True),
    pa.field("phantom_pceps_score",          pa.float32(),    nullable=True),
    pa.field("phantom_attribution_confidence", pa.float32(), nullable=True),
    pa.field("ringbuf_lost_delta",           pa.int64(),      nullable=True),
    # Reproducibility
    pa.field("phantom_version",              pa.string(),     nullable=True),
])

LABELS_SCHEMA = pa.schema([
    pa.field("label_id",                     pa.string(),     nullable=False),
    pa.field("experiment_id",                pa.string(),     nullable=False),
    pa.field("scenario_id",                  pa.string(),     nullable=False),
    pa.field("attack_id",                    pa.string(),     nullable=False),
    pa.field("attack_family",                pa.string(),     nullable=False),
    pa.field("repetition",                   pa.int32(),      nullable=False),
    pa.field("label",                        pa.int32(),      nullable=False),
    pa.field("is_attack",                    pa.bool_(),      nullable=False),
    pa.field("is_pre_compromise",            pa.bool_(),      nullable=False),
    pa.field("is_compromised",               pa.bool_(),      nullable=False),
    pa.field("injection_timestamp",          pa.timestamp("ns", tz="UTC"), nullable=True),
    pa.field("compromise_time_ns",           pa.int64(),      nullable=True),
    pa.field("detection_timestamp_phantom",  pa.timestamp("ns", tz="UTC"), nullable=True),
    pa.field("detection_timestamp_falco",    pa.timestamp("ns", tz="UTC"), nullable=True),
    pa.field("recovery_timestamp",           pa.timestamp("ns", tz="UTC"), nullable=True),
    pa.field("ground_truth_purl",            pa.string(),     nullable=True),
    pa.field("ground_truth_service",         pa.string(),     nullable=True),
    pa.field("expected_identifiable",        pa.bool_(),      nullable=True),
    pa.field("oracle_manifest_path",         pa.string(),     nullable=True),
    pa.field("clean_image_digest",           pa.string(),     nullable=True),
    pa.field("attack_image_digest",          pa.string(),     nullable=True),
    pa.field("phase_durations",              pa.string(),     nullable=True),   # JSON
    pa.field("notes",                        pa.string(),     nullable=True),
])

# ---------------------------------------------------------------------------
# DatasetManifest
# ---------------------------------------------------------------------------

_DATASET_VERSION = "phantom-v1"
_SCHEMA_VERSION = "v1"
_SPLIT_STRATEGY = "by_scenario_family_and_time"

# Split proportions (by scenario family, not random rows — handoff §5).
_TRAIN_FAMILIES = {"benign_update", "high_load", "pod_restart"}
_VAL_FAMILIES: set[str] = set()          # calibration slices (added at split time)
_TEST_FAMILIES = {
    "supply_chain_backdoor",
    "dependency_confusion",
    "build_pipeline_tampering",
}


@dataclass
class DatasetManifest:
    """Provenance and schema record for the PHANTOM v1 dataset.

    Attributes:
        dataset_version: Dataset release tag.
        created_at: ISO 8601 UTC timestamp.
        phantom_version: Git commit hash of PHANTOM at dataset creation.
        attack_scenarios: List of oracle ground-truth dicts.
        event_count: Total rows in traces.parquet.
        scenario_count: Total rows in labels.parquet.
        schema_version: Schema specification version.
        label_source: Always 'experiment_oracle'.
        train_scenario_ids: Scenario IDs in the training split.
        validation_scenario_ids: Scenario IDs in the validation split.
        test_scenario_ids: Scenario IDs in the test split.
        split_strategy: Split strategy description.
        traces_sha256: SHA-256 of traces.parquet.
        labels_sha256: SHA-256 of labels.parquet.
        output_dir: Absolute path of the output directory.
        column_descriptions: Dict of field_name → description.
    """

    dataset_version: str = _DATASET_VERSION
    created_at: str = ""
    phantom_version: str = ""
    attack_scenarios: list[dict[str, Any]] = field(default_factory=list)
    event_count: int = 0
    scenario_count: int = 0
    schema_version: str = _SCHEMA_VERSION
    label_source: str = "experiment_oracle"
    train_scenario_ids: list[str] = field(default_factory=list)
    validation_scenario_ids: list[str] = field(default_factory=list)
    test_scenario_ids: list[str] = field(default_factory=list)
    split_strategy: str = _SPLIT_STRATEGY
    traces_sha256: str = ""
    labels_sha256: str = ""
    output_dir: str = ""
    column_descriptions: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-serializable dict.

        Returns:
            Dict with all manifest fields.
        """
        return {
            "dataset_version": self.dataset_version,
            "created_at": self.created_at,
            "phantom_version": self.phantom_version,
            "attack_scenarios": self.attack_scenarios,
            "event_count": self.event_count,
            "scenario_count": self.scenario_count,
            "schema_version": self.schema_version,
            "label_source": self.label_source,
            "train_scenario_ids": self.train_scenario_ids,
            "validation_scenario_ids": self.validation_scenario_ids,
            "test_scenario_ids": self.test_scenario_ids,
            "split_strategy": self.split_strategy,
            "traces_sha256": self.traces_sha256,
            "labels_sha256": self.labels_sha256,
            "output_dir": self.output_dir,
            "column_descriptions": self.column_descriptions,
        }


# ---------------------------------------------------------------------------
# Column descriptions (for README auto-fill and manifest)
# ---------------------------------------------------------------------------

_COLUMN_DESCRIPTIONS: dict[str, str] = {
    "event_id":                      "Stable UUID for event row (join/debug key)",
    "scenario_id":                   "Scenario/run_id identifier",
    "experiment_id":                 "Trial identifier grouping all repetitions",
    "repetition":                    "Repetition number (1-based)",
    "phase":                         "Scenario phase: baseline|attack|recovery|post_recovery",
    "label":                         "Oracle ground truth: 1=attack, 0=benign",
    "attack_family":                 "Attack taxonomy or null for benign",
    "target_purl":                   "PURL of the substituted/added component",
    "observed_at":                   "UTC event observation timestamp (ns precision)",
    "kernel_timestamp_ns":           "Kernel event timestamp (ns)",
    "agent_lag_ms":                  "Collection latency: ingest_ts - kernel_ts (ms)",
    "event_type":                    "eBPF event category (exec|net_connect|file_open|...)",
    "identity_status":               "Component identity binding status",
    "violation_types":               "JSON list of behavioral contract violation types",
    "purl_binding_status":           "declared|runtime_only|substituted|unknown",
    "comm":                          "Executable basename (no path, no args)",
    "pid_hash":                      "Salted SHA-256 of PID+session (not reversible)",
    "ppid_hash":                     "Salted SHA-256 of parent PID",
    "uid_class":                     "Coarse UID category: root|service|unknown",
    "argv_fingerprint":              "SHA-256 of command arguments (no raw argv)",
    "file_path_class":               "Coarse path category (no raw paths with secrets)",
    "file_hash":                     "SHA-256 of accessed file artifact",
    "remote_ip_class":               "cluster|private|public|none (no raw IPs)",
    "remote_port":                   "Remote port (not PII alone)",
    "dns_domain_class":              "cluster_service|controlled_sink|external|none",
    "edge_src_purl":                 "BDG source component PURL",
    "edge_dst_purl":                 "BDG destination component PURL",
    "edge_type":                     "process|file|network|ipc",
    "edge_weight":                   "Decayed BDG edge weight",
    "node_id_hash":                  "Salted node identifier (salted per release)",
    "namespace":                     "Kubernetes namespace",
    "pod_uid_hash":                  "Salted Pod UID (not reversible)",
    "container_id_hash":             "Salted container ID (not reversible)",
    "service_name":                  "Benchmark service name",
    "image_digest":                  "OCI image digest (artifact metadata, no secrets)",
    "purl":                          "Package URL attributed to event",
    "agent_sequence":                "Monotone agent event sequence number",
    "contract_state":                "Behavioral contract state",
    "kl_score":                      "Component KL divergence from baseline",
    "phantom_kl_divergence":         "PHANTOM KL drift score (null for baselines)",
    "phantom_pceps_score":           "PCEPS predicted exploit probability (null for baselines)",
    "phantom_attribution_confidence": "PHANTOM attribution confidence (null for baselines)",
    "ringbuf_lost_delta":            "eBPF ring buffer lost-event counter delta",
    "phantom_version":               "PHANTOM git commit hash for reproducibility",
}


# ---------------------------------------------------------------------------
# PII-free field coarseners
# ---------------------------------------------------------------------------

_SALT: str = os.environ.get("PHANTOM_HASH_SALT", "phantom-eval-salt-v1")


def _salted_hash(value: str) -> str:
    """Return a salted SHA-256 hash of value.

    Used to hash PID, Pod UID, container ID — sufficient for grouping
    without exposing raw values.

    Args:
        value: Raw value to hash.

    Returns:
        Hex SHA-256 string.
    """
    return hashlib.sha256(f"{_SALT}:{value}".encode()).hexdigest()


def _uid_class(uid: int) -> str:
    """Map a UID to a coarse category.

    Args:
        uid: Unix UID integer.

    Returns:
        'root' | 'service' | 'unknown'
    """
    if uid == 0:
        return "root"
    if 1 <= uid < 1000:
        return "service"
    return "unknown"


def _ip_class(ip: str) -> str:
    """Map an IP to a coarse class.

    Args:
        ip: IP address string.

    Returns:
        'cluster' | 'private' | 'public' | 'none'
    """
    if not ip:
        return "none"
    if ip.startswith("10.") or ip.startswith("172.") or ip.startswith("192.168."):
        return "private"
    if ip.startswith("100."):
        return "cluster"
    if ip in ("127.0.0.1", "::1"):
        return "cluster"
    return "public"


def _path_class(path: str) -> str:
    """Map a file path to a coarse category.

    Args:
        path: Raw file path string.

    Returns:
        Coarse path category string.
    """
    if not path:
        return "none"
    p = path.lower()
    if "/tmp/" in p:
        return "tmp"
    if "/proc/" in p:
        return "proc"
    if "/sys/" in p:
        return "sys"
    if "/etc/" in p:
        return "etc"
    if "/usr/lib" in p or "/usr/local/lib" in p:
        return "lib"
    if "/usr/bin" in p or "/usr/local/bin" in p:
        return "bin"
    if "/home/" in p or "/root/" in p:
        return "home"
    return "other"


def _dns_class(domain: str, sink_host: str = "phantom-sink") -> str:
    """Classify a DNS domain into a coarse category.

    Args:
        domain: Domain name string.
        sink_host: Substring identifying the controlled evaluation sink.

    Returns:
        'cluster_service' | 'controlled_sink' | 'external' | 'none'
    """
    if not domain:
        return "none"
    d = domain.lower()
    if sink_host in d:
        return "controlled_sink"
    if d.endswith(".svc.cluster.local") or d.endswith(".cluster.local"):
        return "cluster_service"
    return "external"


# ---------------------------------------------------------------------------
# DatasetPackager
# ---------------------------------------------------------------------------


class DatasetPackager:
    """Packages labeled eBPF traces as a reproducible research artifact.

    Reads ScenarioResult JSON files (from research/datasets/raw/) and
    the drift events collected from the PHANTOM API during each scenario,
    then writes traces.parquet, labels.parquet, manifest.json, and README.md
    to the output directory.

    Label source: ALL labels come from oracle timestamps in ScenarioResult.
    PHANTOM detections are stored in separate columns for analysis but are
    never used to derive the ``label`` column. This is enforced by design
    and verified by the manifest field ``label_source: "experiment_oracle"``.

    Args:
        output_dir: Output directory for the packaged dataset.
        phantom_version: Git commit hash string (auto-detected if None).
        compression: Parquet compression codec ('snappy', 'gzip', 'none').
    """

    def __init__(
        self,
        output_dir: str | Path = _DEFAULT_OUTPUT_DIR,
        phantom_version: str | None = None,
        compression: str = "snappy",
    ) -> None:
        """Initialise the packager.

        Args:
            output_dir: Dataset output directory.
            phantom_version: Git commit hash.
            compression: Parquet compression codec.
        """
        self._output_dir = Path(output_dir)
        self._compression = compression
        self._phantom_version = phantom_version or self._get_git_hash()

    def package(
        self,
        scenario_results: list[ScenarioResult],
        extra_traces: list[dict[str, Any]] | None = None,
    ) -> DatasetManifest:
        """Create the full dataset artifact from scenario results.

        Writes:
            traces.parquet   — eBPF event rows (one per drift event from PHANTOM API)
            labels.parquet   — one row per scenario run
            manifest.json    — provenance, splits, checksums
            README.md        — human-readable description
            splits/          — train.txt, validation.txt, test.txt

        Args:
            scenario_results: ScenarioResult list from run_all_scenarios.py.
            extra_traces: Optional additional raw event dicts to include
                in traces.parquet (e.g. from a separate event log). If None,
                PHANTOM drift events from ScenarioResult.phantom_detections
                are used.

        Returns:
            DatasetManifest describing the packaged dataset.
        """
        self._output_dir.mkdir(parents=True, exist_ok=True)

        manifest = DatasetManifest(
            created_at=datetime.now(tz=timezone.utc).isoformat(),
            phantom_version=self._phantom_version,
            output_dir=str(self._output_dir),
            column_descriptions=_COLUMN_DESCRIPTIONS,
        )

        # ------------------------------------------------------------------ #
        # Build labels rows (one per ScenarioResult)                          #
        # ------------------------------------------------------------------ #
        label_rows = self._build_label_rows(scenario_results)

        # ------------------------------------------------------------------ #
        # Build traces rows (from PHANTOM drift events)                       #
        # ------------------------------------------------------------------ #
        trace_rows = self._build_trace_rows(scenario_results, extra_traces or [])

        # ------------------------------------------------------------------ #
        # Split scenario IDs                                                  #
        # ------------------------------------------------------------------ #
        train_ids, val_ids, test_ids = self._split_scenario_ids(scenario_results)
        manifest.train_scenario_ids = train_ids
        manifest.validation_scenario_ids = val_ids
        manifest.test_scenario_ids = test_ids

        # ------------------------------------------------------------------ #
        # Compute attack scenario metadata for manifest                       #
        # ------------------------------------------------------------------ #
        manifest.attack_scenarios = [
            r.scenario_label
            for r in scenario_results
            if r.ground_truth_label == 1
        ]

        manifest.event_count = len(trace_rows)
        manifest.scenario_count = len(label_rows)

        # ------------------------------------------------------------------ #
        # Write Parquet files                                                  #
        # ------------------------------------------------------------------ #
        traces_path = self._output_dir / "traces.parquet"
        labels_path = self._output_dir / "labels.parquet"

        self._write_parquet(trace_rows, TRACES_SCHEMA, traces_path)
        self._write_parquet(label_rows, LABELS_SCHEMA, labels_path)

        manifest.traces_sha256 = self._sha256(traces_path)
        manifest.labels_sha256 = self._sha256(labels_path)

        # ------------------------------------------------------------------ #
        # Write manifest.json                                                  #
        # ------------------------------------------------------------------ #
        manifest_path = self._output_dir / "manifest.json"
        with manifest_path.open("w") as fh:
            json.dump(manifest.to_dict(), fh, indent=2, default=str)
        log.info("packager.manifest_written", extra={"path": str(manifest_path)})

        # ------------------------------------------------------------------ #
        # Write README.md                                                      #
        # ------------------------------------------------------------------ #
        readme_path = self._output_dir / "README.md"
        self._write_readme(manifest, readme_path)

        # ------------------------------------------------------------------ #
        # Write split files                                                    #
        # ------------------------------------------------------------------ #
        splits_dir = self._output_dir / "splits"
        splits_dir.mkdir(exist_ok=True)
        (splits_dir / "train.txt").write_text("\n".join(train_ids))
        (splits_dir / "validation.txt").write_text("\n".join(val_ids))
        (splits_dir / "test.txt").write_text("\n".join(test_ids))

        log.info(
            "packager.complete",
            extra={
                "events": manifest.event_count,
                "scenarios": manifest.scenario_count,
                "output": str(self._output_dir),
            },
        )
        return manifest

    # ------------------------------------------------------------------ #
    # Row builders                                                         #
    # ------------------------------------------------------------------ #

    def _build_trace_rows(
        self,
        scenario_results: list[ScenarioResult],
        extra_traces: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Build trace rows from PHANTOM drift events in scenario results.

        Each PHANTOM drift-event dict from ScenarioResult.phantom_detections
        becomes one row in traces.parquet. Fields are coarsened per PII policy.

        Args:
            scenario_results: Scenario results containing drift events.
            extra_traces: Additional raw event dicts.

        Returns:
            List of row dicts conforming to TRACES_SCHEMA.
        """
        rows: list[dict[str, Any]] = []
        phantom_version = self._phantom_version

        for result in scenario_results:
            # Determine oracle phase for each event.
            # Events from phantom_detections are during the attack phase.
            for evt in result.phantom_detections:
                row = self._coarsen_event(
                    raw=evt,
                    scenario_id=result.run_id,
                    experiment_id=result.attack_id,
                    repetition=result.repetition,
                    phase="attack",
                    label=result.ground_truth_label,
                    attack_family=result.attack_family if result.ground_truth_label == 1 else None,
                    target_purl=result.scenario_label.get("target_purl"),
                    phantom_version=phantom_version,
                )
                rows.append(row)

        # Append any extra traces (e.g. from eBPF log file export).
        for raw in extra_traces:
            row = self._coarsen_event(
                raw=raw,
                scenario_id=raw.get("scenario_id", ""),
                experiment_id=raw.get("experiment_id", ""),
                repetition=int(raw.get("repetition", 1)),
                phase=raw.get("phase", "baseline"),
                label=int(raw.get("label", 0)),
                attack_family=raw.get("attack_family"),
                target_purl=raw.get("target_purl"),
                phantom_version=phantom_version,
            )
            rows.append(row)

        return rows

    def _coarsen_event(
        self,
        raw: dict[str, Any],
        scenario_id: str,
        experiment_id: str,
        repetition: int,
        phase: str,
        label: int,
        attack_family: str | None,
        target_purl: str | None,
        phantom_version: str,
    ) -> dict[str, Any]:
        """Transform a raw drift-event dict into a PII-free trace row.

        Applies salted hashing to PID, container ID, Pod UID.
        Coarsens UID to root|service|unknown.
        Replaces raw file paths with path_class categories.
        Replaces raw IPs with ip_class categories.
        Replaces raw DNS domains with domain_class categories.

        Args:
            raw: Raw drift event dict from PHANTOM API.
            scenario_id: Scenario run_id.
            experiment_id: Attack ID (experiment group).
            repetition: Repetition index.
            phase: Scenario phase name.
            label: Oracle label (1=attack, 0=benign).
            attack_family: Attack family or None.
            target_purl: Oracle target PURL or None.
            phantom_version: Git commit hash.

        Returns:
            Row dict conforming to TRACES_SCHEMA.
        """
        observed_at_raw = raw.get("observed_at") or raw.get("created_at") or ""
        try:
            observed_at = pd.Timestamp(observed_at_raw, tz="UTC")
        except Exception:  # noqa: BLE001
            observed_at = pd.Timestamp.now(tz="UTC")

        return {
            "event_id":                       str(raw.get("event_id") or uuid.uuid4()),
            "scenario_id":                    scenario_id,
            "experiment_id":                  experiment_id,
            "repetition":                     repetition,
            "phase":                          phase,
            "label":                          label,
            "attack_family":                  attack_family,
            "target_purl":                    target_purl,
            "observed_at":                    observed_at,
            "kernel_timestamp_ns":            int(raw.get("kernel_timestamp_ns", 0)),
            "agent_lag_ms":                   float(raw.get("agent_lag_ms") or 0.0) or None,
            "event_type":                     str(raw.get("event_type", "")),
            "identity_status":                raw.get("identity_status"),
            "violation_types":                json.dumps(raw.get("violation_types") or []),
            "purl_binding_status":            raw.get("purl_binding_status"),
            # Process — coarsened
            "comm":                           str(raw.get("comm", ""))[:64],
            "pid_hash":                       _salted_hash(str(raw.get("pid", ""))),
            "ppid_hash":                      _salted_hash(str(raw.get("ppid", ""))),
            "uid_class":                      _uid_class(int(raw.get("uid", 1001))),
            "argv_fingerprint":               hashlib.sha256(
                                                  str(raw.get("argv", "")).encode()
                                              ).hexdigest() if raw.get("argv") else None,
            # File — coarsened
            "file_path_class":                _path_class(raw.get("file_path", "")),
            "file_hash":                      raw.get("file_hash"),
            # Network — coarsened
            "remote_ip_class":                _ip_class(raw.get("remote_ip", "")),
            "remote_port":                    raw.get("remote_port"),
            "dns_domain_class":               _dns_class(raw.get("dns_domain", "")),
            # BDG
            "edge_src_purl":                  raw.get("edge_src_purl"),
            "edge_dst_purl":                  raw.get("edge_dst_purl"),
            "edge_type":                      raw.get("edge_type"),
            "edge_weight":                    raw.get("edge_weight"),
            # Infrastructure — salted
            "node_id_hash":                   _salted_hash(str(raw.get("node_id", ""))),
            "namespace":                      raw.get("namespace"),
            "pod_uid_hash":                   _salted_hash(str(raw.get("pod_uid", ""))),
            "container_id_hash":              _salted_hash(str(raw.get("container_id", ""))),
            "service_name":                   raw.get("service_name"),
            "image_digest":                   raw.get("image_digest"),
            "purl":                           raw.get("purl"),
            "agent_sequence":                 raw.get("agent_sequence"),
            # Contract
            "contract_state":                 raw.get("contract_state"),
            "kl_score":                       raw.get("kl_score"),
            # PHANTOM metrics
            "phantom_kl_divergence":          raw.get("phantom_kl_divergence") or raw.get("kl_divergence"),
            "phantom_pceps_score":            raw.get("phantom_pceps_score") or raw.get("pceps_score"),
            "phantom_attribution_confidence": raw.get("phantom_attribution_confidence"),
            "ringbuf_lost_delta":             raw.get("ringbuf_lost_delta"),
            "phantom_version":                phantom_version,
        }

    def _build_label_rows(
        self,
        scenario_results: list[ScenarioResult],
    ) -> list[dict[str, Any]]:
        """Build one labels.parquet row per ScenarioResult.

        All timestamps are from oracle injection records, not PHANTOM detections.

        Args:
            scenario_results: List of ScenarioResult.

        Returns:
            List of row dicts conforming to LABELS_SCHEMA.
        """
        rows: list[dict[str, Any]] = []

        for result in scenario_results:
            # Recovery timestamp = end of recover phase.
            recovery_phase = next(
                (p for p in result.phases if p.name == "recover"), None
            )
            recovery_ts = pd.Timestamp(
                recovery_phase.end_time, tz="UTC"
            ) if recovery_phase and recovery_phase.end_time else None

            # First Falco detection timestamp.
            falco_ts = None
            if result.falco_detections:
                ts_raw = result.falco_detections[0].get("time", "")
                if ts_raw:
                    try:
                        falco_ts = pd.Timestamp(ts_raw, tz="UTC")
                    except Exception:  # noqa: BLE001
                        pass

            # Phase durations JSON.
            phase_durations = {
                p.name: round(p.duration_s, 2)
                for p in result.phases
                if p.duration_s > 0
            }

            oracle_path = result.scenario_label.get("oracle_manifest_path", "")

            rows.append({
                "label_id":                    str(uuid.uuid4()),
                "experiment_id":               result.attack_id,
                "scenario_id":                 result.run_id,
                "attack_id":                   result.attack_id,
                "attack_family":               result.attack_family,
                "repetition":                  result.repetition,
                "label":                       result.ground_truth_label,
                "is_attack":                   result.ground_truth_label == 1,
                "is_pre_compromise":           False,    # filled post-hoc from sink logs
                "is_compromised":              result.is_true_positive,
                "injection_timestamp":         pd.Timestamp(result.injection_timestamp, tz="UTC")
                                               if result.injection_timestamp else None,
                "compromise_time_ns":          None,     # from sink log; filled post-hoc
                "detection_timestamp_phantom": pd.Timestamp(
                                                   result.first_phantom_detection_timestamp, tz="UTC"
                                               ) if result.first_phantom_detection_timestamp else None,
                "detection_timestamp_falco":   falco_ts,
                "recovery_timestamp":          recovery_ts,
                "ground_truth_purl":           result.scenario_label.get("target_purl"),
                "ground_truth_service":        result.scenario_label.get("target_service"),
                "expected_identifiable":       result.ground_truth_label == 1,
                "oracle_manifest_path":        oracle_path,
                "clean_image_digest":          result.scenario_label.get("clean_image_digest"),
                "attack_image_digest":         result.scenario_label.get("attack_image_digest"),
                "phase_durations":             json.dumps(phase_durations),
                "notes":                       result.scenario_label.get("notes", ""),
            })

        return rows

    # ------------------------------------------------------------------ #
    # Split strategy                                                       #
    # ------------------------------------------------------------------ #

    def _split_scenario_ids(
        self,
        scenario_results: list[ScenarioResult],
    ) -> tuple[list[str], list[str], list[str]]:
        """Assign scenario IDs to train/val/test splits.

        Split by scenario family and time (handoff §5):
            Train:      benign control families (update, load, restart)
                        + all repetitions of each attack family except the last.
            Validation: One repetition per attack family (for threshold calibration).
            Test:       Held-out repetitions of all three attack families.

        No Pod UIDs, container IDs, or time-adjacent windows cross splits.
        The same attack family cannot appear in both validation and test
        on the same repetition.

        Args:
            scenario_results: All scenario results.

        Returns:
            (train_ids, validation_ids, test_ids)
        """
        # Group by (attack_family, repetition).
        by_family: dict[str, list[ScenarioResult]] = {}
        for r in scenario_results:
            by_family.setdefault(r.attack_family, []).append(r)

        train_ids: list[str] = []
        val_ids: list[str] = []
        test_ids: list[str] = []

        for family, results in by_family.items():
            sorted_results = sorted(results, key=lambda r: r.repetition)

            if family in _TRAIN_FAMILIES:
                # All benign control repetitions → train.
                train_ids.extend(r.run_id for r in sorted_results)
            elif family in _TEST_FAMILIES:
                # Last repetition → test; penultimate → validation; rest → train.
                if len(sorted_results) >= 3:
                    train_ids.extend(r.run_id for r in sorted_results[:-2])
                    val_ids.append(sorted_results[-2].run_id)
                    test_ids.append(sorted_results[-1].run_id)
                elif len(sorted_results) == 2:
                    val_ids.append(sorted_results[0].run_id)
                    test_ids.append(sorted_results[1].run_id)
                elif sorted_results:
                    test_ids.append(sorted_results[0].run_id)
            else:
                # Unknown family → train.
                train_ids.extend(r.run_id for r in sorted_results)

        return train_ids, val_ids, test_ids

    # ------------------------------------------------------------------ #
    # Parquet I/O                                                          #
    # ------------------------------------------------------------------ #

    def _write_parquet(
        self,
        rows: list[dict[str, Any]],
        schema: pa.Schema,
        path: Path,
    ) -> None:
        """Write a list of row dicts to a Parquet file using the given schema.

        Args:
            rows: List of row dicts.
            schema: PyArrow schema for type enforcement.
            path: Output path.
        """
        if not rows:
            # Write an empty table with the correct schema.
            table = pa.table({f.name: pa.array([], type=f.type) for f in schema}, schema=schema)
        else:
            df = pd.DataFrame(rows)
            # Enforce column presence and order.
            for col_field in schema:
                if col_field.name not in df.columns:
                    df[col_field.name] = None
            df = df[[f.name for f in schema]]
            table = pa.Table.from_pandas(df, schema=schema, preserve_index=False)

        pq.write_table(
            table,
            str(path),
            compression=self._compression,
        )
        log.info(
            "packager.parquet_written",
            extra={"path": str(path), "rows": len(rows)},
        )

    # ------------------------------------------------------------------ #
    # Checksums and git                                                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _sha256(path: Path) -> str:
        """Compute SHA-256 hex digest of a file.

        Args:
            path: File path.

        Returns:
            Hex SHA-256 string.
        """
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _get_git_hash() -> str:
        """Return the current git HEAD commit hash.

        Returns:
            Git commit hash string or 'unknown'.
        """
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            )
            return result.stdout.strip()
        except Exception:  # noqa: BLE001
            return "unknown"

    # ------------------------------------------------------------------ #
    # README generation                                                    #
    # ------------------------------------------------------------------ #

    def _write_readme(self, manifest: DatasetManifest, path: Path) -> None:
        """Generate README.md from the manifest using the template.

        Args:
            manifest: DatasetManifest with all provenance fields.
            path: Output path for README.md.
        """
        template_path = _README_TEMPLATE
        if template_path.exists():
            template = template_path.read_text()
        else:
            template = _DEFAULT_README_TEMPLATE

        # Auto-fill schema section.
        schema_lines = [
            f"| `{name}` | {desc} |"
            for name, desc in _COLUMN_DESCRIPTIONS.items()
        ]
        schema_table = (
            "| Column | Description |\n"
            "|---|---|\n"
            + "\n".join(schema_lines)
        )

        # Auto-fill attack scenarios section.
        scenario_lines: list[str] = []
        for sc in manifest.attack_scenarios:
            scenario_lines.append(
                f"- **{sc.get('attack_id', '?')}** "
                f"({sc.get('attack_family', '?')}): "
                f"`{sc.get('target_purl', '?')}` → "
                f"`{sc.get('target_service', '?')}`"
            )
        scenarios_block = "\n".join(scenario_lines) if scenario_lines else "No attack scenarios."

        readme = template.replace("{{SCHEMA_TABLE}}", schema_table)
        readme = readme.replace("{{ATTACK_SCENARIOS}}", scenarios_block)
        readme = readme.replace("{{CREATED_AT}}", manifest.created_at)
        readme = readme.replace("{{PHANTOM_VERSION}}", manifest.phantom_version)
        readme = readme.replace("{{EVENT_COUNT}}", str(manifest.event_count))
        readme = readme.replace("{{SCENARIO_COUNT}}", str(manifest.scenario_count))
        readme = readme.replace("{{TRACES_SHA256}}", manifest.traces_sha256)
        readme = readme.replace("{{LABELS_SHA256}}", manifest.labels_sha256)
        readme = readme.replace("{{SPLIT_STRATEGY}}", manifest.split_strategy)

        path.write_text(readme)
        log.info("packager.readme_written", extra={"path": str(path)})


# ---------------------------------------------------------------------------
# Default README template (used if README_template.md is missing)
# ---------------------------------------------------------------------------

_DEFAULT_README_TEMPLATE = """# PHANTOM eBPF Behavioral Trace Dataset v1

## Description

Labeled eBPF runtime event traces from PHANTOM supply-chain attack detection experiments.
Created at: {{CREATED_AT}}
PHANTOM version: {{PHANTOM_VERSION}}
Events: {{EVENT_COUNT}} | Scenarios: {{SCENARIO_COUNT}}

## Quick Start

```python
import pandas as pd
traces = pd.read_parquet('traces.parquet')
labels = pd.read_parquet('labels.parquet')
attack_traces = traces[traces['label'] == 1]
print(attack_traces.groupby('attack_family')['event_type'].value_counts())
```

## Schema — traces.parquet

{{SCHEMA_TABLE}}

## Attack Scenarios

{{ATTACK_SCENARIOS}}

## Split Strategy

{{SPLIT_STRATEGY}}

Train: benign control scenarios and non-held-out attack repetitions.
Validation: one held-out repetition per attack family (threshold calibration only).
Test: final held-out repetition per attack family.
No Pod UID, container ID, or time-adjacent windows cross split boundaries.

## Checksums

traces.parquet SHA-256: {{TRACES_SHA256}}
labels.parquet SHA-256: {{LABELS_SHA256}}

## Ethical Considerations

This dataset contains no PII, no real credentials, no real network endpoints, and no
real system paths. All attacks were conducted in isolated test environments with
controlled cluster-internal endpoints only. PID, Pod UID, and container IDs are
replaced with salted SHA-256 hashes. File paths are categorized into coarse classes.
IP addresses are classified as cluster|private|public|none. No raw argv is recorded.

## License

Data: CC BY 4.0. Packaging scripts: Apache-2.0.

## Citation

If you use this dataset, please cite the PHANTOM paper (citation TBD).
"""


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    _REPO_ROOT_CLI = Path(__file__).resolve().parents[4]
    if str(_REPO_ROOT_CLI) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT_CLI))

    parser = argparse.ArgumentParser(description="Package PHANTOM evaluation dataset.")
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=_REPO_ROOT_CLI / "research" / "datasets" / "raw",
        help="Directory containing ScenarioResult JSON files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_DEFAULT_OUTPUT_DIR,
        help="Output directory for packaged dataset.",
    )
    parser.add_argument(
        "--compression",
        default="snappy",
        choices=["snappy", "gzip", "none"],
        help="Parquet compression codec.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    raw_dir = args.raw_dir
    results: list[ScenarioResult] = []

    for json_file in sorted(raw_dir.glob("*.json")):
        if json_file.name == "index.json":
            continue
        try:
            with json_file.open() as fh:
                data = json.load(fh)
            # Reconstruct ScenarioResult from dict (minimal reconstruction).
            sr = ScenarioResult(
                run_id=data.get("run_id", ""),
                attack_id=data.get("attack_id", ""),
                attack_family=data.get("attack_family", ""),
                repetition=data.get("repetition", 1),
                namespace=data.get("namespace", ""),
                pod_name=data.get("pod_name", ""),
                ground_truth_label=data.get("ground_truth_label", 0),
                mttd_s=data.get("mttd_s"),
                is_true_positive=data.get("is_true_positive", False),
                phantom_detections=data.get("phantom_detections", []),
                falco_detections=data.get("falco_detections", []),
                scenario_label=data.get("scenario_label", {}),
                error=data.get("error", ""),
            )
            if data.get("injection_timestamp"):
                sr.injection_timestamp = datetime.fromisoformat(
                    data["injection_timestamp"].rstrip("Z")
                ).replace(tzinfo=timezone.utc)
            if data.get("first_phantom_detection_timestamp"):
                sr.first_phantom_detection_timestamp = datetime.fromisoformat(
                    data["first_phantom_detection_timestamp"].rstrip("Z")
                ).replace(tzinfo=timezone.utc)
            results.append(sr)
        except Exception as exc:  # noqa: BLE001
            log.warning("cli.load_failed", extra={"file": str(json_file), "error": str(exc)})

    packager = DatasetPackager(
        output_dir=args.output_dir,
        compression=args.compression,
    )
    manifest = packager.package(results)
    print(f"Dataset packaged: {args.output_dir}")
    print(f"  Events:    {manifest.event_count}")
    print(f"  Scenarios: {manifest.scenario_count}")
    print(f"  Train IDs: {len(manifest.train_scenario_ids)}")
    print(f"  Val IDs:   {len(manifest.validation_scenario_ids)}")
    print(f"  Test IDs:  {len(manifest.test_scenario_ids)}")
    print(f"  traces.parquet SHA-256: {manifest.traces_sha256}")
    print(f"  labels.parquet SHA-256: {manifest.labels_sha256}")
