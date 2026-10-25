"""
research/evaluation/attacks — Attack injection implementations.

Provides deterministic, repeatable attack scenarios for the PHANTOM
evaluation. Every attack is identified by an AttackManifest that serves
as the oracle ground-truth record for metric computation.
"""

from __future__ import annotations

from research.evaluation.attacks.base_attack import AttackManifest, BaseAttack
from research.evaluation.attacks.dependency_confusion import (
    DEP_CONFUSION_MANIFEST,
    DependencyConfusionAttack,
)
from research.evaluation.attacks.file_tamper_style import (
    FILE_TAMPER_MANIFEST,
    FileTamperAttack,
)
from research.evaluation.attacks.net_egress_style import (
    NET_EGRESS_MANIFEST,
    NetEgressAttack,
)
from research.evaluation.attacks.proc_spawn_style import (
    PROC_SPAWN_MANIFEST,
    ProcSpawnAttack,
)
from research.evaluation.attacks.safety import (
    ALLOWLISTED_NAMESPACES,
    ALLOWLISTED_SERVICES,
    ALLOWLISTED_SINK_HOSTS,
    ALLOWLISTED_SINK_PORTS,
    APPROVED_CLUSTER_ENDPOINT_PATTERNS,
    APPROVED_DISPOSABLE_CONTEXTS,
    DISALLOWED_ENDPOINT_DOMAINS,
    DRY_RUN_ALLOWLISTED_SINK_HOSTS,
    LIVE_ALLOWLISTED_SINK_HOSTS,
    SafetyCheckError,
    SafetyPreflight,
)
from research.evaluation.attacks.solarwinds_style import (
    SOLARWINDS_MANIFEST,
    SolarWindsStyleAttack,
)
from research.evaluation.attacks.xzutils_style import (
    XZUTILS_MANIFEST,
    XZUtilsStyleAttack,
)

__all__ = [
    "ALLOWLISTED_NAMESPACES",
    "ALLOWLISTED_SERVICES",
    "ALLOWLISTED_SINK_HOSTS",
    "ALLOWLISTED_SINK_PORTS",
    "APPROVED_CLUSTER_ENDPOINT_PATTERNS",
    "APPROVED_DISPOSABLE_CONTEXTS",
    "AttackManifest",
    "BaseAttack",
    "DEP_CONFUSION_MANIFEST",
    "DISALLOWED_ENDPOINT_DOMAINS",
    "DRY_RUN_ALLOWLISTED_SINK_HOSTS",
    "DependencyConfusionAttack",
    "FILE_TAMPER_MANIFEST",
    "FileTamperAttack",
    "LIVE_ALLOWLISTED_SINK_HOSTS",
    "NET_EGRESS_MANIFEST",
    "NetEgressAttack",
    "PROC_SPAWN_MANIFEST",
    "ProcSpawnAttack",
    "SOLARWINDS_MANIFEST",
    "SafetyCheckError",
    "SafetyPreflight",
    "SolarWindsStyleAttack",
    "XZUTILS_MANIFEST",
    "XZUtilsStyleAttack",
]
