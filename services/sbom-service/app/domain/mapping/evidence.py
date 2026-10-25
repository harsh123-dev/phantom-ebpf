"""
services/sbom-service/app/domain/mapping/evidence.py

Evidence types for the runtime-to-SBOM component mapping resolver.

These types capture *what we know and how we know it* for each mapping
attempt.  They are pure domain value objects with no framework dependencies.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Evidence source categories
# ---------------------------------------------------------------------------


class EvidenceKind(str, Enum):
    """Category of evidence used to justify a mapping.

    Members:
        IMAGE_DIGEST: The container image digest ties the event to a specific
            image for which an SBOM exists.
        CONTAINER_ID: The container ID resolves the event to a specific running
            container instance and its associated image.
        WORKLOAD_SBOM: The workload (pod/deployment) is bound to an SBOM via
            admission control or label annotation.
        EXECUTABLE_PATH: The observed executable path matches a file listed in
            an SBOM component's file inventory.
        EXECUTABLE_HASH: The sha256 hash of the observed executable matches a
            known artifact hash in the SBOM component.
        PURL_DIRECT: The PURL is directly recorded on the runtime event (e.g.
            injected by the build pipeline).
        FILE_INVENTORY: The observed file path appears in the SBOM's file
            component inventory.
        PROCESS_LINEAGE: The process is a child of a process already mapped to
            a component.
        SBOM_DEPENDENCY: The component is an explicit dependency of another
            resolved component in the same SBOM.
        HEURISTIC_PATH_PREFIX: The file path prefix matches a known package
            install location (e.g. /usr/lib/python3.11/site-packages/requests/).
            This is the weakest form of evidence.
    """

    IMAGE_DIGEST = "image_digest"
    CONTAINER_ID = "container_id"
    WORKLOAD_SBOM = "workload_sbom"
    EXECUTABLE_PATH = "executable_path"
    EXECUTABLE_HASH = "executable_hash"
    PURL_DIRECT = "purl_direct"
    FILE_INVENTORY = "file_inventory"
    PROCESS_LINEAGE = "process_lineage"
    SBOM_DEPENDENCY = "sbom_dependency"
    HEURISTIC_PATH_PREFIX = "heuristic_path_prefix"


@dataclass(frozen=True)
class EvidenceSource:
    """A single piece of evidence contributing to a mapping decision.

    Attributes:
        kind: Category of this evidence piece.
        value: The specific value (e.g. path, hash, digest string).
        description: Human-readable explanation of how this evidence was
            used.
        confidence_contribution: How much this evidence contributes to the
            overall mapping confidence [0.0, 1.0].
    """

    kind: EvidenceKind
    value: str
    description: str
    confidence_contribution: float

    def __post_init__(self) -> None:
        """Validate confidence_contribution is in [0, 1]."""
        if not (0.0 <= self.confidence_contribution <= 1.0):
            raise ValueError(
                f"confidence_contribution must be in [0, 1], "
                f"got {self.confidence_contribution}"
            )


# ---------------------------------------------------------------------------
# Process identity
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProcessIdentity:
    """Stable identity for a running process, disambiguating PID reuse.

    A (tgid, pid_start_time_ns) pair is unique within a container for the
    lifetime of the container. Across containers, container_id is the
    additional discriminator. PID alone is NOT a stable identity.

    Attributes:
        tgid: Thread group ID (essentially the process ID for single-threaded
            processes).
        pid_start_time_ns: Kernel process start time in nanoseconds.
            Disambiguates PID reuse after process termination.
        container_id: Container ID string; distinguishes same-pid processes
            in different containers.
        ppid: Parent process TGID, if known.
        executable_path: Path of the executed binary, if available.
        executable_hash: sha256 of the executable content, if collected.
        comm: Process command name (comm field from the kernel).
        uid: User ID of the process.
    """

    tgid: int
    pid_start_time_ns: int
    container_id: str
    ppid: Optional[int] = None
    executable_path: Optional[str] = None
    executable_hash: Optional[str] = None
    comm: Optional[str] = None
    uid: Optional[int] = None

    @property
    def stable_key(self) -> tuple[str, int, int]:
        """Return a stable, PID-reuse-safe identity key.

        Returns:
            Tuple of (container_id, tgid, pid_start_time_ns).
        """
        return (self.container_id, self.tgid, self.pid_start_time_ns)

    @property
    def is_interpreter(self) -> bool:
        """True if this process is a known interpreter (Python, JVM, Node.js, …).

        Interpreters do not identify the specific language package responsible
        for an operation — only the runtime environment.

        The check is performed on the **basename** of the executable path only.
        Paths like ``/usr/lib/python3.11/site-packages/requests/__init__.py``
        contain "python" as a directory component but are NOT interpreters;
        only binaries named ``python3``, ``java``, ``node``, etc. qualify.

        Returns:
            True if the basename of the executable matches a known interpreter.
        """
        if not self.executable_path:
            return False
        basename = self.executable_path.rstrip("/").split("/")[-1].lower()
        return any(
            basename.startswith(pattern)
            for pattern in (
                "python", "python3", "python2",
                "java", "javac",
                "node", "nodejs",
                "ruby", "perl", "php",
                "dotnet", "mono",
            )
        )


# ---------------------------------------------------------------------------
# Container identity
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContainerIdentity:
    """Identity of a running container instance.

    Attributes:
        container_id: Runtime container ID (e.g. CRI-O or containerd ID).
        image_digest: sha256 digest of the container image, if available.
            This is the primary key for SBOM lookup.
        pod_uid: Kubernetes pod UID, if available.
        namespace: Kubernetes namespace.
        workload_name: Deployment/StatefulSet/DaemonSet name, if resolved.
        node_name: Kubernetes node name, if available.
    """

    container_id: str
    image_digest: Optional[str] = None
    pod_uid: Optional[str] = None
    namespace: Optional[str] = None
    workload_name: Optional[str] = None
    node_name: Optional[str] = None

    @property
    def has_image_digest(self) -> bool:
        """True if a validated image digest is available.

        Returns:
            True when image_digest is set and non-empty.
        """
        return bool(self.image_digest)


# ---------------------------------------------------------------------------
# Runtime event for mapping
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuntimeEventRecord:
    """Minimal runtime event fields needed for component mapping.

    This is NOT a copy of the full eBPF event — only the fields the
    mapper needs.  The mapper does not need to know about KL scores or
    BDG weights.

    Attributes:
        event_id: Unique event UUID (used for idempotency and audit).
        event_type: Normalised event type string (exec, file_open, …).
        event_time: UTC timestamp of the event.
        process: Process identity of the observed process.
        container: Container identity, if resolved.
        resource_path: Observed file or network resource, if applicable.
        resource_hash: sha256 of the accessed file content, if collected.
        tenant_id: Tenant UUID string.
        run_id: Experiment run ID, if in evaluation context.
    """

    event_id: uuid.UUID
    event_type: str
    event_time: datetime
    process: ProcessIdentity
    container: Optional[ContainerIdentity] = None
    resource_path: Optional[str] = None
    resource_hash: Optional[str] = None
    tenant_id: str = ""
    run_id: str = ""
