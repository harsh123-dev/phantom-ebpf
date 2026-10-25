"""
tests/fixtures/mapping_fixtures.py

SYNTHETIC ground-truth mapping fixtures for unit and integration testing.

Each fixture is clearly labelled SYNTHETIC.  None represents a real attack,
real experimental result, or real component identity.

15 fixture cases from the Part 3 specification §10:

  F01  Verified executable-to-component mapping (hash match)
  F02  Process inside known container, no package-level evidence
  F03  Package with known PURL, no defensible link to observed event
  F04  Two candidate packages that cannot be distinguished (ambiguous)
  F05  File whose hash matches a known component artifact
  F06  Process loading a library where the collector provides evidence
  F07  Missing image digest
  F08  Missing or malformed SBOM
  F09  Invalid or ambiguous PURL
  F10  Reused PID across separate process lifetimes
  F11  Duplicate delivery of the same event
  F12  Two distinct events with otherwise similar attributes
  F13  Event received out of timestamp order
  F14  Event associated with a known container but an unknown workload
  F15  SBOM component whose identity is not present in runtime evidence
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Optional

from app.domain.entities import BindingStatus, Component, ImageDigest, Purl, Sbom, SbomDigest, SbomSource, VerificationStatus
from app.domain.mapping.evidence import ContainerIdentity, ProcessIdentity, RuntimeEventRecord
from app.domain.mapping.resolver import MappingStatus, SbomIndex

# ---------------------------------------------------------------------------
# Shared identifiers (SYNTHETIC)
# ---------------------------------------------------------------------------

SYNTHETIC_TENANT_ID: str = "00000000-0000-0000-0000-000000000001"
SYNTHETIC_RUN_ID: str    = "run-synthetic-part3"

# Two distinct image digests.
IMAGE_DIGEST_A: str = "sha256:" + "a" * 64
IMAGE_DIGEST_B: str = "sha256:" + "b" * 64

# Three distinct PURLs.
PURL_REQUESTS: str   = "pkg:pypi/requests@2.31.0"
PURL_URLLIB3: str    = "pkg:pypi/urllib3@2.0.7"
PURL_CRYPTOGRAPHY: str = "pkg:pypi/cryptography@41.0.7"

# Two container IDs.
CONTAINER_ID_A: str = "aaaa" * 16  # 64 chars
CONTAINER_ID_B: str = "bbbb" * 16

# Timestamps.
T0: datetime = datetime(2000, 1, 1, 0, 0, 0, tzinfo=UTC)
T1: datetime = datetime(2000, 1, 1, 0, 1, 0, tzinfo=UTC)
T2: datetime = datetime(2000, 1, 1, 0, 2, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers to build SYNTHETIC components and SBOMs
# ---------------------------------------------------------------------------

def _make_sbom(
    sbom_id: uuid.UUID,
    tenant_id: str,
    image_digest: str,
) -> Sbom:
    """SYNTHETIC: Build a minimal Sbom entity for testing."""
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    return Sbom(
        sbom_id=sbom_id,
        tenant_id=uuid.UUID(tenant_id),
        image_digest=ImageDigest(image_digest),
        sbom_digest=SbomDigest.compute(doc),
        cyclonedx_document=doc,
        spec_version="1.5",
        source=SbomSource.SYFT,
        artifact_uri="s3://phantom-test/sbom.json",
        signature_bundle_uri=None,
        verification_status=VerificationStatus.VERIFIED,
        generated_at=T0,
        created_at=T0,
        purl_count=2,
    )


def _make_component(sbom_id: uuid.UUID, purl: str, name: str) -> Component:
    """SYNTHETIC: Build a minimal Component entity for testing."""
    return Component(
        component_id=uuid.uuid4(),
        sbom_id=sbom_id,
        purl=Purl(purl),
        name=name,
        version="1.0.0",
        component_type="library",
        binding_status=BindingStatus.AMBIGUOUS,
        binding_confidence=0.0,
        created_at=T0,
    )


def _make_process(
    container_id: str,
    tgid: int = 1000,
    pid_start_time_ns: int = 100_000_000_000,
    executable_path: Optional[str] = None,
    executable_hash: Optional[str] = None,
    ppid: Optional[int] = None,
    comm: Optional[str] = None,
) -> ProcessIdentity:
    """SYNTHETIC: Build a ProcessIdentity."""
    return ProcessIdentity(
        tgid=tgid,
        pid_start_time_ns=pid_start_time_ns,
        container_id=container_id,
        ppid=ppid,
        executable_path=executable_path,
        executable_hash=executable_hash,
        comm=comm or "python3",
    )


def _make_container(
    container_id: str,
    image_digest: Optional[str] = IMAGE_DIGEST_A,
    pod_uid: Optional[str] = None,
    namespace: Optional[str] = "phantom-eval",
) -> ContainerIdentity:
    """SYNTHETIC: Build a ContainerIdentity."""
    return ContainerIdentity(
        container_id=container_id,
        image_digest=image_digest,
        pod_uid=pod_uid or str(uuid.uuid4()),
        namespace=namespace,
    )


def _make_event(
    process: ProcessIdentity,
    container: Optional[ContainerIdentity] = None,
    resource_path: Optional[str] = None,
    resource_hash: Optional[str] = None,
    event_type: str = "file_open",
    event_time: datetime = T0,
    event_id: Optional[uuid.UUID] = None,
) -> RuntimeEventRecord:
    """SYNTHETIC: Build a RuntimeEventRecord."""
    return RuntimeEventRecord(
        event_id=event_id or uuid.uuid4(),
        event_type=event_type,
        event_time=event_time,
        process=process,
        container=container,
        resource_path=resource_path,
        resource_hash=resource_hash,
        tenant_id=SYNTHETIC_TENANT_ID,
        run_id=SYNTHETIC_RUN_ID,
    )


# ---------------------------------------------------------------------------
# SYNTHETIC SbomIndex for test fixture A (IMAGE_DIGEST_A)
# Has file inventory for PURL_REQUESTS and PURL_URLLIB3
# ---------------------------------------------------------------------------

_SBOM_ID_A: uuid.UUID = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001")
_SBOM_A: Sbom = _make_sbom(_SBOM_ID_A, SYNTHETIC_TENANT_ID, IMAGE_DIGEST_A)
_COMP_REQUESTS: Component = _make_component(_SBOM_ID_A, PURL_REQUESTS, "requests")
_COMP_URLLIB3: Component  = _make_component(_SBOM_ID_A, PURL_URLLIB3, "urllib3")

# File inventory: which files belong to which package (SYNTHETIC paths).
_FILE_INVENTORY_A: dict[str, list[str]] = {
    PURL_REQUESTS: [
        "/usr/lib/python3.11/site-packages/requests/__init__.py",
        "/usr/lib/python3.11/site-packages/requests/adapters.py",
        "/usr/lib/python3.11/site-packages/requests/api.py",
    ],
    PURL_URLLIB3: [
        "/usr/lib/python3.11/site-packages/urllib3/__init__.py",
        "/usr/lib/python3.11/site-packages/urllib3/connectionpool.py",
    ],
}

SBOM_INDEX_A: SbomIndex = SbomIndex.build(
    _SBOM_A,
    [_COMP_REQUESTS, _COMP_URLLIB3],
    file_inventory=_FILE_INVENTORY_A,
)


# ---------------------------------------------------------------------------
# F01 — Verified executable-to-component mapping (hash match)
# SYNTHETIC: executable_hash matches a known artifact hash.
# Expected status: INFERRED (VERIFIED requires EXECUTABLE_HASH tier, which
# is not yet collected by the eBPF agent; hash_candidates list will be empty).
# With path inventory match: status=INFERRED, selected_purl=PURL_REQUESTS.
# ---------------------------------------------------------------------------

@dataclass
class F01_VerifiedExecutableToComponent:
    """SYNTHETIC F01: File path in inventory → single component → INFERRED."""

    label: str = "F01_verified_exec_to_component"
    expected_status: MappingStatus = MappingStatus.INFERRED
    expected_purl: str = PURL_REQUESTS
    expected_candidate_count: int = 1

    process: ProcessIdentity = field(default_factory=lambda: _make_process(
        CONTAINER_ID_A,
        executable_path="/usr/lib/python3.11/site-packages/requests/__init__.py",
    ))
    container: ContainerIdentity = field(default_factory=lambda: _make_container(CONTAINER_ID_A))
    event: RuntimeEventRecord = field(init=False)
    sbom_index: SbomIndex = field(default_factory=lambda: SBOM_INDEX_A)
    ground_truth_purl: str = PURL_REQUESTS

    def __post_init__(self) -> None:
        self.event = _make_event(self.process, self.container,
                                 event_type="exec",
                                 resource_path="/usr/lib/python3.11/site-packages/requests/__init__.py")


# ---------------------------------------------------------------------------
# F02 — Process inside known container, no package-level evidence
# SYNTHETIC: container + image_digest known, but no file inventory and no
# executable path that matches any SBOM component.
# Expected status: UNRESOLVED.
# ---------------------------------------------------------------------------

@dataclass
class F02_ContainerKnownNoPackageEvidence:
    """SYNTHETIC F02: Image known, but no path/hash evidence → UNRESOLVED."""

    label: str = "F02_container_known_no_package_evidence"
    expected_status: MappingStatus = MappingStatus.UNRESOLVED
    expected_purl: str = "UNRESOLVED"
    expected_candidate_count: int = 0

    process: ProcessIdentity = field(default_factory=lambda: _make_process(
        CONTAINER_ID_A,
        executable_path="/usr/local/bin/custom-binary",  # not in inventory
    ))
    container: ContainerIdentity = field(default_factory=lambda: _make_container(CONTAINER_ID_A))
    event: RuntimeEventRecord = field(init=False)
    sbom_index: SbomIndex = field(default_factory=lambda: SBOM_INDEX_A)
    ground_truth_purl: str = "UNRESOLVED"  # no mapping expected

    def __post_init__(self) -> None:
        self.event = _make_event(self.process, self.container,
                                 event_type="exec",
                                 resource_path="/usr/local/bin/custom-binary")


# ---------------------------------------------------------------------------
# F03 — Package with known PURL, no defensible link to observed event
# SYNTHETIC: PURL_CRYPTOGRAPHY is in the SBOM but the event's file path
# is not in any component's inventory.
# Expected status: UNRESOLVED.
# ---------------------------------------------------------------------------

_SBOM_ID_F03: uuid.UUID = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000003")
_SBOM_F03: Sbom = _make_sbom(_SBOM_ID_F03, SYNTHETIC_TENANT_ID, IMAGE_DIGEST_A)
_COMP_CRYPTO: Component = _make_component(_SBOM_ID_F03, PURL_CRYPTOGRAPHY, "cryptography")

SBOM_INDEX_F03: SbomIndex = SbomIndex.build(
    _SBOM_F03,
    [_COMP_CRYPTO],
    file_inventory={
        PURL_CRYPTOGRAPHY: [
            "/usr/lib/python3.11/site-packages/cryptography/__init__.py",
        ]
    },
)

@dataclass
class F03_PurlKnownNoLinkToEvent:
    """SYNTHETIC F03: PURL in SBOM but event path matches nothing → UNRESOLVED."""

    label: str = "F03_purl_known_no_link_to_event"
    expected_status: MappingStatus = MappingStatus.UNRESOLVED
    expected_purl: str = "UNRESOLVED"
    expected_candidate_count: int = 0

    process: ProcessIdentity = field(default_factory=lambda: _make_process(
        CONTAINER_ID_A,
        executable_path="/usr/bin/unrelated-tool",
    ))
    container: ContainerIdentity = field(default_factory=lambda: _make_container(CONTAINER_ID_A))
    event: RuntimeEventRecord = field(init=False)
    sbom_index: SbomIndex = field(default_factory=lambda: SBOM_INDEX_F03)
    ground_truth_purl: str = "UNRESOLVED"

    def __post_init__(self) -> None:
        self.event = _make_event(self.process, self.container,
                                 event_type="exec",
                                 resource_path="/usr/bin/unrelated-tool")


# ---------------------------------------------------------------------------
# F04 — Two candidate packages that cannot be distinguished (ambiguous)
# SYNTHETIC: resource path prefix matches both PURL_REQUESTS and PURL_URLLIB3.
# (Both share /usr/lib/python3.11/site-packages/ prefix.)
# Expected status: AMBIGUOUS, candidate_purls has both PURLs.
# ---------------------------------------------------------------------------

@dataclass
class F04_AmbiguousTwoCandidates:
    """SYNTHETIC F04: Path prefix matches two packages → AMBIGUOUS."""

    label: str = "F04_ambiguous_two_candidates"
    expected_status: MappingStatus = MappingStatus.AMBIGUOUS
    expected_purl: str = "UNRESOLVED"  # no single selected
    expected_candidate_count: int = 2

    process: ProcessIdentity = field(default_factory=lambda: _make_process(
        CONTAINER_ID_A,
        executable_path=None,  # no exec path in file inventory
    ))
    container: ContainerIdentity = field(default_factory=lambda: _make_container(CONTAINER_ID_A))
    event: RuntimeEventRecord = field(init=False)
    sbom_index: SbomIndex = field(default_factory=lambda: SBOM_INDEX_A)
    ground_truth_purl: str = PURL_REQUESTS  # one of the two (for candidate-set accuracy)

    def __post_init__(self) -> None:
        # Access a shared prefix path — both packages live under
        # /usr/lib/python3.11/site-packages/, so prefix heuristic hits both.
        self.event = _make_event(
            self.process, self.container,
            event_type="file_open",
            resource_path="/usr/lib/python3.11/site-packages/unknown_file.py",
        )


# ---------------------------------------------------------------------------
# F05 — File whose hash matches a known component artifact
# SYNTHETIC: resource_hash would match PURL_URLLIB3 (in real implementation
# this would use EXECUTABLE_HASH tier). Currently the eBPF agent does not
# collect hashes, so this fixture documents the expected behavior when
# the collector adds hash support.
# Expected status: UNRESOLVED (hash tier not yet active).
# ---------------------------------------------------------------------------

@dataclass
class F05_FileHashMatchesComponent:
    """SYNTHETIC F05: resource_hash set, but hash tier not yet active → UNRESOLVED."""

    label: str = "F05_file_hash_matches_component"
    expected_status: MappingStatus = MappingStatus.UNRESOLVED
    expected_purl: str = "UNRESOLVED"
    expected_candidate_count: int = 0

    process: ProcessIdentity = field(default_factory=lambda: _make_process(
        CONTAINER_ID_A,
        executable_path="/no/inventory/match",
        executable_hash="sha256:" + "f" * 64,
    ))
    container: ContainerIdentity = field(default_factory=lambda: _make_container(CONTAINER_ID_A))
    event: RuntimeEventRecord = field(init=False)
    sbom_index: SbomIndex = field(default_factory=lambda: SBOM_INDEX_A)
    # Ground truth: if hash tier were active, this would resolve to PURL_URLLIB3.
    ground_truth_purl: str = PURL_URLLIB3

    def __post_init__(self) -> None:
        self.event = _make_event(
            self.process, self.container,
            event_type="file_open",
            resource_path="/no/inventory/match",
            resource_hash="sha256:" + "f" * 64,
        )


# ---------------------------------------------------------------------------
# F06 — Process loading a library where collector provides evidence
# SYNTHETIC: Library file path matches an SBOM file inventory entry.
# Expected status: INFERRED (file_inventory tier).
# ---------------------------------------------------------------------------

@dataclass
class F06_LibraryLoadWithInventoryEvidence:
    """SYNTHETIC F06: Library path in file inventory → INFERRED."""

    label: str = "F06_library_load_with_inventory_evidence"
    expected_status: MappingStatus = MappingStatus.INFERRED
    expected_purl: str = PURL_URLLIB3
    expected_candidate_count: int = 1

    process: ProcessIdentity = field(default_factory=lambda: _make_process(
        CONTAINER_ID_A,
        executable_path="/usr/bin/python3",  # interpreter — will not match inventory
    ))
    container: ContainerIdentity = field(default_factory=lambda: _make_container(CONTAINER_ID_A))
    event: RuntimeEventRecord = field(init=False)
    sbom_index: SbomIndex = field(default_factory=lambda: SBOM_INDEX_A)
    ground_truth_purl: str = PURL_URLLIB3

    def __post_init__(self) -> None:
        self.event = _make_event(
            self.process, self.container,
            event_type="file_open",
            resource_path="/usr/lib/python3.11/site-packages/urllib3/connectionpool.py",
        )


# ---------------------------------------------------------------------------
# F07 — Missing image digest
# SYNTHETIC: container exists but image_digest is None.
# Expected status: UNRESOLVED.
# ---------------------------------------------------------------------------

@dataclass
class F07_MissingImageDigest:
    """SYNTHETIC F07: image_digest is None → UNRESOLVED (no SBOM lookup)."""

    label: str = "F07_missing_image_digest"
    expected_status: MappingStatus = MappingStatus.UNRESOLVED
    expected_purl: str = "UNRESOLVED"
    expected_candidate_count: int = 0

    process: ProcessIdentity = field(default_factory=lambda: _make_process(CONTAINER_ID_A))
    container: ContainerIdentity = field(default_factory=lambda: _make_container(
        CONTAINER_ID_A, image_digest=None
    ))
    event: RuntimeEventRecord = field(init=False)
    sbom_index: SbomIndex = field(default_factory=lambda: SBOM_INDEX_A)
    ground_truth_purl: str = "UNRESOLVED"

    def __post_init__(self) -> None:
        self.event = _make_event(self.process, self.container, event_type="exec")


# ---------------------------------------------------------------------------
# F08 — Missing SBOM (no index entry for the image digest)
# SYNTHETIC: image_digest is valid but no SbomIndex was loaded for it.
# Expected status: UNRESOLVED.
# ---------------------------------------------------------------------------

@dataclass
class F08_MissingSbom:
    """SYNTHETIC F08: SBOM not indexed for this image → UNRESOLVED."""

    label: str = "F08_missing_sbom"
    expected_status: MappingStatus = MappingStatus.UNRESOLVED
    expected_purl: str = "UNRESOLVED"
    expected_candidate_count: int = 0

    process: ProcessIdentity = field(default_factory=lambda: _make_process(CONTAINER_ID_B))
    container: ContainerIdentity = field(default_factory=lambda: _make_container(
        CONTAINER_ID_B, image_digest=IMAGE_DIGEST_B  # no index for B
    ))
    event: RuntimeEventRecord = field(init=False)
    sbom_index: SbomIndex = field(default_factory=lambda: SBOM_INDEX_A)  # only A indexed
    ground_truth_purl: str = "UNRESOLVED"

    def __post_init__(self) -> None:
        self.event = _make_event(self.process, self.container, event_type="exec")


# ---------------------------------------------------------------------------
# F09 — Invalid container_id (empty) → INVALID
# SYNTHETIC: process.container_id is empty string.
# Expected status: INVALID.
# ---------------------------------------------------------------------------

@dataclass
class F09_InvalidContainerId:
    """SYNTHETIC F09: empty container_id → INVALID."""

    label: str = "F09_invalid_container_id"
    expected_status: MappingStatus = MappingStatus.INVALID
    expected_purl: str = "UNRESOLVED"
    expected_candidate_count: int = 0

    process: ProcessIdentity = field(default_factory=lambda: _make_process(
        container_id=""  # invalid
    ))
    container: ContainerIdentity = field(default_factory=lambda: _make_container(CONTAINER_ID_A))
    event: RuntimeEventRecord = field(init=False)
    sbom_index: SbomIndex = field(default_factory=lambda: SBOM_INDEX_A)
    ground_truth_purl: str = "UNRESOLVED"

    def __post_init__(self) -> None:
        self.event = _make_event(self.process, self.container, event_type="exec")


# ---------------------------------------------------------------------------
# F10 — Reused PID across separate process lifetimes
# SYNTHETIC: Two events with the same (tgid, container_id) but different
# pid_start_time_ns represent distinct processes.
# Expected: both events get independent, separate MappingResults.
# ---------------------------------------------------------------------------

@dataclass
class F10_ReusedPid:
    """SYNTHETIC F10: Same PID reused — two distinct process identities."""

    label: str = "F10_reused_pid"
    # First process lifetime: maps to PURL_REQUESTS
    process_a: ProcessIdentity = field(default_factory=lambda: _make_process(
        CONTAINER_ID_A, tgid=500, pid_start_time_ns=100_000,
        executable_path="/usr/lib/python3.11/site-packages/requests/__init__.py",
    ))
    # Second process lifetime: same PID, different start time → different identity
    process_b: ProcessIdentity = field(default_factory=lambda: _make_process(
        CONTAINER_ID_A, tgid=500, pid_start_time_ns=200_000,
        executable_path="/usr/lib/python3.11/site-packages/urllib3/__init__.py",
    ))
    container: ContainerIdentity = field(default_factory=lambda: _make_container(CONTAINER_ID_A))
    event_a: RuntimeEventRecord = field(init=False)
    event_b: RuntimeEventRecord = field(init=False)
    sbom_index: SbomIndex = field(default_factory=lambda: SBOM_INDEX_A)
    expected_status_a: MappingStatus = MappingStatus.INFERRED
    expected_purl_a: str = PURL_REQUESTS
    expected_status_b: MappingStatus = MappingStatus.INFERRED
    expected_purl_b: str = PURL_URLLIB3

    def __post_init__(self) -> None:
        self.event_a = _make_event(self.process_a, self.container, event_type="exec",
                                   resource_path="/usr/lib/python3.11/site-packages/requests/__init__.py",
                                   event_time=T0)
        self.event_b = _make_event(self.process_b, self.container, event_type="exec",
                                   resource_path="/usr/lib/python3.11/site-packages/urllib3/__init__.py",
                                   event_time=T1)


# ---------------------------------------------------------------------------
# F11 — Duplicate delivery of the same event
# SYNTHETIC: Same event_id delivered twice. The BDG deduplicates; the mapper
# produces the same MappingResult both times (idempotent by event_id).
# ---------------------------------------------------------------------------

@dataclass
class F11_DuplicateEventDelivery:
    """SYNTHETIC F11: Same event_id delivered twice → identical MappingResults."""

    label: str = "F11_duplicate_event_delivery"
    shared_event_id: uuid.UUID = field(default_factory=uuid.uuid4)
    process: ProcessIdentity = field(default_factory=lambda: _make_process(
        CONTAINER_ID_A,
        executable_path="/usr/lib/python3.11/site-packages/requests/__init__.py",
    ))
    container: ContainerIdentity = field(default_factory=lambda: _make_container(CONTAINER_ID_A))
    event_first: RuntimeEventRecord = field(init=False)
    event_second: RuntimeEventRecord = field(init=False)  # same UUID
    sbom_index: SbomIndex = field(default_factory=lambda: SBOM_INDEX_A)
    expected_status: MappingStatus = MappingStatus.INFERRED
    expected_purl: str = PURL_REQUESTS

    def __post_init__(self) -> None:
        self.event_first = _make_event(
            self.process, self.container, event_type="exec",
            event_id=self.shared_event_id, event_time=T0,
        )
        self.event_second = _make_event(
            self.process, self.container, event_type="exec",
            event_id=self.shared_event_id, event_time=T0,  # same UUID, same time
        )


# ---------------------------------------------------------------------------
# F12 — Two distinct events with otherwise similar attributes
# SYNTHETIC: Same process, same type, different resource_path → different
# component resolved. They must NOT be collapsed.
# ---------------------------------------------------------------------------

@dataclass
class F12_TwoDistinctSimilarEvents:
    """SYNTHETIC F12: Same process, same type, different paths → two separate results."""

    label: str = "F12_two_distinct_similar_events"
    process: ProcessIdentity = field(default_factory=lambda: _make_process(CONTAINER_ID_A))
    container: ContainerIdentity = field(default_factory=lambda: _make_container(CONTAINER_ID_A))
    event_a: RuntimeEventRecord = field(init=False)
    event_b: RuntimeEventRecord = field(init=False)
    sbom_index: SbomIndex = field(default_factory=lambda: SBOM_INDEX_A)
    expected_status_a: MappingStatus = MappingStatus.INFERRED
    expected_purl_a: str = PURL_REQUESTS
    expected_status_b: MappingStatus = MappingStatus.INFERRED
    expected_purl_b: str = PURL_URLLIB3

    def __post_init__(self) -> None:
        self.event_a = _make_event(
            self.process, self.container, event_type="file_open",
            resource_path="/usr/lib/python3.11/site-packages/requests/api.py",
            event_time=T0,
        )
        self.event_b = _make_event(
            self.process, self.container, event_type="file_open",
            resource_path="/usr/lib/python3.11/site-packages/urllib3/connectionpool.py",
            event_time=T1,
        )


# ---------------------------------------------------------------------------
# F13 — Event received out of timestamp order
# SYNTHETIC: event_b has an earlier timestamp than event_a but arrives second.
# The mapper is stateless (no window logic) — both should resolve correctly
# regardless of arrival order.
# ---------------------------------------------------------------------------

@dataclass
class F13_OutOfOrderTimestamp:
    """SYNTHETIC F13: Out-of-order event timestamps — both resolve independently."""

    label: str = "F13_out_of_order_timestamp"
    process: ProcessIdentity = field(default_factory=lambda: _make_process(CONTAINER_ID_A))
    container: ContainerIdentity = field(default_factory=lambda: _make_container(CONTAINER_ID_A))
    sbom_index: SbomIndex = field(default_factory=lambda: SBOM_INDEX_A)
    # event_late arrives second but has an earlier event_time
    event_early_time: RuntimeEventRecord = field(init=False)
    event_late_time: RuntimeEventRecord = field(init=False)
    expected_status: MappingStatus = MappingStatus.INFERRED
    expected_purl: str = PURL_REQUESTS

    def __post_init__(self) -> None:
        self.event_early_time = _make_event(
            self.process, self.container, event_type="file_open",
            resource_path="/usr/lib/python3.11/site-packages/requests/api.py",
            event_time=T2,  # later timestamp, arrives first
        )
        self.event_late_time = _make_event(
            self.process, self.container, event_type="file_open",
            resource_path="/usr/lib/python3.11/site-packages/requests/api.py",
            event_time=T0,  # earlier timestamp, arrives second
        )


# ---------------------------------------------------------------------------
# F14 — Event associated with a known container but an unknown workload
# SYNTHETIC: container_id + image_digest known; pod_uid is None.
# Expected: INFERRED (workload info is not required for component mapping).
# ---------------------------------------------------------------------------

@dataclass
class F14_KnownContainerUnknownWorkload:
    """SYNTHETIC F14: container known, workload unknown → INFERRED still possible."""

    label: str = "F14_known_container_unknown_workload"
    expected_status: MappingStatus = MappingStatus.INFERRED
    expected_purl: str = PURL_REQUESTS
    expected_candidate_count: int = 1

    process: ProcessIdentity = field(default_factory=lambda: _make_process(
        CONTAINER_ID_A,
        executable_path="/usr/lib/python3.11/site-packages/requests/__init__.py",
    ))
    container: ContainerIdentity = field(default_factory=lambda: ContainerIdentity(
        container_id=CONTAINER_ID_A,
        image_digest=IMAGE_DIGEST_A,
        pod_uid=None,        # unknown workload
        namespace=None,
    ))
    event: RuntimeEventRecord = field(init=False)
    sbom_index: SbomIndex = field(default_factory=lambda: SBOM_INDEX_A)
    ground_truth_purl: str = PURL_REQUESTS

    def __post_init__(self) -> None:
        self.event = _make_event(self.process, self.container, event_type="exec",
                                 resource_path="/usr/lib/python3.11/site-packages/requests/__init__.py")


# ---------------------------------------------------------------------------
# F15 — SBOM component with no matching runtime evidence
# SYNTHETIC: PURL_CRYPTOGRAPHY is in the SBOM index, but no event touches
# any of its files. The component exists but cannot be attributed.
# Expected: the mapping resolver returns UNRESOLVED for the event (not crypto).
# ---------------------------------------------------------------------------

@dataclass
class F15_SbomComponentNoRuntimeEvidence:
    """SYNTHETIC F15: Component in SBOM but no event matches it → UNRESOLVED."""

    label: str = "F15_sbom_component_no_runtime_evidence"
    expected_status: MappingStatus = MappingStatus.UNRESOLVED
    expected_purl: str = "UNRESOLVED"
    expected_candidate_count: int = 0

    _SBOM_ID_F15: uuid.UUID = field(default_factory=lambda: uuid.UUID("ffffffff-0000-0000-0000-000000000015"))

    process: ProcessIdentity = field(default_factory=lambda: _make_process(
        CONTAINER_ID_A,
        executable_path="/usr/bin/completely-unrelated",
    ))
    container: ContainerIdentity = field(default_factory=lambda: _make_container(CONTAINER_ID_A))
    event: RuntimeEventRecord = field(init=False)
    sbom_index: SbomIndex = field(init=False)
    ground_truth_purl: str = "UNRESOLVED"

    def __post_init__(self) -> None:
        sbom_id = uuid.UUID("ffffffff-0000-0000-0000-000000000015")
        sbom = _make_sbom(sbom_id, SYNTHETIC_TENANT_ID, IMAGE_DIGEST_A)
        comp = _make_component(sbom_id, PURL_CRYPTOGRAPHY, "cryptography")
        self.sbom_index = SbomIndex.build(
            sbom, [comp],
            file_inventory={
                PURL_CRYPTOGRAPHY: [
                    "/usr/lib/python3.11/site-packages/cryptography/__init__.py",
                ]
            },
        )
        self.event = _make_event(
            self.process, self.container,
            event_type="exec",
            resource_path="/usr/bin/completely-unrelated",
        )
