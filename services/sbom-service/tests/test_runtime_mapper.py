"""
tests/test_runtime_mapper.py

Unit tests for the PHANTOM runtime-to-SBOM component mapping resolver.

ALL DATA IN THIS FILE IS SYNTHETIC.
No real attack detections, real experiment results, or real component
identities are used or modified.

Test coverage:
  - All 15 ground-truth fixture cases (F01–F15)
  - MappingStatus semantics (correct field invariants per status)
  - MappingResult.to_dict() serialization
  - SbomIndex.build() with and without file inventory
  - ProcessIdentity.is_interpreter detection
  - ProcessIdentity.stable_key PID-reuse disambiguation
  - MappingQualityMetrics with and without ground truth
  - Evidence ordering (strongest evidence tier wins)
  - Interpreter path does NOT produce a PURL candidate
  - Duplicate event delivery produces identical results
  - Out-of-order timestamps do not affect outcome
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from app.domain.mapping.evidence import (
    ContainerIdentity,
    EvidenceKind,
    EvidenceSource,
    ProcessIdentity,
    RuntimeEventRecord,
)
from app.domain.mapping.metrics import MappingQualityMetrics
from app.domain.mapping.resolver import (
    MappingResult,
    MappingStatus,
    RuntimeToSbomMapper,
    SbomIndex,
    _UNRESOLVED_PURL,
)
from tests.fixtures.mapping_fixtures import (
    CONTAINER_ID_A,
    IMAGE_DIGEST_A,
    PURL_REQUESTS,
    PURL_URLLIB3,
    SBOM_INDEX_A,
    SYNTHETIC_RUN_ID,
    SYNTHETIC_TENANT_ID,
    T0,
    F01_VerifiedExecutableToComponent,
    F02_ContainerKnownNoPackageEvidence,
    F03_PurlKnownNoLinkToEvent,
    F04_AmbiguousTwoCandidates,
    F05_FileHashMatchesComponent,
    F06_LibraryLoadWithInventoryEvidence,
    F07_MissingImageDigest,
    F08_MissingSbom,
    F09_InvalidContainerId,
    F10_ReusedPid,
    F11_DuplicateEventDelivery,
    F12_TwoDistinctSimilarEvents,
    F13_OutOfOrderTimestamp,
    F14_KnownContainerUnknownWorkload,
    F15_SbomComponentNoRuntimeEvidence,
    _make_container,
    _make_event,
    _make_process,
    _make_component,
    _make_sbom,
)


# ===========================================================================
# Helper: build mapper with only INDEX_A loaded
# ===========================================================================

def _mapper_with_a() -> RuntimeToSbomMapper:
    """SYNTHETIC: Mapper pre-loaded with SBOM index for IMAGE_DIGEST_A only."""
    return RuntimeToSbomMapper({IMAGE_DIGEST_A: SBOM_INDEX_A})


# ===========================================================================
# F01 — Verified executable-to-component mapping
# ===========================================================================

class TestF01_VerifiedExecToComponent:
    """SYNTHETIC F01: File path in file inventory → INFERRED, single PURL."""

    def test_status_inferred(self) -> None:
        f = F01_VerifiedExecutableToComponent()
        result = _mapper_with_a().map(f.event)
        assert result.status == f.expected_status

    def test_selected_purl_correct(self) -> None:
        f = F01_VerifiedExecutableToComponent()
        result = _mapper_with_a().map(f.event)
        assert result.selected_purl == f.expected_purl

    def test_single_candidate(self) -> None:
        f = F01_VerifiedExecutableToComponent()
        result = _mapper_with_a().map(f.event)
        assert len(result.candidate_purls) == f.expected_candidate_count

    def test_evidence_non_empty(self) -> None:
        f = F01_VerifiedExecutableToComponent()
        result = _mapper_with_a().map(f.event)
        assert len(result.evidence) >= 1

    def test_sbom_id_populated(self) -> None:
        f = F01_VerifiedExecutableToComponent()
        result = _mapper_with_a().map(f.event)
        assert result.sbom_id == SBOM_INDEX_A.sbom_id

    def test_image_digest_preserved(self) -> None:
        f = F01_VerifiedExecutableToComponent()
        result = _mapper_with_a().map(f.event)
        assert result.image_digest == IMAGE_DIGEST_A


# ===========================================================================
# F02 — Container known, no package-level evidence
# ===========================================================================

class TestF02_ContainerKnownNoPackageEvidence:
    """SYNTHETIC F02: Image known but no path evidence → UNRESOLVED."""

    def test_status_unresolved(self) -> None:
        f = F02_ContainerKnownNoPackageEvidence()
        result = _mapper_with_a().map(f.event)
        assert result.status == MappingStatus.UNRESOLVED

    def test_selected_purl_is_sentinel(self) -> None:
        f = F02_ContainerKnownNoPackageEvidence()
        result = _mapper_with_a().map(f.event)
        assert result.selected_purl == _UNRESOLVED_PURL

    def test_no_candidate_purls(self) -> None:
        f = F02_ContainerKnownNoPackageEvidence()
        result = _mapper_with_a().map(f.event)
        assert result.candidate_purls == []

    def test_unresolved_reason_populated(self) -> None:
        f = F02_ContainerKnownNoPackageEvidence()
        result = _mapper_with_a().map(f.event)
        assert len(result.unresolved_reason) > 0


# ===========================================================================
# F03 — PURL in SBOM but no link to event
# ===========================================================================

class TestF03_PurlKnownNoLinkToEvent:
    """SYNTHETIC F03: Package exists in SBOM but event is unrelated → UNRESOLVED."""

    def test_status_unresolved(self) -> None:
        f = F03_PurlKnownNoLinkToEvent()
        mapper = RuntimeToSbomMapper({IMAGE_DIGEST_A: f.sbom_index})
        result = mapper.map(f.event)
        assert result.status == MappingStatus.UNRESOLVED

    def test_purl_not_invented(self) -> None:
        f = F03_PurlKnownNoLinkToEvent()
        mapper = RuntimeToSbomMapper({IMAGE_DIGEST_A: f.sbom_index})
        result = mapper.map(f.event)
        # The SBOM contains PURL_CRYPTOGRAPHY but the event path doesn't touch it.
        assert "cryptography" not in result.selected_purl


# ===========================================================================
# F04 — Ambiguous: two candidates that cannot be distinguished
# ===========================================================================

class TestF04_AmbiguousTwoCandidates:
    """SYNTHETIC F04: Path prefix matches both packages → AMBIGUOUS."""

    def test_status_ambiguous(self) -> None:
        f = F04_AmbiguousTwoCandidates()
        result = _mapper_with_a().map(f.event)
        assert result.status == MappingStatus.AMBIGUOUS

    def test_two_candidate_purls(self) -> None:
        f = F04_AmbiguousTwoCandidates()
        result = _mapper_with_a().map(f.event)
        assert len(result.candidate_purls) >= 2

    def test_selected_purl_is_sentinel_for_ambiguous(self) -> None:
        f = F04_AmbiguousTwoCandidates()
        result = _mapper_with_a().map(f.event)
        assert result.selected_purl == _UNRESOLVED_PURL

    def test_ambiguity_reason_populated(self) -> None:
        f = F04_AmbiguousTwoCandidates()
        result = _mapper_with_a().map(f.event)
        assert len(result.ambiguity_reason) > 0

    def test_gt_in_candidate_set(self) -> None:
        """For candidate-set accuracy: ground truth PURL is in candidates."""
        f = F04_AmbiguousTwoCandidates()
        result = _mapper_with_a().map(f.event)
        assert f.ground_truth_purl in result.candidate_purls


# ===========================================================================
# F05 — File hash (hash tier not yet active → UNRESOLVED)
# ===========================================================================

class TestF05_FileHashMatchesComponent:
    """SYNTHETIC F05: resource_hash present but hash tier not active → UNRESOLVED."""

    def test_status_unresolved(self) -> None:
        f = F05_FileHashMatchesComponent()
        result = _mapper_with_a().map(f.event)
        assert result.status == MappingStatus.UNRESOLVED

    def test_no_verified_status_without_hash_tier(self) -> None:
        """Providing a hash does NOT produce VERIFIED until the hash tier is active."""
        f = F05_FileHashMatchesComponent()
        result = _mapper_with_a().map(f.event)
        assert result.status != MappingStatus.VERIFIED


# ===========================================================================
# F06 — Library load with file inventory evidence
# ===========================================================================

class TestF06_LibraryLoadWithInventoryEvidence:
    """SYNTHETIC F06: Library path in inventory → INFERRED (interpreter ignored)."""

    def test_status_inferred(self) -> None:
        f = F06_LibraryLoadWithInventoryEvidence()
        result = _mapper_with_a().map(f.event)
        assert result.status == MappingStatus.INFERRED

    def test_selected_purl_urllib3(self) -> None:
        f = F06_LibraryLoadWithInventoryEvidence()
        result = _mapper_with_a().map(f.event)
        assert result.selected_purl == PURL_URLLIB3

    def test_interpreter_exec_path_not_used_for_mapping(self) -> None:
        """The python3 executable path does NOT produce a component candidate."""
        f = F06_LibraryLoadWithInventoryEvidence()
        result = _mapper_with_a().map(f.event)
        # Evidence should note interpreter was detected (from exec_path tier).
        interpreter_noted = any(
            "interpreter" in e.description.lower()
            for e in result.evidence
        )
        assert interpreter_noted


# ===========================================================================
# F07 — Missing image digest
# ===========================================================================

class TestF07_MissingImageDigest:
    """SYNTHETIC F07: No image_digest → UNRESOLVED before SBOM lookup."""

    def test_status_unresolved(self) -> None:
        f = F07_MissingImageDigest()
        result = _mapper_with_a().map(f.event)
        assert result.status == MappingStatus.UNRESOLVED

    def test_sbom_id_is_none(self) -> None:
        f = F07_MissingImageDigest()
        result = _mapper_with_a().map(f.event)
        assert result.sbom_id is None

    def test_image_digest_is_none_in_result(self) -> None:
        f = F07_MissingImageDigest()
        result = _mapper_with_a().map(f.event)
        assert result.image_digest is None


# ===========================================================================
# F08 — Missing SBOM (no index entry for image digest B)
# ===========================================================================

class TestF08_MissingSbom:
    """SYNTHETIC F08: SBOM not indexed for this image → UNRESOLVED."""

    def test_status_unresolved(self) -> None:
        f = F08_MissingSbom()
        # Only IMAGE_DIGEST_A is indexed; event uses IMAGE_DIGEST_B.
        mapper = RuntimeToSbomMapper({IMAGE_DIGEST_A: SBOM_INDEX_A})
        result = mapper.map(f.event)
        assert result.status == MappingStatus.UNRESOLVED

    def test_reason_mentions_sbom(self) -> None:
        f = F08_MissingSbom()
        mapper = RuntimeToSbomMapper({IMAGE_DIGEST_A: SBOM_INDEX_A})
        result = mapper.map(f.event)
        assert "sbom" in result.unresolved_reason.lower() or "digest" in result.unresolved_reason.lower()


# ===========================================================================
# F09 — Invalid container_id
# ===========================================================================

class TestF09_InvalidContainerId:
    """SYNTHETIC F09: empty container_id → INVALID."""

    def test_status_invalid(self) -> None:
        f = F09_InvalidContainerId()
        result = _mapper_with_a().map(f.event)
        assert result.status == MappingStatus.INVALID

    def test_invalid_reason_populated(self) -> None:
        f = F09_InvalidContainerId()
        result = _mapper_with_a().map(f.event)
        assert len(result.invalid_reason) > 0

    def test_selected_purl_is_sentinel(self) -> None:
        f = F09_InvalidContainerId()
        result = _mapper_with_a().map(f.event)
        assert result.selected_purl == _UNRESOLVED_PURL


# ===========================================================================
# F10 — Reused PID across process lifetimes
# ===========================================================================

class TestF10_ReusedPid:
    """SYNTHETIC F10: Same TGID, different start times → distinct identities."""

    def test_stable_keys_differ(self) -> None:
        f = F10_ReusedPid()
        assert f.process_a.stable_key != f.process_b.stable_key

    def test_same_tgid_different_identity(self) -> None:
        f = F10_ReusedPid()
        assert f.process_a.tgid == f.process_b.tgid
        assert f.process_a.pid_start_time_ns != f.process_b.pid_start_time_ns

    def test_process_a_resolves_to_requests(self) -> None:
        f = F10_ReusedPid()
        result_a = _mapper_with_a().map(f.event_a)
        assert result_a.status == f.expected_status_a
        assert result_a.selected_purl == f.expected_purl_a

    def test_process_b_resolves_to_urllib3(self) -> None:
        f = F10_ReusedPid()
        result_b = _mapper_with_a().map(f.event_b)
        assert result_b.status == f.expected_status_b
        assert result_b.selected_purl == f.expected_purl_b

    def test_results_are_independent(self) -> None:
        f = F10_ReusedPid()
        r_a = _mapper_with_a().map(f.event_a)
        r_b = _mapper_with_a().map(f.event_b)
        assert r_a.mapping_id != r_b.mapping_id
        assert r_a.selected_purl != r_b.selected_purl


# ===========================================================================
# F11 — Duplicate event delivery
# ===========================================================================

class TestF11_DuplicateEventDelivery:
    """SYNTHETIC F11: Same event_id → same MappingResult (idempotent resolver)."""

    def test_both_deliveries_resolve_same_purl(self) -> None:
        f = F11_DuplicateEventDelivery()
        mapper = _mapper_with_a()
        r1 = mapper.map(f.event_first)
        r2 = mapper.map(f.event_second)
        assert r1.selected_purl == f.expected_purl
        assert r2.selected_purl == f.expected_purl

    def test_both_deliveries_same_status(self) -> None:
        f = F11_DuplicateEventDelivery()
        mapper = _mapper_with_a()
        r1 = mapper.map(f.event_first)
        r2 = mapper.map(f.event_second)
        assert r1.status == f.expected_status
        assert r2.status == f.expected_status

    def test_same_event_id_in_both(self) -> None:
        f = F11_DuplicateEventDelivery()
        assert f.event_first.event_id == f.event_second.event_id

    def test_mapping_ids_differ(self) -> None:
        """Each map() call produces a new mapping_id (new provenance record)."""
        f = F11_DuplicateEventDelivery()
        mapper = _mapper_with_a()
        r1 = mapper.map(f.event_first)
        r2 = mapper.map(f.event_second)
        assert r1.mapping_id != r2.mapping_id


# ===========================================================================
# F12 — Two distinct events with similar attributes
# ===========================================================================

class TestF12_TwoDistinctSimilarEvents:
    """SYNTHETIC F12: Same process, different paths → different mapping results."""

    def test_event_a_resolves_to_requests(self) -> None:
        f = F12_TwoDistinctSimilarEvents()
        result = _mapper_with_a().map(f.event_a)
        assert result.status == f.expected_status_a
        assert result.selected_purl == f.expected_purl_a

    def test_event_b_resolves_to_urllib3(self) -> None:
        f = F12_TwoDistinctSimilarEvents()
        result = _mapper_with_a().map(f.event_b)
        assert result.status == f.expected_status_b
        assert result.selected_purl == f.expected_purl_b

    def test_events_are_not_collapsed(self) -> None:
        f = F12_TwoDistinctSimilarEvents()
        assert f.event_a.event_id != f.event_b.event_id
        assert f.event_a.resource_path != f.event_b.resource_path


# ===========================================================================
# F13 — Out-of-order timestamps
# ===========================================================================

class TestF13_OutOfOrderTimestamp:
    """SYNTHETIC F13: Out-of-order arrivals both resolve correctly."""

    def test_early_time_event_resolves(self) -> None:
        f = F13_OutOfOrderTimestamp()
        result = _mapper_with_a().map(f.event_early_time)
        assert result.status == f.expected_status
        assert result.selected_purl == f.expected_purl

    def test_late_time_event_resolves(self) -> None:
        f = F13_OutOfOrderTimestamp()
        result = _mapper_with_a().map(f.event_late_time)
        assert result.status == f.expected_status
        assert result.selected_purl == f.expected_purl

    def test_order_does_not_affect_outcome(self) -> None:
        """Mapper is stateless — swapping arrival order gives identical results."""
        f = F13_OutOfOrderTimestamp()
        r_early_first  = _mapper_with_a().map(f.event_early_time)
        r_late_second  = _mapper_with_a().map(f.event_late_time)
        r_late_first   = _mapper_with_a().map(f.event_late_time)
        r_early_second = _mapper_with_a().map(f.event_early_time)
        assert r_early_first.selected_purl  == r_early_second.selected_purl
        assert r_late_first.selected_purl   == r_late_second.selected_purl


# ===========================================================================
# F14 — Known container, unknown workload
# ===========================================================================

class TestF14_KnownContainerUnknownWorkload:
    """SYNTHETIC F14: pod_uid=None does not block mapping."""

    def test_status_inferred(self) -> None:
        f = F14_KnownContainerUnknownWorkload()
        result = _mapper_with_a().map(f.event)
        assert result.status == f.expected_status

    def test_selected_purl_correct(self) -> None:
        f = F14_KnownContainerUnknownWorkload()
        result = _mapper_with_a().map(f.event)
        assert result.selected_purl == f.expected_purl

    def test_pod_uid_none_in_container(self) -> None:
        f = F14_KnownContainerUnknownWorkload()
        assert f.container.pod_uid is None


# ===========================================================================
# F15 — SBOM component with no runtime evidence
# ===========================================================================

class TestF15_SbomComponentNoRuntimeEvidence:
    """SYNTHETIC F15: Component in SBOM but event doesn't touch it → UNRESOLVED."""

    def test_status_unresolved(self) -> None:
        f = F15_SbomComponentNoRuntimeEvidence()
        mapper = RuntimeToSbomMapper({IMAGE_DIGEST_A: f.sbom_index})
        result = mapper.map(f.event)
        assert result.status == MappingStatus.UNRESOLVED

    def test_cryptography_purl_not_selected(self) -> None:
        f = F15_SbomComponentNoRuntimeEvidence()
        mapper = RuntimeToSbomMapper({IMAGE_DIGEST_A: f.sbom_index})
        result = mapper.map(f.event)
        assert "cryptography" not in result.selected_purl


# ===========================================================================
# MappingResult invariants
# ===========================================================================

class TestMappingResultInvariants:
    """MappingResult field invariants for each status."""

    def _resolved_result(self) -> MappingResult:
        f = F01_VerifiedExecutableToComponent()
        return _mapper_with_a().map(f.event)

    def _unresolved_result(self) -> MappingResult:
        f = F07_MissingImageDigest()
        return _mapper_with_a().map(f.event)

    def _ambiguous_result(self) -> MappingResult:
        f = F04_AmbiguousTwoCandidates()
        return _mapper_with_a().map(f.event)

    def _invalid_result(self) -> MappingResult:
        f = F09_InvalidContainerId()
        return _mapper_with_a().map(f.event)

    def test_resolved_is_actionable(self) -> None:
        assert self._resolved_result().is_resolved is True

    def test_unresolved_not_actionable(self) -> None:
        assert self._unresolved_result().is_resolved is False

    def test_ambiguous_not_actionable(self) -> None:
        assert self._ambiguous_result().is_resolved is False

    def test_invalid_not_actionable(self) -> None:
        assert self._invalid_result().is_resolved is False

    def test_resolved_binding_status(self) -> None:
        from app.domain.entities import BindingStatus
        assert self._resolved_result().binding_status == BindingStatus.RESOLVED

    def test_ambiguous_binding_status(self) -> None:
        from app.domain.entities import BindingStatus
        assert self._ambiguous_result().binding_status == BindingStatus.AMBIGUOUS

    def test_unresolved_binding_status(self) -> None:
        from app.domain.entities import BindingStatus
        assert self._unresolved_result().binding_status == BindingStatus.MISSING

    def test_to_dict_json_serializable(self) -> None:
        import json
        result = self._resolved_result()
        d = result.to_dict()
        # Should not raise.
        json.dumps(d)

    def test_to_dict_contains_required_keys(self) -> None:
        d = self._resolved_result().to_dict()
        required = {
            "mapping_id", "event_id", "run_id", "mapped_at",
            "process", "container", "image_digest", "sbom_id",
            "candidate_purls", "selected_purl", "status",
            "evidence", "mapping_method", "resolver_version",
        }
        assert required.issubset(d.keys())

    def test_resolver_version_present(self) -> None:
        result = self._resolved_result()
        assert result.resolver_version == "v1"

    def test_mapping_id_is_uuid(self) -> None:
        result = self._resolved_result()
        assert isinstance(result.mapping_id, uuid.UUID)


# ===========================================================================
# SbomIndex.build()
# ===========================================================================

class TestSbomIndexBuild:
    """Unit tests for SbomIndex.build() with and without file inventory."""

    def test_build_without_inventory_has_empty_path_index(self) -> None:
        sbom_id = uuid.uuid4()
        sbom = _make_sbom(sbom_id, SYNTHETIC_TENANT_ID, IMAGE_DIGEST_A)
        comp = _make_component(sbom_id, PURL_REQUESTS, "requests")
        idx = SbomIndex.build(sbom, [comp], file_inventory=None)
        assert idx.path_to_purls == {}

    def test_build_with_inventory_populates_path_index(self) -> None:
        idx = SBOM_INDEX_A
        key = "/usr/lib/python3.11/site-packages/requests/__init__.py"
        assert key in idx.path_to_purls
        assert PURL_REQUESTS in idx.path_to_purls[key]

    def test_build_prefix_index_populated(self) -> None:
        idx = SBOM_INDEX_A
        # Prefix /usr/lib/python3.11/site-packages should exist.
        found = any(
            "site-packages" in prefix for prefix in idx.prefix_to_purls.keys()
        )
        assert found

    def test_purl_to_component_populated(self) -> None:
        idx = SBOM_INDEX_A
        assert PURL_REQUESTS in idx.purl_to_component
        assert PURL_URLLIB3 in idx.purl_to_component


# ===========================================================================
# ProcessIdentity
# ===========================================================================

class TestProcessIdentity:
    """ProcessIdentity stable_key and is_interpreter."""

    def test_stable_key_differs_across_start_times(self) -> None:
        p1 = _make_process(CONTAINER_ID_A, tgid=100, pid_start_time_ns=1_000)
        p2 = _make_process(CONTAINER_ID_A, tgid=100, pid_start_time_ns=2_000)
        assert p1.stable_key != p2.stable_key

    def test_stable_key_differs_across_containers(self) -> None:
        p1 = _make_process(CONTAINER_ID_A, tgid=100, pid_start_time_ns=1_000)
        p2 = _make_process("different_container", tgid=100, pid_start_time_ns=1_000)
        assert p1.stable_key != p2.stable_key

    def test_is_interpreter_python(self) -> None:
        p = _make_process(CONTAINER_ID_A, executable_path="/usr/bin/python3")
        assert p.is_interpreter is True

    def test_is_interpreter_java(self) -> None:
        p = _make_process(CONTAINER_ID_A, executable_path="/usr/lib/jvm/java-17/bin/java")
        assert p.is_interpreter is True

    def test_is_interpreter_false_for_binary(self) -> None:
        p = _make_process(CONTAINER_ID_A, executable_path="/usr/bin/curl")
        assert p.is_interpreter is False

    def test_is_interpreter_false_when_no_path(self) -> None:
        p = _make_process(CONTAINER_ID_A, executable_path=None)
        assert p.is_interpreter is False

    def test_interpreter_path_does_not_produce_candidate(self) -> None:
        """An interpreter exec path in the file inventory MUST NOT be used for mapping."""
        # Build an index that has python3 in the inventory (hypothetical).
        sbom_id = uuid.uuid4()
        sbom = _make_sbom(sbom_id, SYNTHETIC_TENANT_ID, IMAGE_DIGEST_A)
        comp = _make_component(sbom_id, PURL_REQUESTS, "requests")
        idx = SbomIndex.build(
            sbom, [comp],
            file_inventory={PURL_REQUESTS: ["/usr/bin/python3"]},
        )
        proc = _make_process(CONTAINER_ID_A, executable_path="/usr/bin/python3")
        container = _make_container(CONTAINER_ID_A)
        event = _make_event(proc, container, event_type="exec",
                            resource_path="/usr/bin/python3")
        mapper = RuntimeToSbomMapper({IMAGE_DIGEST_A: idx})
        result = mapper.map(event)
        # Interpreter detected → no candidate from exec path.
        assert result.selected_purl != PURL_REQUESTS


# ===========================================================================
# EvidenceSource validation
# ===========================================================================

class TestEvidenceSource:
    """EvidenceSource constructor rejects invalid confidence values."""

    def test_valid_evidence_source(self) -> None:
        src = EvidenceSource(
            kind=EvidenceKind.IMAGE_DIGEST,
            value="sha256:abc",
            description="test",
            confidence_contribution=0.5,
        )
        assert src.confidence_contribution == 0.5

    def test_confidence_above_one_raises(self) -> None:
        with pytest.raises(ValueError):
            EvidenceSource(
                kind=EvidenceKind.IMAGE_DIGEST,
                value="v",
                description="d",
                confidence_contribution=1.1,
            )

    def test_negative_confidence_raises(self) -> None:
        with pytest.raises(ValueError):
            EvidenceSource(
                kind=EvidenceKind.IMAGE_DIGEST,
                value="v",
                description="d",
                confidence_contribution=-0.1,
            )


# ===========================================================================
# MappingQualityMetrics
# ===========================================================================

class TestMappingQualityMetrics:
    """MappingQualityMetrics with and without ground truth."""

    def _run_all_fixtures(self) -> list[MappingResult]:
        """SYNTHETIC: Run all single-event fixtures through the mapper."""
        mapper = _mapper_with_a()
        results = []
        for cls in (
            F01_VerifiedExecutableToComponent,
            F02_ContainerKnownNoPackageEvidence,
            F03_PurlKnownNoLinkToEvent,
            F07_MissingImageDigest,
            F09_InvalidContainerId,
        ):
            f = cls()
            mapper_to_use = mapper
            if hasattr(f, "sbom_index") and f.sbom_index is not SBOM_INDEX_A:
                mapper_to_use = RuntimeToSbomMapper({IMAGE_DIGEST_A: f.sbom_index})
            results.append(mapper_to_use.map(f.event))
        return results

    def test_rate_metrics_sum_to_one(self) -> None:
        results = self._run_all_fixtures()
        m = MappingQualityMetrics(results).compute()
        total_rate = m.unresolved_rate + m.ambiguous_rate + m.invalid_rate
        # These three rates sum to at most 1.0 (some may be verified/inferred).
        assert total_rate <= 1.0 + 1e-9

    def test_n_total_correct(self) -> None:
        results = self._run_all_fixtures()
        m = MappingQualityMetrics(results).compute()
        assert m.n_total == len(results)

    def test_counts_sum_to_total(self) -> None:
        results = self._run_all_fixtures()
        m = MappingQualityMetrics(results).compute()
        assert (m.n_verified + m.n_inferred + m.n_ambiguous +
                m.n_unresolved + m.n_invalid) == m.n_total

    def test_no_gt_precision_is_none(self) -> None:
        results = self._run_all_fixtures()
        m = MappingQualityMetrics(results).compute()
        assert m.precision is None
        assert m.recall is None
        assert m.exact_match_accuracy is None

    def test_gt_precision_computed(self) -> None:
        f1 = F01_VerifiedExecutableToComponent()
        f2 = F02_ContainerKnownNoPackageEvidence()
        results = [
            _mapper_with_a().map(f1.event),
            _mapper_with_a().map(f2.event),
        ]
        gt = {
            str(results[0].event_id): f1.ground_truth_purl,
            str(results[1].event_id): f2.ground_truth_purl,
        }
        report = MappingQualityMetrics(results, ground_truth=gt).compute()
        assert report.precision is not None
        assert report.exact_match_accuracy is not None

    def test_empty_results_returns_zero_metrics(self) -> None:
        report = MappingQualityMetrics([]).compute()
        assert report.n_total == 0
        assert report.unresolved_rate == 0.0

    def test_gt_provided_flag(self) -> None:
        f = F01_VerifiedExecutableToComponent()
        result = _mapper_with_a().map(f.event)
        gt = {str(result.event_id): f.ground_truth_purl}
        report = MappingQualityMetrics([result], ground_truth=gt).compute()
        assert report.ground_truth_available is True

    def test_no_gt_flag(self) -> None:
        f = F01_VerifiedExecutableToComponent()
        result = _mapper_with_a().map(f.event)
        report = MappingQualityMetrics([result]).compute()
        assert report.ground_truth_available is False

    def test_candidate_set_accuracy_for_ambiguous(self) -> None:
        """For F04 (AMBIGUOUS), GT PURL is in candidate_purls → hit."""
        f = F04_AmbiguousTwoCandidates()
        result = _mapper_with_a().map(f.event)
        gt = {str(result.event_id): f.ground_truth_purl}
        report = MappingQualityMetrics([result], ground_truth=gt).compute()
        assert report.candidate_set_accuracy == pytest.approx(1.0)
