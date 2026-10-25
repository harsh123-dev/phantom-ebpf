"""
services/sbom-service/app/domain/mapping/resolver.py

Evidence-based runtime-to-SBOM component mapping resolver.

Implements the mapping rules from the Part 3 specification §4:

    Rule 1 — verify SBOM/image association with the observed workload.
    Rule 2 — resolve event to the correct process, container, workload.
    Rule 3 — resolve executables/artifacts to components only with defensible
              evidence.
    Rule 4 — use exact hashes or verified artifact metadata where supported.
    Rule 5 — file inventory information only where meaningful.
    Rule 6 — do NOT infer every package caused every event in its image.
    Rule 7 — do NOT assume an interpreter identifies the responsible package.
    Rule 8 — record ambiguity when multiple components could explain an event.
    Rule 9 — preserve UNRESOLVED rather than inventing a PURL.
    Rule 10 — record the reason for every decision (verified/inferred/
              ambiguous/unresolved/invalid).

Mapping pipeline:
    1. Validate container identity and locate the SBOM for the image.
    2. Verify the SBOM is signed and trusted (pass-through; trust decisions
       are made upstream by verify_sbom_signature use case).
    3. Attempt each evidence tier in order of decreasing strength:
       a. PURL_DIRECT — runtime event carries a PURL directly.
       b. EXECUTABLE_HASH — sha256 of executable matches an SBOM artifact hash.
       c. EXECUTABLE_PATH — executable path in SBOM file inventory.
       d. FILE_INVENTORY — accessed file path in SBOM file inventory.
       e. HEURISTIC_PATH_PREFIX — path prefix matches known install location.
    4. If a single component survives: resolved (verified or inferred).
    5. If multiple components survive: ambiguous.
    6. If no component survives: unresolved.
    7. If the input is structurally invalid: invalid.

Design decisions:
    - The resolver is a pure domain object (no I/O, no database).
    - SBOMs and component lists are injected; the resolver never fetches them.
    - All decisions are recorded in MappingResult with full evidence trail.
    - is_interpreter prevents interpreter paths from generating false PURL claims.
    - Duplicate event detection is the BDG's responsibility; the resolver does
      not de-duplicate. Each event gets an independent MappingResult.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from app.domain.entities import BindingStatus, Component, Sbom
from app.domain.mapping.evidence import (
    ContainerIdentity,
    EvidenceKind,
    EvidenceSource,
    ProcessIdentity,
    RuntimeEventRecord,
)

# ---------------------------------------------------------------------------
# Resolver version (bump when the algorithm changes)
# ---------------------------------------------------------------------------

RESOLVER_VERSION: str = "v1"


# ---------------------------------------------------------------------------
# Mapping status
# ---------------------------------------------------------------------------


class MappingStatus(str, Enum):
    """Quality of a single runtime-event-to-SBOM-component mapping.

    Members:
        VERIFIED: The mapping is supported by an explicit, validated evidence
            rule (e.g. exact executable hash match against SBOM artifact).
            Rule: at least one EXECUTABLE_HASH or PURL_DIRECT evidence piece.

        INFERRED: A plausible mapping exists but depends on assumptions or
            incomplete evidence (e.g. file path in component inventory, path
            prefix heuristic).
            Rule: EXECUTABLE_PATH or FILE_INVENTORY evidence only.

        AMBIGUOUS: Multiple SBOM components are consistent with the event
            and available evidence cannot distinguish them.
            Rule: more than one candidate PURL remains after all evidence tiers.

        UNRESOLVED: Insufficient information to identify any component.
            Rule: no SBOM found for the image, or no evidence tier produced
            a candidate.

        INVALID: The event or container identity failed structural validation
            (e.g. missing container_id, malformed PURL, missing image digest).
    """

    VERIFIED = "verified"
    INFERRED = "inferred"
    AMBIGUOUS = "ambiguous"
    UNRESOLVED = "unresolved"
    INVALID = "invalid"


# ---------------------------------------------------------------------------
# Mapping result
# ---------------------------------------------------------------------------

_UNRESOLVED_PURL: str = "UNRESOLVED"


@dataclass
class MappingResult:
    """Full provenance record for one runtime-event-to-component mapping.

    Attributes:
        mapping_id: Unique UUID for this mapping result (for audit).
        event_id: UUID of the runtime event that was mapped.
        run_id: Experiment run ID (empty if not in evaluation context).
        mapped_at: UTC timestamp when the mapping was computed.
        process: Process identity of the observed process.
        container: Container identity (may be None if unavailable).
        image_digest: Image digest used for SBOM lookup, or None.
        sbom_id: UUID of the SBOM used, or None if not found.
        candidate_purls: All PURL strings that survived evidence filtering.
        selected_purl: The single selected PURL, only when status is VERIFIED
            or INFERRED and exactly one candidate survived.
            Equals _UNRESOLVED_PURL ("UNRESOLVED") for any other status.
        status: The mapping quality status.
        evidence: Ordered list of evidence pieces that contributed.
        mapping_method: Human-readable description of the method used.
        ambiguity_reason: Non-empty when status is AMBIGUOUS.
        unresolved_reason: Non-empty when status is UNRESOLVED.
        invalid_reason: Non-empty when status is INVALID.
        resolver_version: Version string of the resolver algorithm.
    """

    mapping_id: uuid.UUID
    event_id: uuid.UUID
    run_id: str
    mapped_at: datetime
    process: ProcessIdentity
    container: Optional[ContainerIdentity]
    image_digest: Optional[str]
    sbom_id: Optional[uuid.UUID]
    candidate_purls: list[str]
    selected_purl: str
    status: MappingStatus
    evidence: list[EvidenceSource]
    mapping_method: str
    ambiguity_reason: str = ""
    unresolved_reason: str = ""
    invalid_reason: str = ""
    resolver_version: str = RESOLVER_VERSION

    @property
    def is_resolved(self) -> bool:
        """True when status is VERIFIED or INFERRED (single candidate)."""
        return self.status in (MappingStatus.VERIFIED, MappingStatus.INFERRED)

    @property
    def binding_status(self) -> BindingStatus:
        """Convert MappingStatus to the domain BindingStatus enum.

        Returns:
            BindingStatus.RESOLVED for VERIFIED/INFERRED.
            BindingStatus.AMBIGUOUS for AMBIGUOUS.
            BindingStatus.MISSING for UNRESOLVED/INVALID.
        """
        if self.status in (MappingStatus.VERIFIED, MappingStatus.INFERRED):
            return BindingStatus.RESOLVED
        if self.status == MappingStatus.AMBIGUOUS:
            return BindingStatus.AMBIGUOUS
        return BindingStatus.MISSING

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-compatible dict for API/audit output.

        Returns:
            Dict representation of this MappingResult.
        """
        return {
            "mapping_id": str(self.mapping_id),
            "event_id": str(self.event_id),
            "run_id": self.run_id,
            "mapped_at": self.mapped_at.isoformat(),
            "process": {
                "tgid": self.process.tgid,
                "pid_start_time_ns": self.process.pid_start_time_ns,
                "container_id": self.process.container_id,
                "executable_path": self.process.executable_path,
                "executable_hash": self.process.executable_hash,
                "comm": self.process.comm,
            },
            "container": {
                "container_id": self.container.container_id,
                "image_digest": self.container.image_digest,
                "pod_uid": self.container.pod_uid,
                "namespace": self.container.namespace,
            } if self.container else None,
            "image_digest": self.image_digest,
            "sbom_id": str(self.sbom_id) if self.sbom_id else None,
            "candidate_purls": self.candidate_purls,
            "selected_purl": self.selected_purl,
            "status": self.status.value,
            "evidence": [
                {
                    "kind": e.kind.value,
                    "value": e.value,
                    "description": e.description,
                    "confidence_contribution": e.confidence_contribution,
                }
                for e in self.evidence
            ],
            "mapping_method": self.mapping_method,
            "ambiguity_reason": self.ambiguity_reason,
            "unresolved_reason": self.unresolved_reason,
            "invalid_reason": self.invalid_reason,
            "resolver_version": self.resolver_version,
        }

    def to_causal_binding_payload(self) -> dict[str, Any]:
        """Convert this result to the shared event contract without guessing.

        Positive component attribution requires a digest, SBOM identity, one
        selected PURL, and a nonempty resolver evidence trail. Unknown cases
        never serialize the unresolved sentinel as a package URL.
        """
        if not self.image_digest:
            raise ValueError("causal binding requires an immutable image digest")
        if self.status == MappingStatus.VERIFIED:
            if not self.sbom_id or not self.selected_purl or not self.evidence:
                raise ValueError("resolved mapping is missing binding provenance")
            status = "bound"
            purl: str | None = self.selected_purl
        elif self.status == MappingStatus.INFERRED:
            status, purl = "insufficient_evidence", None
        elif self.status == MappingStatus.AMBIGUOUS:
            status, purl = "ambiguous", None
        elif self.sbom_id is None:
            status, purl = "unbound", None
        else:
            status, purl = "insufficient_evidence", None
        return {
            "binding_status": status,
            "image_digest": self.image_digest,
            "sbom_id": str(self.sbom_id) if self.sbom_id else None,
            "purl": purl,
            "confidence": (
                max(item.confidence_contribution for item in self.evidence)
                if status == "bound" else None
            ),
            "resolver_version": self.resolver_version,
            "method": self.mapping_method,
            "reason": (
                self.ambiguity_reason or self.unresolved_reason or self.invalid_reason
                or ("mapping relies on inferred path evidence, not a verified component identity"
                    if self.status == MappingStatus.INFERRED else None)
            ),
            "candidate_purls": self.candidate_purls if status == "ambiguous" else [],
            "evidence": [
                {
                    "kind": item.kind.value,
                    "value": item.value,
                    "description": item.description,
                    "confidence_contribution": item.confidence_contribution,
                }
                for item in self.evidence
            ],
        }


# ---------------------------------------------------------------------------
# SBOM index — built once per SBOM for efficient lookups
# ---------------------------------------------------------------------------


@dataclass
class SbomIndex:
    """Pre-built lookup index over an SBOM's component list.

    Constructed once per SBOM load; shared across all events that use the
    same image digest.

    Attributes:
        sbom_id: UUID of the indexed SBOM.
        image_digest: Image digest this SBOM covers.
        purl_to_component: Mapping from PURL string to Component.
        path_to_purls: Mapping from file path string to set of PURL strings.
            A path may appear in multiple components (e.g. shared headers).
        prefix_to_purls: Mapping from path prefix to set of PURLs.
            Used only for heuristic tier.
    """

    sbom_id: uuid.UUID
    image_digest: str
    purl_to_component: dict[str, Component] = field(default_factory=dict)
    path_to_purls: dict[str, set[str]] = field(default_factory=dict)
    prefix_to_purls: dict[str, set[str]] = field(default_factory=dict)
    hash_to_purls: dict[str, set[str]] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        sbom: Sbom,
        components: list[Component],
        file_inventory: Optional[dict[str, list[str]]] = None,
    ) -> SbomIndex:
        """Build a lookup index from an SBOM and its component list.

        Args:
            sbom: The parent SBOM entity.
            components: All Component records for this SBOM.
            file_inventory: Optional dict mapping PURL → list of file paths
                that belong to that component (from a file-content scanner
                like Syft with --output syft-json).  When absent, file-level
                lookups return empty sets.

        Returns:
            A populated SbomIndex ready for resolver use.
        """
        purl_to_component: dict[str, Component] = {}
        path_to_purls: dict[str, set[str]] = {}
        prefix_to_purls: dict[str, set[str]] = {}
        hash_to_purls: dict[str, set[str]] = {}

        for comp in components:
            purl_str = str(comp.purl)
            purl_to_component[purl_str] = comp

            if file_inventory and purl_str in file_inventory:
                for fpath in file_inventory[purl_str]:
                    path_to_purls.setdefault(fpath, set()).add(purl_str)
                    # Build prefix index at depths 5–7 only.
                    # Shallow depths (1–4) generate common system prefixes like
                    # /usr or /usr/lib that would match unrelated event paths,
                    # causing false attributions. Requiring at least 5 components
                    # ensures only package-specific directory prefixes are indexed
                    # (e.g. /usr/lib/python3.11/site-packages which is depth 5).
                    parts = fpath.rstrip("/").split("/")
                    for depth in range(5, min(len(parts) + 1, 8)):
                        prefix = "/".join(parts[:depth])
                        prefix_to_purls.setdefault(prefix, set()).add(purl_str)

        # Exact SHA-256 hashes in CycloneDX are package artifact provenance.
        document_components = sbom.cyclonedx_document.get("components", [])
        if isinstance(document_components, list):
            for item in document_components:
                if not isinstance(item, dict) or not isinstance(item.get("purl"), str):
                    continue
                if item["purl"] not in purl_to_component:
                    continue
                hashes = item.get("hashes", [])
                if not isinstance(hashes, list):
                    continue
                for entry in hashes:
                    if not isinstance(entry, dict):
                        continue
                    algorithm = str(entry.get("alg", "")).replace("-", "").lower()
                    content = entry.get("content")
                    if algorithm == "sha256" and isinstance(content, str) and len(content) == 64:
                        value = content.lower()
                        if all(char in "0123456789abcdef" for char in value):
                            hash_to_purls.setdefault(f"sha256:{value}", set()).add(item["purl"])

        return cls(
            sbom_id=sbom.sbom_id,
            image_digest=str(sbom.image_digest),
            purl_to_component=purl_to_component,
            path_to_purls=path_to_purls,
            prefix_to_purls=prefix_to_purls,
            hash_to_purls=hash_to_purls,
        )


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


class RuntimeToSbomMapper:
    """Maps runtime events to SBOM components using evidence-based rules.

    The resolver is injected with all data it needs; it performs no I/O.
    SBOMs and their indices must be prepared and cached by the caller.

    Args:
        sbom_index_by_digest: Mapping from image_digest string to SbomIndex.
            The caller is responsible for loading the correct SBOMs.
    """

    def __init__(
        self,
        sbom_index_by_digest: Optional[dict[str, SbomIndex]] = None,
    ) -> None:
        """Initialise the mapper with a pre-built SBOM index cache.

        Args:
            sbom_index_by_digest: Optional pre-built mapping; defaults to
                an empty dict (no SBOM data available → UNRESOLVED results).
        """
        self._index: dict[str, SbomIndex] = sbom_index_by_digest or {}

    def map(self, event: RuntimeEventRecord) -> MappingResult:
        """Map one runtime event to a SBOM component.

        Args:
            event: The runtime event to map.

        Returns:
            A MappingResult with full provenance and a controlled status.
        """
        # --- 0. Structural validation ---
        if not event.process.container_id:
            return self._invalid(
                event,
                reason="Process container_id is empty; cannot resolve image",
            )

        image_digest: Optional[str] = (
            event.container.image_digest
            if event.container and event.container.image_digest
            else None
        )

        if not image_digest:
            return self._unresolved(
                event,
                image_digest=None,
                sbom_id=None,
                reason="No image_digest available for this container; "
                       "SBOM lookup is not possible without a digest",
            )

        # --- 1. Locate SBOM for this image ---
        idx = self._index.get(image_digest)
        if idx is None:
            return self._unresolved(
                event,
                image_digest=image_digest,
                sbom_id=None,
                reason=f"No SBOM indexed for image_digest={image_digest}",
            )

        # --- 2. Evidence tier A: PURL_DIRECT (strongest) ---
        # If the event carries an explicit PURL (from build-pipeline injection).
        # Not yet populated by the eBPF collector; reserved for future use.

        # --- 3. Evidence tier B: EXECUTABLE_HASH ---
        hash_evidence: Optional[EvidenceSource] = None
        hash_candidates: list[str] = []
        if event.process.executable_hash:
            normalized_hash = event.process.executable_hash.lower()
            if not normalized_hash.startswith("sha256:"):
                normalized_hash = f"sha256:{normalized_hash}"
            hash_candidates = sorted(idx.hash_to_purls.get(normalized_hash, set()))
            if hash_candidates:
                hash_evidence = EvidenceSource(
                    kind=EvidenceKind.EXECUTABLE_HASH,
                    value=normalized_hash,
                    description="Runtime executable SHA-256 exactly matches an explicit CycloneDX component hash.",
                    confidence_contribution=1.0,
                )

        # --- 4. Evidence tier C: EXECUTABLE_PATH in file inventory ---
        path_evidence: Optional[EvidenceSource] = None
        path_candidates: list[str] = []

        exec_path = event.process.executable_path
        if exec_path:
            if event.process.is_interpreter:
                # Always record interpreter detection — even when the binary is
                # not in the SBOM file inventory — so callers can explain why
                # no component-level mapping was produced for this event.
                path_evidence = EvidenceSource(
                    kind=EvidenceKind.EXECUTABLE_PATH,
                    value=exec_path,
                    description=(
                        f"Executable {exec_path!r} is a known interpreter; "
                        "it cannot identify the specific language package "
                        "responsible for this event."
                    ),
                    confidence_contribution=0.0,
                )
                # No candidates added — interpreters are not mapped.
            elif idx.path_to_purls:
                matched = idx.path_to_purls.get(exec_path, set())
                if matched:
                    path_candidates = sorted(matched)
                    path_evidence = EvidenceSource(
                        kind=EvidenceKind.EXECUTABLE_PATH,
                        value=exec_path,
                        description=(
                            f"Executable path {exec_path!r} found in SBOM "
                            f"file inventory for {len(path_candidates)} component(s)."
                        ),
                        confidence_contribution=0.7,
                    )

        # --- 5. Evidence tier D: accessed file in file inventory ---
        file_evidence: Optional[EvidenceSource] = None
        file_candidates: list[str] = []

        resource_path = event.resource_path
        # Skip the file inventory tier when the resource_path is the interpreter's
        # own executable binary — using the interpreter binary as a component
        # evidence source would produce a false attribution.
        _resource_is_interpreter_binary = (
            event.process.is_interpreter
            and resource_path is not None
            and resource_path == event.process.executable_path
        )
        if resource_path and idx.path_to_purls and not path_candidates and not _resource_is_interpreter_binary:
            matched = idx.path_to_purls.get(resource_path, set())
            if matched:
                file_candidates = sorted(matched)
                file_evidence = EvidenceSource(
                    kind=EvidenceKind.FILE_INVENTORY,
                    value=resource_path,
                    description=(
                        f"Accessed path {resource_path!r} found in SBOM "
                        f"file inventory for {len(file_candidates)} component(s)."
                    ),
                    confidence_contribution=0.5,
                )

        # --- 6. Evidence tier E: path prefix heuristic (weakest) ---
        # Only activated when no stronger evidence tier produced candidates.
        # Searches path prefixes of depth >= 5 (at least 5 components after
        # the leading '/'), preventing common system directories like /usr or
        # /usr/bin from generating false component attributions.
        prefix_evidence: Optional[EvidenceSource] = None
        prefix_candidates: list[str] = []

        if not path_candidates and not file_candidates and resource_path and not _resource_is_interpreter_binary:
            parts = resource_path.rstrip("/").split("/")
            # Start at max depth and descend, but never below depth 5.
            # Paths with fewer than 5 components produce no prefix candidates.
            for depth in range(min(len(parts), 7), 4, -1):
                prefix = "/".join(parts[:depth])
                matched = idx.prefix_to_purls.get(prefix, set())
                if matched:
                    prefix_candidates = sorted(matched)
                    prefix_evidence = EvidenceSource(
                        kind=EvidenceKind.HEURISTIC_PATH_PREFIX,
                        value=prefix,
                        description=(
                            f"Path prefix {prefix!r} heuristically matches "
                            f"{len(prefix_candidates)} component(s). "
                            "This is the weakest evidence tier; treat with caution."
                        ),
                        confidence_contribution=0.2,
                    )
                    break

        # --- 7. Collect all evidence and candidates ---
        all_evidence: list[EvidenceSource] = [
            e for e in (hash_evidence, path_evidence, file_evidence, prefix_evidence)
            if e is not None
        ]

        # Priority: hash > path > file > prefix.
        final_candidates: list[str] = (
            hash_candidates or path_candidates or file_candidates or prefix_candidates
        )

        # Container-level identity evidence is always added (weakest basis).
        all_evidence.append(EvidenceSource(
            kind=EvidenceKind.IMAGE_DIGEST,
            value=image_digest,
            description=(
                f"Image digest {image_digest[:20]}... identifies the image "
                "but does NOT identify which package caused this specific event."
            ),
            confidence_contribution=0.1,
        ))

        # --- 8. Decision ---
        if not final_candidates:
            return self._unresolved(
                event,
                image_digest=image_digest,
                sbom_id=idx.sbom_id,
                reason=(
                    "No SBOM component matched the event's executable path, "
                    "resource path, or path prefix. The event belongs to this "
                    "image but cannot be attributed to a specific package."
                ),
                evidence=all_evidence,
            )

        if len(final_candidates) > 1:
            return self._ambiguous(
                event,
                image_digest=image_digest,
                sbom_id=idx.sbom_id,
                candidates=final_candidates,
                evidence=all_evidence,
                reason=(
                    f"{len(final_candidates)} components are consistent with "
                    "this event's evidence. Available evidence cannot distinguish them."
                ),
            )

        # Exactly one candidate.
        purl = final_candidates[0]
        strongest = all_evidence[0] if all_evidence else None
        if strongest and strongest.kind in (
            EvidenceKind.EXECUTABLE_HASH, EvidenceKind.PURL_DIRECT
        ):
            status = MappingStatus.VERIFIED
            method = f"Exact {strongest.kind.value} match"
        else:
            status = MappingStatus.INFERRED
            method = (
                f"{strongest.kind.value if strongest else 'unknown'} "
                "match (inferred; not hash-verified)"
            )

        return MappingResult(
            mapping_id=uuid.uuid4(),
            event_id=event.event_id,
            run_id=event.run_id,
            mapped_at=datetime.now(tz=timezone.utc),
            process=event.process,
            container=event.container,
            image_digest=image_digest,
            sbom_id=idx.sbom_id,
            candidate_purls=final_candidates,
            selected_purl=purl,
            status=status,
            evidence=all_evidence,
            mapping_method=method,
        )

    # ------------------------------------------------------------------
    # Factory helpers for clean result construction
    # ------------------------------------------------------------------

    def _invalid(
        self,
        event: RuntimeEventRecord,
        reason: str,
    ) -> MappingResult:
        return MappingResult(
            mapping_id=uuid.uuid4(),
            event_id=event.event_id,
            run_id=event.run_id,
            mapped_at=datetime.now(tz=timezone.utc),
            process=event.process,
            container=event.container,
            image_digest=None,
            sbom_id=None,
            candidate_purls=[],
            selected_purl=_UNRESOLVED_PURL,
            status=MappingStatus.INVALID,
            evidence=[],
            mapping_method="validation_failed",
            invalid_reason=reason,
        )

    def _unresolved(
        self,
        event: RuntimeEventRecord,
        image_digest: Optional[str],
        sbom_id: Optional[uuid.UUID],
        reason: str,
        evidence: Optional[list[EvidenceSource]] = None,
    ) -> MappingResult:
        return MappingResult(
            mapping_id=uuid.uuid4(),
            event_id=event.event_id,
            run_id=event.run_id,
            mapped_at=datetime.now(tz=timezone.utc),
            process=event.process,
            container=event.container,
            image_digest=image_digest,
            sbom_id=sbom_id,
            candidate_purls=[],
            selected_purl=_UNRESOLVED_PURL,
            status=MappingStatus.UNRESOLVED,
            evidence=evidence or [],
            mapping_method="unresolved",
            unresolved_reason=reason,
        )

    def _ambiguous(
        self,
        event: RuntimeEventRecord,
        image_digest: str,
        sbom_id: uuid.UUID,
        candidates: list[str],
        evidence: list[EvidenceSource],
        reason: str,
    ) -> MappingResult:
        return MappingResult(
            mapping_id=uuid.uuid4(),
            event_id=event.event_id,
            run_id=event.run_id,
            mapped_at=datetime.now(tz=timezone.utc),
            process=event.process,
            container=event.container,
            image_digest=image_digest,
            sbom_id=sbom_id,
            candidate_purls=candidates,
            selected_purl=_UNRESOLVED_PURL,
            status=MappingStatus.AMBIGUOUS,
            evidence=evidence,
            mapping_method="ambiguous_candidates",
            ambiguity_reason=reason,
        )
