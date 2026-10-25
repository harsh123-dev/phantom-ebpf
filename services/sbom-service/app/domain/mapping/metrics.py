"""
services/sbom-service/app/domain/mapping/metrics.py

Mapping quality metrics for the runtime-to-SBOM component resolver.

Integrated with the Part 1 experiment runner:
- Metrics are computed from MappingResult lists.
- When ground-truth labels exist, precision/recall are computed.
- When ground-truth is absent, only rate metrics are reported.

IMPORTANT: container-level matches are NOT counted as component-level matches.
Unverified candidate mappings are NOT counted as correct.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional

from app.domain.mapping.resolver import MappingResult, MappingStatus


# ---------------------------------------------------------------------------
# Metric result
# ---------------------------------------------------------------------------


@dataclass
class MappingQualityReport:
    """Mapping quality metrics for a batch of MappingResult objects.

    Attributes:
        n_total: Total mapping attempts in the batch.
        n_verified: Count with status=VERIFIED.
        n_inferred: Count with status=INFERRED.
        n_ambiguous: Count with status=AMBIGUOUS.
        n_unresolved: Count with status=UNRESOLVED.
        n_invalid: Count with status=INVALID.
        unresolved_rate: n_unresolved / n_total.
        ambiguous_rate: n_ambiguous / n_total.
        invalid_rate: n_invalid / n_total.
        precision: Fraction of selected_purls that match ground truth.
            Only computed when ground_truth_purls is provided AND the
            status is VERIFIED or INFERRED. None if ground truth absent.
        recall: Fraction of ground-truth PURLs that were correctly selected.
            None if ground truth absent.
        exact_match_accuracy: Fraction of all results (including UNRESOLVED)
            where selected_purl == ground_truth_purl.
            None if ground truth absent.
        candidate_set_accuracy: Fraction of AMBIGUOUS results where the
            ground-truth PURL is in candidate_purls.
            None if ground truth absent or no AMBIGUOUS results.
        ground_truth_available: True if ground truth was supplied.
        notes: Explanatory notes, especially when metrics cannot be computed.
    """

    n_total: int = 0
    n_verified: int = 0
    n_inferred: int = 0
    n_ambiguous: int = 0
    n_unresolved: int = 0
    n_invalid: int = 0

    unresolved_rate: float = 0.0
    ambiguous_rate: float = 0.0
    invalid_rate: float = 0.0

    precision: Optional[float] = None
    recall: Optional[float] = None
    exact_match_accuracy: Optional[float] = None
    candidate_set_accuracy: Optional[float] = None

    ground_truth_available: bool = False
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Metric calculator
# ---------------------------------------------------------------------------


class MappingQualityMetrics:
    """Compute quality metrics over a batch of MappingResult objects.

    Args:
        results: List of MappingResult objects from a mapping run.
        ground_truth: Optional dict mapping event_id (str) → correct PURL
            string.  If absent, only rate metrics are computed.
    """

    def __init__(
        self,
        results: list[MappingResult],
        ground_truth: Optional[dict[str, str]] = None,
    ) -> None:
        """Initialise the calculator.

        Args:
            results: MappingResult objects to evaluate.
            ground_truth: Optional dict of event_id → correct PURL.
        """
        self._results = results
        self._gt = ground_truth or {}

    def compute(self) -> MappingQualityReport:
        """Compute the mapping quality report.

        Returns:
            A MappingQualityReport with all computable metrics populated.
        """
        n = len(self._results)
        report = MappingQualityReport(n_total=n)

        if n == 0:
            report.notes.append("No mapping results provided; all metrics are zero.")
            return report

        # --- Count by status ---
        for r in self._results:
            if r.status == MappingStatus.VERIFIED:
                report.n_verified += 1
            elif r.status == MappingStatus.INFERRED:
                report.n_inferred += 1
            elif r.status == MappingStatus.AMBIGUOUS:
                report.n_ambiguous += 1
            elif r.status == MappingStatus.UNRESOLVED:
                report.n_unresolved += 1
            elif r.status == MappingStatus.INVALID:
                report.n_invalid += 1

        report.unresolved_rate = report.n_unresolved / n
        report.ambiguous_rate  = report.n_ambiguous  / n
        report.invalid_rate    = report.n_invalid    / n

        # --- Ground-truth metrics ---
        if not self._gt:
            report.ground_truth_available = False
            report.notes.append(
                "No ground-truth labels supplied. "
                "Precision, recall, and accuracy cannot be computed. "
                "Do not report measured mapping accuracy without ground truth."
            )
            return report

        report.ground_truth_available = True

        # Exact match: selected_purl == ground_truth for any status.
        exact_matches = 0
        for r in self._results:
            gt_purl = self._gt.get(str(r.event_id))
            if gt_purl and r.selected_purl == gt_purl:
                exact_matches += 1
        report.exact_match_accuracy = exact_matches / n

        # Precision: among VERIFIED/INFERRED, how many selected_purls are correct?
        actionable = [
            r for r in self._results
            if r.status in (MappingStatus.VERIFIED, MappingStatus.INFERRED)
            and str(r.event_id) in self._gt
        ]
        if actionable:
            correct_actionable = sum(
                1 for r in actionable
                if r.selected_purl == self._gt[str(r.event_id)]
            )
            report.precision = correct_actionable / len(actionable)
        else:
            report.notes.append(
                "No VERIFIED or INFERRED results with ground truth — precision is undefined."
            )

        # Recall: among all events with ground truth, how many were correctly mapped?
        gt_event_ids = {str(r.event_id) for r in self._results if str(r.event_id) in self._gt}
        if gt_event_ids:
            correctly_recalled = sum(
                1 for r in self._results
                if str(r.event_id) in self._gt
                and r.selected_purl == self._gt[str(r.event_id)]
            )
            report.recall = correctly_recalled / len(gt_event_ids)
        else:
            report.notes.append("No results have matching ground-truth entries — recall is undefined.")

        # Candidate set accuracy: for AMBIGUOUS, is GT in candidate_purls?
        ambig_with_gt = [
            r for r in self._results
            if r.status == MappingStatus.AMBIGUOUS
            and str(r.event_id) in self._gt
        ]
        if ambig_with_gt:
            cand_hits = sum(
                1 for r in ambig_with_gt
                if self._gt[str(r.event_id)] in r.candidate_purls
            )
            report.candidate_set_accuracy = cand_hits / len(ambig_with_gt)

        return report
