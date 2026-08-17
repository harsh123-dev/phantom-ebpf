"""
causal-engine domain exceptions.

Typed exceptions for causal engine invariant violations:
- GraphCycleError: causal DAG contains a cycle
- EffectNotIdentifiableError: no valid adjustment set found
- SnapshotNotFoundError: requested BDG snapshot is absent
- AttributionJobConflictError: duplicate active attribution request
- PositivityFailureError: treatment/covariate overlap insufficient
- InsufficientVariationError: no variation in treatment or outcome
- CausalModelConstructionError: DoWhy model construction failure
"""

from __future__ import annotations


class GraphCycleError(Exception):
    """Raised when a projected temporal DAG contains a cycle involving
    the treatment or outcome variable.

    Per handoff §5.2: treatment/outcome in an unresolved cycle → not_identifiable.
    """

    def __init__(self, scc_nodes: list[str], message: str = "") -> None:
        """Initialise with the nodes in the offending SCC.

        Args:
            scc_nodes: Variable names in the strongly connected component.
            message: Optional human-readable detail.
        """
        self.scc_nodes = scc_nodes
        super().__init__(message or f"Treatment/outcome in cycle: {scc_nodes}")


class EffectNotIdentifiableError(Exception):
    """Raised when DoWhy cannot identify an estimand.

    Per handoff §6.6: return not_identifiable, null effect fields.
    """

    def __init__(self, reason: str) -> None:
        """Initialise with a reason string.

        Args:
            reason: Why the effect is not identifiable.
        """
        self.reason = reason
        super().__init__(f"Effect not identifiable: {reason}")


class SnapshotNotFoundError(Exception):
    """Raised when a requested BDG snapshot UUID is not found."""

    def __init__(self, snapshot_id: str) -> None:
        """Initialise with the missing snapshot ID.

        Args:
            snapshot_id: String representation of the missing UUID.
        """
        self.snapshot_id = snapshot_id
        super().__init__(f"Snapshot not found: {snapshot_id}")


class AttributionJobConflictError(Exception):
    """Raised when a duplicate attribution job is submitted."""

    def __init__(self, job_id: str) -> None:
        """Initialise with the conflicting job ID.

        Args:
            job_id: String representation of the conflicting job UUID.
        """
        self.job_id = job_id
        super().__init__(f"Attribution job already active: {job_id}")


class PositivityFailureError(Exception):
    """Raised when the positivity diagnostic fails.

    Per handoff §6.4 line 10: return not_identifiable.
    """

    def __init__(self, details: str = "") -> None:
        """Initialise with diagnostic details.

        Args:
            details: Description of the overlap failure.
        """
        self.details = details
        super().__init__(f"Positivity failure: {details}")


class InsufficientVariationError(Exception):
    """Raised when treatment or outcome has no variation.

    Per handoff §6.4 lines 7–8: return not_identifiable.
    """

    def __init__(self, variable: str) -> None:
        """Initialise with the constant variable name.

        Args:
            variable: Name of the variable with no variation.
        """
        self.variable = variable
        super().__init__(f"No variation in {variable}")


class CausalModelConstructionError(Exception):
    """Raised when DoWhy CausalModel construction fails."""

    def __init__(self, reason: str) -> None:
        """Initialise with the failure reason.

        Args:
            reason: Description of the construction failure.
        """
        self.reason = reason
        super().__init__(f"CausalModel construction failed: {reason}")
