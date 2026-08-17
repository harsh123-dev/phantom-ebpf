from __future__ import annotations


class EvidenceNotFoundError(Exception):
    """Raised when incident evidence is not found or not tenant-visible."""

    error_code: str = "EVIDENCE_NOT_FOUND"

    def __init__(self, incident_id: str, missing_type: str, missing_id: str) -> None:
        super().__init__(incident_id, missing_type, missing_id)
        self.incident_id: str = incident_id
        self.missing_type: str = missing_type
        self.missing_id: str = missing_id

    def __str__(self) -> str:
        return (
            f"Evidence not found for incident {self.incident_id!r}: "
            f"{self.missing_type} {self.missing_id!r}"
        )


class ReportAssemblyError(Exception):
    """Raised when an incident report cannot be assembled."""

    error_code: str = "REPORT_ASSEMBLY_ERROR"

    def __init__(self, incident_id: str, reason: str) -> None:
        super().__init__(incident_id, reason)
        self.incident_id: str = incident_id
        self.reason: str = reason

    def __str__(self) -> str:
        return f"Report assembly failed for incident {self.incident_id!r}: {self.reason}"


class ReportStorageError(Exception):
    """Raised when a report document cannot be stored."""

    error_code: str = "REPORT_STORAGE_ERROR"

    def __init__(self, path: str, reason: str) -> None:
        super().__init__(path, reason)
        self.path: str = path
        self.reason: str = reason

    def __str__(self) -> str:
        return f"Report storage failed for {self.path!r}: {self.reason}"


class ReportGenerationTimeoutError(Exception):
    """Raised when report generation exceeds its allowed time budget."""

    error_code: str = "REPORT_GENERATION_TIMEOUT"

    def __init__(self, incident_id: str, elapsed_seconds: float) -> None:
        super().__init__(incident_id, elapsed_seconds)
        self.incident_id: str = incident_id
        self.elapsed_seconds: float = elapsed_seconds

    def __str__(self) -> str:
        return (
            f"Report generation timed out for incident {self.incident_id!r} "
            f"after {self.elapsed_seconds:.3f} seconds"
        )
