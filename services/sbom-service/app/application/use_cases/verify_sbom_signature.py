"""
services/sbom-service/app/application/use_cases/verify_sbom_signature.py

Use cases for cosign signature verification:

- EnqueueVerificationUseCase: POST /api/v1/sboms/{sbom_id}/verification
  Enqueues a new async verification job; rejects if one is already running.

- GetVerificationResultUseCase: GET /api/v1/sboms/{sbom_id}/verification
  Returns the current or final verification result.

- RunVerificationUseCase: internal use case invoked by the worker; performs
  the actual cosign call and updates both the job and SBOM entity state.

Imports only from domain/ and application/ports/.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import structlog

from app.application.ports.repositories import (
    SbomRepositoryPort,
    SbomVerifierPort,
    VerificationJobRepositoryPort,
)
from app.domain.entities import VerificationJob
from app.domain.exceptions import (
    VerificationAlreadyInProgressError,
    VerificationJobNotFoundError,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Enqueue verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnqueueVerificationCommand:
    """Input command for EnqueueVerificationUseCase.

    Attributes:
        sbom_id: UUID of the SBOM to verify.
        tenant_id: Tenant scope.
        expected_identity: Expected Fulcio signing identity; 1..512 chars.
        expected_issuer: Expected OIDC issuer URI.
        rekor_required: Whether a Rekor transparency log entry is mandatory.
    """

    sbom_id: uuid.UUID
    tenant_id: uuid.UUID
    expected_identity: str
    expected_issuer: str
    rekor_required: bool


@dataclass(frozen=True)
class EnqueueVerificationResult:
    """Output result of EnqueueVerificationUseCase.

    Attributes:
        verification_job_id: UUID of the newly created job.
        sbom_id: UUID of the SBOM being verified.
        status: Always ``"queued"`` on successful enqueue.
        submitted_at: UTC timestamp when the job was created.
    """

    verification_job_id: uuid.UUID
    sbom_id: uuid.UUID
    status: str
    submitted_at: datetime


class EnqueueVerificationUseCase:
    """Enqueue a cosign verification job for ``POST /api/v1/sboms/{sbom_id}/verification``.

    Rejects with VerificationAlreadyInProgressError if a job is already
    in the ``queued`` or ``running`` state for this SBOM.

    Args:
        sbom_repo: Repository for SBOM existence checks.
        job_repo: Repository for verification job persistence.
    """

    def __init__(
        self,
        sbom_repo: SbomRepositoryPort,
        job_repo: VerificationJobRepositoryPort,
    ) -> None:
        """Initialise with injected repositories.

        Args:
            sbom_repo: Repository for SBOM existence checks.
            job_repo: Repository for verification job persistence.
        """
        self._sbom_repo = sbom_repo
        self._job_repo = job_repo

    async def execute(
        self, command: EnqueueVerificationCommand
    ) -> EnqueueVerificationResult:
        """Execute the verification enqueueing workflow.

        Args:
            command: The enqueue command.

        Returns:
            EnqueueVerificationResult with the queued job details.

        Raises:
            SbomNotFoundError: If the SBOM does not exist in this tenant.
            VerificationAlreadyInProgressError: If a job is already running.
        """
        bound_log = log.bind(
            sbom_id=str(command.sbom_id),
            tenant_id=str(command.tenant_id),
        )
        bound_log.info("verify_sbom.enqueue_started")

        # 1. Verify the SBOM exists (raises SbomNotFoundError → 404).
        await self._sbom_repo.get_by_id(
            sbom_id=command.sbom_id,
            tenant_id=command.tenant_id,
        )

        # 2. Check for an existing in-progress job (→ 409).
        try:
            existing_job = await self._job_repo.get_by_sbom_id(
                sbom_id=command.sbom_id,
                tenant_id=command.tenant_id,
            )
            if existing_job.status in {"queued", "running"}:
                raise VerificationAlreadyInProgressError(str(command.sbom_id))
        except VerificationJobNotFoundError:
            pass  # No existing job — safe to enqueue.

        # 3. Create and persist the new job.
        now = datetime.now(tz=UTC)
        job = VerificationJob(
            verification_job_id=uuid.uuid4(),
            sbom_id=command.sbom_id,
            tenant_id=command.tenant_id,
            expected_identity=command.expected_identity,
            expected_issuer=command.expected_issuer,
            rekor_required=command.rekor_required,
            status="queued",
            submitted_at=now,
        )
        await self._job_repo.save(job)
        bound_log.info(
            "verify_sbom.job_enqueued",
            verification_job_id=str(job.verification_job_id),
        )

        return EnqueueVerificationResult(
            verification_job_id=job.verification_job_id,
            sbom_id=command.sbom_id,
            status="queued",
            submitted_at=now,
        )


# ---------------------------------------------------------------------------
# Get verification result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GetVerificationResultQuery:
    """Input query for GetVerificationResultUseCase.

    Attributes:
        sbom_id: UUID of the SBOM.
        tenant_id: Tenant scope.
    """

    sbom_id: uuid.UUID
    tenant_id: uuid.UUID


@dataclass(frozen=True)
class GetVerificationResultResult:
    """Output result of GetVerificationResultUseCase.

    Attributes:
        verification_job_id: UUID of the verification job.
        sbom_id: UUID of the SBOM being verified.
        status: Current job status.
        signing_identity: Verified identity; None if pending.
        issuer: Verified issuer URI; None if pending.
        rekor_entry_uuid: Rekor log entry UUID; None if absent.
        verified_at: UTC timestamp of success; None if pending or failed.
        failure_reason: Human-readable failure reason; None if not failed.
    """

    verification_job_id: uuid.UUID
    sbom_id: uuid.UUID
    status: str
    signing_identity: str | None
    issuer: str | None
    rekor_entry_uuid: uuid.UUID | None
    verified_at: datetime | None
    failure_reason: str | None

    @classmethod
    def from_job(cls, job: VerificationJob) -> GetVerificationResultResult:
        """Build the result DTO from a domain entity.

        Args:
            job: The VerificationJob domain entity.

        Returns:
            GetVerificationResultResult populated from the entity.
        """
        return cls(
            verification_job_id=job.verification_job_id,
            sbom_id=job.sbom_id,
            status=job.status,
            signing_identity=job.signing_identity,
            issuer=job.issuer,
            rekor_entry_uuid=job.rekor_entry_uuid,
            verified_at=job.completed_at if job.status == "verified" else None,
            failure_reason=job.failure_reason,
        )


class GetVerificationResultUseCase:
    """Retrieve the current or final verification result for a SBOM.

    Serves ``GET /api/v1/sboms/{sbom_id}/verification``.

    Args:
        sbom_repo: Repository for SBOM existence checks.
        job_repo: Repository for verification job reads.
    """

    def __init__(
        self,
        sbom_repo: SbomRepositoryPort,
        job_repo: VerificationJobRepositoryPort,
    ) -> None:
        """Initialise with injected repositories.

        Args:
            sbom_repo: Repository for SBOM existence checks.
            job_repo: Repository for verification job reads.
        """
        self._sbom_repo = sbom_repo
        self._job_repo = job_repo

    async def execute(
        self, query: GetVerificationResultQuery
    ) -> GetVerificationResultResult:
        """Execute the verification result retrieval.

        Args:
            query: The retrieval query.

        Returns:
            GetVerificationResultResult with current job state.

        Raises:
            SbomNotFoundError: If the SBOM does not exist.
            VerificationJobNotFoundError: If no job has been submitted.
        """
        log.info(
            "verify_sbom.get_result_started",
            sbom_id=str(query.sbom_id),
            tenant_id=str(query.tenant_id),
        )
        # Guard: SBOM must exist.
        await self._sbom_repo.get_by_id(
            sbom_id=query.sbom_id,
            tenant_id=query.tenant_id,
        )
        job = await self._job_repo.get_by_sbom_id(
            sbom_id=query.sbom_id,
            tenant_id=query.tenant_id,
        )
        return GetVerificationResultResult.from_job(job)


# ---------------------------------------------------------------------------
# Run verification (internal, called by the background worker)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RunVerificationCommand:
    """Internal command for the background worker to execute a verification job.

    Attributes:
        verification_job_id: UUID of the job to execute.
        tenant_id: Tenant scope.
    """

    verification_job_id: uuid.UUID
    tenant_id: uuid.UUID


class RunVerificationUseCase:
    """Execute a cosign verification job and update both job and SBOM state.

    This use case is called by the background worker (not the HTTP request path).
    It is NOT a replacement for the HTTP-facing EnqueueVerificationUseCase.

    Args:
        sbom_repo: Repository for SBOM reads and verification-state updates.
        job_repo: Repository for verification job reads and updates.
        verifier: Port to the cosign/Sigstore adapter.
    """

    def __init__(
        self,
        sbom_repo: SbomRepositoryPort,
        job_repo: VerificationJobRepositoryPort,
        verifier: SbomVerifierPort,
    ) -> None:
        """Initialise with injected repositories and verifier.

        Args:
            sbom_repo: Repository for SBOM reads and updates.
            job_repo: Repository for verification job reads and updates.
            verifier: Port to the cosign/Sigstore adapter.
        """
        self._sbom_repo = sbom_repo
        self._job_repo = job_repo
        self._verifier = verifier

    async def execute(self, command: RunVerificationCommand) -> None:
        """Execute cosign verification and persist the result.

        Args:
            command: The run command containing the job UUID.

        Raises:
            VerificationJobNotFoundError: If the job no longer exists.
        """
        bound_log = log.bind(
            verification_job_id=str(command.verification_job_id),
            tenant_id=str(command.tenant_id),
        )
        bound_log.info("verify_sbom.run_started")

        # 1. Load the job (raises VerificationJobNotFoundError if absent).
        job = await self._job_repo.get_by_sbom_id(
            sbom_id=command.verification_job_id,   # fallback lookup
            tenant_id=command.tenant_id,
        )

        # Mark as running.
        import dataclasses

        job = dataclasses.replace(job, status="running")
        await self._job_repo.update(job)

        # 2. Load the SBOM.
        sbom = await self._sbom_repo.get_by_id(
            sbom_id=job.sbom_id,
            tenant_id=command.tenant_id,
        )

        now = datetime.now(tz=UTC)

        try:
            # 3. Call the cosign adapter (may raise SignatureVerificationError
            #    or VerificationServiceUnavailableError).
            updated_sbom = await self._verifier.verify(
                sbom=sbom,
                expected_identity=job.expected_identity,
                expected_issuer=job.expected_issuer,
                rekor_required=job.rekor_required,
            )

            # 4a. Verification succeeded — update job and SBOM.
            job = dataclasses.replace(
                job,
                status="verified",
                completed_at=now,
                signing_identity=updated_sbom.signing_identity,
                issuer=updated_sbom.issuer,
                rekor_entry_uuid=updated_sbom.rekor_entry_uuid,
                failure_reason=None,
            )
            bound_log.info("verify_sbom.run_succeeded")

        except Exception as exc:  # noqa: BLE001
            # 4b. Verification failed — mark both job and SBOM as failed.
            job = dataclasses.replace(
                job,
                status="failed",
                completed_at=now,
                failure_reason=str(exc),
            )
            updated_sbom = sbom.mark_verification_failed(reason=str(exc))
            bound_log.warning("verify_sbom.run_failed", error=str(exc))

        # 5. Persist updated state.
        await self._job_repo.update(job)
        await self._sbom_repo.update_verification(updated_sbom)
