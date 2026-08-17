"""
services/ebpf-agent/application/use_cases/generate_contract.py

GenerateContractUseCase: trains a Markov model from a stream of resolved
runtime events for a given image_digest/PURL, signs the model with cosign,
and stores the behavioral contract.

Algorithm invocation:
  1. Load resolved events for the training window from the event store.
  2. Tokenize events via tau().
  3. Call domain.markov.chain.train() (Algorithm 1).
  4. Serialize the model to JSON.
  5. Compute the model digest (sha256 of the serialized JSON).
  6. Sign with cosign (cosign sign-blob --bundle=...).
  7. Persist the contract record via the contract store port.
  8. Return the GenerateContractResult DTO.

Clean Architecture compliance:
- This file is in application/. It imports from domain/ only.
- It depends on ports (abstract interfaces) defined in application/ports/.
- No infrastructure imports here.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import structlog
from app.domain.markov.chain import MarkovModel, Token, tau, train
from app.domain.markov.serializer import serialize as serialize_model

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Ports (abstract interfaces — implementations live in infrastructure/)
# ---------------------------------------------------------------------------


class EventSequencePort:
    """Abstract port for fetching training event sequences for an image.

    Implementations live in infrastructure/; the use case depends only
    on this interface.
    """

    async def fetch_training_sequences(
        self,
        image_digest: str,
        purl: str,
        window_start: datetime,
        window_end: datetime,
    ) -> list[list[tuple[str, str, str, str]]]:
        """Fetch tokenized event sequences for training.

        Args:
            image_digest: sha256 image digest used to scope events.
            purl: SBOM PURL for the component being modeled.
            window_start: Start of the training window (UTC).
            window_end: End of the training window (UTC).

        Returns:
            A list of sequences; each sequence is a list of 4-tuples
            (event_type, operation_class, resource_class, privilege_class).

        Raises:
            NotImplementedError: Must be overridden by infrastructure adapter.
        """
        raise NotImplementedError


class ContractSignerPort:
    """Abstract port for signing the serialized contract model.

    The implementation calls cosign sign-blob and returns the bundle URI.
    """

    async def sign(
        self,
        content_bytes: bytes,
        content_digest: str,
    ) -> tuple[str, str]:
        """Sign content and return (bundle_uri, signing_identity).

        Args:
            content_bytes: The raw bytes to sign.
            content_digest: The sha256 digest of content_bytes (for verification).

        Returns:
            A 2-tuple of (bundle_uri, signing_identity).

        Raises:
            NotImplementedError: Must be overridden by infrastructure adapter.
        """
        raise NotImplementedError


class ContractStorePort:
    """Abstract port for persisting a signed behavioral contract."""

    async def save_contract(
        self,
        contract_id: uuid.UUID,
        image_digest: str,
        purl: str,
        model_json: str,
        model_digest: str,
        bundle_uri: str,
        signing_identity: str,
        created_at: datetime,
        k_star: int,
        bic_score: float,
        training_n: int,
    ) -> None:
        """Persist the behavioral contract record.

        Args:
            contract_id: The UUID for this contract.
            image_digest: sha256 image digest.
            purl: SBOM PURL for the modeled component.
            model_json: Serialized MarkovModel JSON.
            model_digest: sha256 digest of model_json.
            bundle_uri: Cosign bundle URI returned by the signer.
            signing_identity: Identity string from cosign signing.
            created_at: UTC timestamp of contract creation.
            k_star: Selected Markov order.
            bic_score: BIC score of the selected model.
            training_n: Total training token count.

        Raises:
            NotImplementedError: Must be overridden by infrastructure adapter.
        """
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Command / Result DTOs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GenerateContractCommand:
    """Command object for GenerateContractUseCase.

    Attributes:
        image_digest: sha256 image digest to scope training events.
        purl: SBOM PURL for the component to model.
        tenant_id: Tenant UUID for multi-tenant isolation.
        window_start: Training window start (UTC, timezone-aware).
        window_end: Training window end (UTC, timezone-aware).
        k_max: Maximum candidate Markov order. Default 5.
        minimum_training_tokens: Reject training if fewer tokens available.
    """

    image_digest: str
    purl: str
    tenant_id: uuid.UUID
    window_start: datetime
    window_end: datetime
    k_max: int = 5
    minimum_training_tokens: int = 100


@dataclass(frozen=True)
class GenerateContractResult:
    """Result DTO from a successful contract generation.

    Attributes:
        contract_id: UUID of the persisted contract.
        image_digest: sha256 image digest.
        purl: SBOM PURL.
        model_digest: sha256 of the serialized model JSON.
        bundle_uri: Cosign bundle URI.
        k_star: Selected Markov order.
        bic_score: BIC score.
        training_n: Training token count.
        created_at: UTC timestamp.
    """

    contract_id: uuid.UUID
    image_digest: str
    purl: str
    model_digest: str
    bundle_uri: str
    k_star: int
    bic_score: float
    training_n: int
    created_at: datetime


class InsufficientTrainingDataError(Exception):
    """Raised when fewer training tokens than the minimum are available.

    Attributes:
        image_digest: The image digest for which training was attempted.
        purl: The PURL for which training was attempted.
        available_n: How many tokens were found.
        required_n: How many tokens were required.
    """

    def __init__(self, image_digest: str, purl: str, available_n: int, required_n: int) -> None:
        """Initialise the error.

        Args:
            image_digest: The image digest.
            purl: The PURL.
            available_n: Available token count.
            required_n: Required token count.
        """
        self.image_digest = image_digest
        self.purl = purl
        self.available_n = available_n
        self.required_n = required_n
        super().__init__(
            f"Insufficient training data for {purl} @ {image_digest}: "
            f"{available_n} < {required_n} tokens"
        )


# ---------------------------------------------------------------------------
# Use case
# ---------------------------------------------------------------------------


class GenerateContractUseCase:
    """Trains a Markov model and produces a signed behavioral contract.

    Args:
        event_seq_port: Port for fetching training event sequences.
        signer_port: Port for cosign signature creation.
        store_port: Port for persisting the contract record.
    """

    def __init__(
        self,
        event_seq_port: EventSequencePort,
        signer_port: ContractSignerPort,
        store_port: ContractStorePort,
    ) -> None:
        """Initialise with injected ports.

        Args:
            event_seq_port: Training data source.
            signer_port: Cosign signing adapter.
            store_port: Contract persistence adapter.
        """
        self._event_seq = event_seq_port
        self._signer    = signer_port
        self._store     = store_port

    async def execute(self, cmd: GenerateContractCommand) -> GenerateContractResult:
        """Execute the contract generation pipeline.

        Args:
            cmd: The GenerateContractCommand with all parameters.

        Returns:
            A GenerateContractResult describing the created contract.

        Raises:
            InsufficientTrainingDataError: If training data is below the threshold.
            Exception: Re-raises any signing or storage errors.
        """
        bound_log = log.bind(
            image_digest=cmd.image_digest,
            purl=cmd.purl,
            tenant_id=str(cmd.tenant_id),
        )

        # --- Step 1: Fetch training sequences ---
        bound_log.info("generate_contract.fetch_sequences")
        raw_sequences = await self._event_seq.fetch_training_sequences(
            image_digest=cmd.image_digest,
            purl=cmd.purl,
            window_start=cmd.window_start,
            window_end=cmd.window_end,
        )

        # Convert raw 4-tuples to Token using tau() for normalization.
        sequences: list[list[Token]] = [
            [tau(e[0], e[1], e[2], e[3]) for e in seq]
            for seq in raw_sequences
        ]

        total_tokens = sum(len(s) for s in sequences)
        bound_log.info(
            "generate_contract.sequences_loaded",
            sequence_count=len(sequences),
            total_tokens=total_tokens,
        )

        if total_tokens < cmd.minimum_training_tokens:
            raise InsufficientTrainingDataError(
                image_digest=cmd.image_digest,
                purl=cmd.purl,
                available_n=total_tokens,
                required_n=cmd.minimum_training_tokens,
            )

        # --- Step 2: Train Markov model (Algorithm 1) ---
        bound_log.info("generate_contract.training", k_max=cmd.k_max)
        model: MarkovModel = train(
            sequences=sequences,
            k_max=cmd.k_max,
        )
        bound_log.info(
            "generate_contract.model_trained",
            k_star=model.k_star,
            bic_score=model.bic_score,
            alphabet_size=model.m,
        )

        # --- Step 3: Serialize ---
        model_json: str = serialize_model(model)
        model_bytes: bytes = model_json.encode("utf-8")

        # --- Step 4: Compute model digest ---
        model_digest = "sha256:" + hashlib.sha256(model_bytes).hexdigest()
        bound_log.info("generate_contract.model_digest", digest=model_digest)

        # --- Step 5: Sign with cosign ---
        bound_log.info("generate_contract.signing")
        bundle_uri, signing_identity = await self._signer.sign(
            content_bytes=model_bytes,
            content_digest=model_digest,
        )
        bound_log.info(
            "generate_contract.signed",
            bundle_uri=bundle_uri,
            signing_identity=signing_identity,
        )

        # --- Step 6: Persist ---
        contract_id = uuid.uuid4()
        created_at  = datetime.now(tz=UTC)
        await self._store.save_contract(
            contract_id=contract_id,
            image_digest=cmd.image_digest,
            purl=cmd.purl,
            model_json=model_json,
            model_digest=model_digest,
            bundle_uri=bundle_uri,
            signing_identity=signing_identity,
            created_at=created_at,
            k_star=model.k_star,
            bic_score=model.bic_score,
            training_n=model.N,
        )
        bound_log.info("generate_contract.saved", contract_id=str(contract_id))

        return GenerateContractResult(
            contract_id=contract_id,
            image_digest=cmd.image_digest,
            purl=cmd.purl,
            model_digest=model_digest,
            bundle_uri=bundle_uri,
            k_star=model.k_star,
            bic_score=model.bic_score,
            training_n=model.N,
            created_at=created_at,
        )
