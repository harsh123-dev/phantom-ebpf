"""HTTP evidence sink and durable passive TCP receipt listener."""
from __future__ import annotations

import asyncio
import logging
import os
import re
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from research.evaluation.evidence_store import (
    DurableEvidenceSink,
    ReceiptConflictError,
    ReceiptIntegrityError,
    record_attempt_unknown,
)
from research.evaluation.oracle import evaluate_signed_observation, load_trusted_oracle_keys
from research.evaluation.oracle import (
    InvalidOracleSignatureError, OracleVerificationError, RevokedOracleKeyError,
    StaleOracleObservationError,
    UnknownOracleKeyError, UnsupportedOracleAlgorithmError,
)

log = logging.getLogger("phantom.evidence_sink")


class ReceiptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    run_id: str = Field(min_length=1, max_length=200)
    scenario_id: str = Field(min_length=1, max_length=200)
    event_id: str | None = None
    workload: dict[str, Any]
    processing_outcome: str = Field(min_length=1, max_length=100)
    provenance: dict[str, Any]
    signed_observation: dict[str, Any] | None = None

    @field_validator("event_id")
    @classmethod
    def valid_event_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return str(uuid.UUID(value))
        except (TypeError, ValueError) as exc:
            raise ValueError("event_id must be a UUID") from exc

    @field_validator("workload")
    @classmethod
    def valid_workload_identity(cls, value: dict[str, Any]) -> dict[str, Any]:
        for field in ("cluster", "namespace", "name"):
            if not isinstance(value.get(field), str) or not value[field].strip():
                raise ValueError(f"workload.{field} must be a nonempty identity string")
        digest = value.get("image_digest")
        if digest is not None and (not isinstance(digest, str)
                                   or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)):
            raise ValueError("workload.image_digest must be immutable sha256 or null")
        return value


class SinkRuntime:
    def __init__(self, db_path: str, trust_path: str, tcp_ports: tuple[int, ...]):
        self.store = DurableEvidenceSink(db_path)
        self.trust_path = trust_path
        self.tcp_ports = tcp_ports
        self.trusted_keys = load_trusted_oracle_keys(trust_path)
        self.trusted_keys.revoked_key_ids = self.store.apply_trust_configuration(self.trusted_keys)
        self.servers: list[asyncio.AbstractServer] = []
        self.ready = True

    async def start(self) -> None:
        for port in self.tcp_ports:
            server = await asyncio.start_server(
                lambda reader, writer, bound_port=port: self._handle_tcp(
                    reader, writer, bound_port
                ), "0.0.0.0", port,
            )
            self.servers.append(server)

    async def close(self) -> None:
        for server in self.servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in self.servers))
        self.servers.clear()

    async def _handle_tcp(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, local_port: int,
    ) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        try:
            try:
                content = await asyncio.wait_for(reader.read(65536), timeout=2.0)
            except TimeoutError:
                content = b""
            self.store.record_tcp_connection(
                local_port=local_port, peer_address=str(peer[0]), peer_port=int(peer[1]),
                content=content,
            )
        except Exception:
            # The connection closes, but no successful receipt is claimed.
            log.exception("tcp_receipt_persistence_failed", extra={"local_port": local_port})
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


def create_app(
    *, db_path: str | None = None, trust_path: str | None = None,
    tcp_ports: tuple[int, ...] | None = None,
) -> FastAPI:
    db_path = db_path or os.environ.get("PHANTOM_SINK_DB", "/data/evidence.sqlite3")
    trust_path = trust_path or os.environ.get(
        "PHANTOM_ORACLE_TRUSTED_KEYS_FILE", "/etc/phantom-oracle/trusted-keys.json"
    )
    ports = tcp_ports if tcp_ports is not None else tuple(
        int(port) for port in os.environ.get("PHANTOM_SINK_TCP_PORTS", "8443,4445,4446,8080").split(",")
    )
    runtime = SinkRuntime(db_path, trust_path, ports)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await runtime.start()
        try:
            yield
        finally:
            await runtime.close()

    app = FastAPI(title="PHANTOM evidence sink", version="1.0", lifespan=lifespan)
    app.state.runtime = runtime

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def ready() -> dict[str, str]:
        if not runtime.ready:
            raise HTTPException(status_code=503, detail="sink not ready")
        return {"status": "ready"}

    @app.post("/v1/receipts", status_code=201)
    def submit_receipt(request: ReceiptRequest) -> dict[str, Any]:
        try:
            if request.signed_observation is None:
                receipt = record_attempt_unknown(
                    runtime.store, run_id=request.run_id, scenario_id=request.scenario_id,
                    event_id=request.event_id, workload=request.workload,
                    processing_outcome=request.processing_outcome, provenance=request.provenance,
                )
            else:
                receipt = runtime.store.submit_signed_observation(
                    run_id=request.run_id, scenario_id=request.scenario_id,
                    workload=request.workload, processing_outcome=request.processing_outcome,
                    provenance=request.provenance, signed_observation=request.signed_observation,
                    trusted_keys=runtime.trusted_keys, expected_event_id=request.event_id,
                )
            # submit returns only after SQLite's FULL synchronous transaction commits.
            return receipt
        except (InvalidOracleSignatureError, RevokedOracleKeyError, StaleOracleObservationError,
                UnknownOracleKeyError) as exc:
            log.warning("oracle_signature_rejected", extra={"reason": type(exc).__name__})
            raise HTTPException(status_code=401, detail="oracle signature is not trusted or valid") from exc
        except UnsupportedOracleAlgorithmError as exc:
            log.warning("oracle_algorithm_rejected", extra={"reason": type(exc).__name__})
            raise HTTPException(status_code=422, detail="oracle signature algorithm is unsupported") from exc
        except OracleVerificationError as exc:
            log.warning("oracle_observation_rejected", extra={"reason": type(exc).__name__})
            raise HTTPException(status_code=422, detail="oracle observation is invalid") from exc
        except ReceiptConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/v1/receipts/{receipt_id}")
    def get_receipt(receipt_id: str) -> dict[str, Any]:
        try:
            return runtime.store.get(receipt_id)
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=404, detail="receipt not found") from exc
        except ReceiptIntegrityError as exc:
            raise HTTPException(status_code=500, detail="receipt integrity check failed") from exc

    @app.get("/v1/receipts/{receipt_id}/verify")
    def verify_receipt(receipt_id: str) -> dict[str, Any]:
        try:
            receipt = runtime.store.get(receipt_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="receipt not found") from exc
        except ReceiptIntegrityError as exc:
            raise HTTPException(status_code=409, detail="receipt integrity check failed") from exc
        verification = receipt.get("oracle_verification", {})
        authenticity = "unverified"
        observation = receipt.get("oracle_observation")
        if observation is not None:
            observed_at = observation.get("payload", {}).get("observed_at")
            try:
                from datetime import datetime

                result, verified = evaluate_signed_observation(
                    observation, runtime.trusted_keys,
                    expected_run_id=receipt["run_id"],
                    expected_scenario_id=receipt["scenario_id"],
                    expected_workload=receipt["workload"],
                    # Freshness was enforced at ingestion. Re-verification uses
                    # the signed timestamp as the reference clock so old stored
                    # receipts remain verifiable without relaxing signature checks.
                    now=datetime.fromisoformat(str(observed_at).replace("Z", "+00:00")),
                )
                if result.to_dict()["outcome"] != receipt["oracle_result"]["outcome"]:
                    raise ValueError("stored oracle outcome differs from signed evidence")
                if verified.payload_sha256 != verification.get("payload_sha256"):
                    raise ValueError("stored oracle payload hash differs from its signature")
                if (verified.signature_sha256 != verification.get("signature_sha256")
                        or verified.key_id != verification.get("key_id")
                        or str(verified.payload["observation_id"]) != verification.get("observation_id")):
                    raise ValueError("stored oracle verification metadata does not match signature")
                authenticity = "verified"
            except Exception as exc:  # noqa: BLE001
                raise HTTPException(status_code=409, detail="oracle signature verification failed") from exc
        return {"receipt_id": receipt_id, "integrity": "valid", "sha256": receipt["integrity_sha256"],
                "authenticity": authenticity,
                "independence": verification.get("independence_status", "unverified")}

    @app.get("/v1/runs/{run_id}/receipts")
    def list_run(run_id: str) -> list[dict[str, Any]]:
        return runtime.store.list_run(run_id)

    @app.get("/v1/tcp-receipts/{receipt_id}")
    def get_tcp_receipt(receipt_id: str) -> dict[str, Any]:
        try:
            return runtime.store.get_tcp_connection(receipt_id)
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=404, detail="receipt not found") from exc

    return app


