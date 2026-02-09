from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

from src.kernel.ledger import Ledger
from src.kernel.stage1 import classify_batch
from src.kernel.kernel_gate import KernelGate
from src.ingest.dedup import compute_event_hash


class IngestEvent(BaseModel):
    source_id: str = Field(..., description="Stable source identifier")
    event_id: str = Field(..., description="Event identifier")
    source_timestamp: str = Field(..., description="Event timestamp (RFC3339 or epoch)")
    raw_payload: Optional[Union[Dict[str, Any], str]] = Field(
        None, description="Raw event payload (dict or format line)"
    )
    raw_payload_ref: Optional[str] = Field(
        None, description="Pointer to raw payload in storage"
    )
    raw_payload_hash: Optional[str] = Field(
        None, description="sha256 hash of raw payload"
    )
    raw_event: Optional[str] = Field(
        None, description="Raw event line for format parsing (CEF/LEEF/Syslog)"
    )
    format: Optional[str] = Field(
        None, description="Input format: json, cef, leef, syslog"
    )

    class Config:
        extra = "allow"


class IngestBatch(BaseModel):
    events: List[IngestEvent] = Field(..., description="Batch of ingest events")
    profile_parameters: Optional[Dict[str, Any]] = Field(
        None, description="Profile parameters for this request"
    )


class KernelIngestBatch(BaseModel):
    events: List[IngestEvent] = Field(..., description="Batch of ingest events")
    profile_id: Optional[str] = Field("profile.cix", description="Kernel profile id")
    run_graph: Optional[bool] = Field(False, description="Trigger graph run asynchronously")


class KernelDecision(BaseModel):
    action_id: str
    reason_codes: List[str]


class IngestEventResult(BaseModel):
    event_id: str
    evidence_id: str
    decision: KernelDecision
    dedup_key: Optional[str] = None
    dropped_reason: Optional[str] = None


class IngestBatchResponse(BaseModel):
    batch_id: str
    admitted: List[IngestEventResult]
    dropped: List[IngestEventResult]
    dedup: Dict[str, Any]
    run_id: Optional[str] = None
    registry_commit: str


class GraphRunRequest(BaseModel):
    evidence_ids: List[str] = Field(..., description="Evidence IDs to graph")
    profile_id: Optional[str] = Field("profile.cix", description="Kernel profile id")


class GraphRunResponse(BaseModel):
    run_id: str
    status: str


class Artifact(BaseModel):
    artifact_id: str
    type: str
    path: str


class ArtifactList(BaseModel):
    run_id: str
    artifacts: List[Artifact]


class GraphRunStatus(BaseModel):
    run_id: str
    status: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    metrics: Dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    code: str
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    trace_id: str


def create_app() -> FastAPI:
    app = FastAPI(title="CIX Alerts Ingestion API", version="0.1")

    ledger_path = os.getenv("CIX_LEDGER_PATH", "data/ledger.jsonl")
    ledger_path_obj = Path(ledger_path)
    ledger = Ledger(str(ledger_path_obj))

    kernel_ledger_path = os.getenv("CIX_KERNEL_LEDGER_PATH", "data/kernel_ledger.jsonl")

    idempotency_cache: Dict[str, Dict[str, Any]] = {}
    evidence_store: Dict[str, Dict[str, Any]] = {}
    run_store: Dict[str, Dict[str, Any]] = {}
    artifact_store: Dict[str, List[Dict[str, Any]]] = {}

    @app.get("/healthz")
    def healthz() -> Dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/v1/ingest/classify")
    def ingest_classify(
        batch: IngestBatch,
        reset_ledger: bool = Query(False, description="Reset ledger before processing (testing only)"),
    ) -> Dict[str, Any]:
        nonlocal ledger
        try:
            if reset_ledger:
                if ledger_path_obj.exists():
                    ledger_path_obj.unlink()
                ledger = Ledger(str(ledger_path_obj))

            events = [event.dict(exclude_none=True) for event in batch.events]
            result = classify_batch(
                events,
                profile=batch.profile_parameters,
                ledger=ledger,
            )
            return result
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    def _payload_hash(payload: Dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()

    def _error(code: str, message: str, status: int, details: Optional[Dict[str, Any]] = None):
        trace_id = str(uuid.uuid4())
        raise HTTPException(
            status_code=status,
            detail=ErrorResponse(
                code=code, message=message, details=details or {}, trace_id=trace_id
            ).dict(),
        )

    @app.post("/v1/ingest/events", response_model=IngestBatchResponse)
    def ingest_events(
        batch: KernelIngestBatch,
        background_tasks: BackgroundTasks,
        idempotency_key: str = Header(..., alias="Idempotency-Key"),
    ) -> IngestBatchResponse:
        payload_dict = batch.dict()
        payload_hash = _payload_hash(payload_dict)
        cached = idempotency_cache.get(idempotency_key)
        if cached:
            if cached["payload_hash"] != payload_hash:
                _error("IDEMPOTENCY_CONFLICT", "Idempotency key reuse with different payload", 409)
            return cached["response"]

        gate = KernelGate(profile_id=batch.profile_id or "profile.cix", ledger_path=kernel_ledger_path)
        from sdk import hash_evidence  # type: ignore

        admitted_results: List[IngestEventResult] = []
        dropped_results: List[IngestEventResult] = []
        gated_results = []
        halt_triggered = False

        for raw_alert in batch.events:
            result = gate.evaluate(raw_alert.dict(exclude_none=True))
            decision = KernelDecision(
                action_id=result.action_id,
                reason_codes=result.reason_codes,
            )
            evidence_id = hash_evidence(result.ingest_evidence)

            if result.action_id == "ARV.HALT":
                gate.append_ledger(result)
                dropped_results.append(
                    IngestEventResult(
                        event_id=str(result.graph_raw.get("eventId", "unknown")),
                        evidence_id=evidence_id,
                        decision=decision,
                        dropped_reason="HALT",
                    )
                )
                halt_triggered = True
                break

            if result.action_id in {"ARV.ADMIT", "ARV.COMPRESS"}:
                gated_results.append((result, evidence_id, decision))
            else:
                gate.append_ledger(result)
                dropped_results.append(
                    IngestEventResult(
                        event_id=str(result.graph_raw.get("eventId", "unknown")),
                        evidence_id=evidence_id,
                        decision=decision,
                        dropped_reason="GATED",
                    )
                )

        if halt_triggered:
            response = IngestBatchResponse(
                batch_id=str(uuid.uuid4()),
                admitted=[],
                dropped=dropped_results,
                dedup={"duplicates_removed": 0},
                registry_commit=gate.registry_commit,
            )
            idempotency_cache[idempotency_key] = {
                "payload_hash": payload_hash,
                "response": response,
            }
            return response

        seen_hashes = set()
        duplicates_removed = 0
        deduped_results = []
        for result, evidence_id, decision in gated_results:
            event_hash = compute_event_hash(result.graph_raw)
            if event_hash in seen_hashes:
                duplicates_removed += 1
                dropped_results.append(
                    IngestEventResult(
                        event_id=str(result.graph_raw.get("eventId", "unknown")),
                        evidence_id=evidence_id,
                        decision=decision,
                        dedup_key=event_hash,
                        dropped_reason="DEDUP",
                    )
                )
                continue
            seen_hashes.add(event_hash)
            deduped_results.append((result, evidence_id, decision, event_hash))

        for result, evidence_id, decision, event_hash in deduped_results:
            gate.append_ledger(result)
            admitted_results.append(
                IngestEventResult(
                    event_id=str(result.graph_raw.get("eventId", "unknown")),
                    evidence_id=evidence_id,
                    decision=decision,
                    dedup_key=event_hash,
                )
            )
            evidence_store[evidence_id] = result.graph_raw

        response = IngestBatchResponse(
            batch_id=str(uuid.uuid4()),
            admitted=admitted_results,
            dropped=dropped_results,
            dedup={"duplicates_removed": duplicates_removed},
            registry_commit=gate.registry_commit,
        )

        if batch.run_graph and admitted_results:
            run_id = str(uuid.uuid4())
            response.run_id = run_id
            run_store[run_id] = {
                "run_id": run_id,
                "status": "PENDING",
            }

            def _run_graph_task(run_id: str, evidence_ids: List[str]) -> None:
                run_store[run_id]["status"] = "RUNNING"
                run_store[run_id]["started_at"] = datetime.now(timezone.utc).isoformat()
                raw_events = [evidence_store[eid] for eid in evidence_ids if eid in evidence_store]
                from src.pipeline.graph_pipeline import run_graph_pipeline

                output_dir = f"data/runs/{run_id}"
                artifacts = run_graph_pipeline(raw_events, output_dir=output_dir, enable_kernel=False)
                artifact_list: List[Dict[str, Any]] = []
                for path in artifacts["reports"]:
                    artifact_list.append({"artifact_id": str(uuid.uuid4()), "type": "report_md", "path": path})
                for path in artifacts["ledgers"]:
                    artifact_list.append({"artifact_id": str(uuid.uuid4()), "type": "ledger_json", "path": path})
                for path in artifacts["graphs_html"]:
                    artifact_list.append({"artifact_id": str(uuid.uuid4()), "type": "graph_html", "path": path})
                for path in artifacts["graphs_png"]:
                    artifact_list.append({"artifact_id": str(uuid.uuid4()), "type": "graph_png", "path": path})
                artifact_store[run_id] = artifact_list
                run_store[run_id]["status"] = "SUCCEEDED"
                run_store[run_id]["finished_at"] = datetime.now(timezone.utc).isoformat()

            background_tasks.add_task(
                _run_graph_task, run_id, [r.evidence_id for r in admitted_results]
            )

        idempotency_cache[idempotency_key] = {
            "payload_hash": payload_hash,
            "response": response,
        }
        return response

    @app.post("/v1/runs/graph", response_model=GraphRunResponse)
    def create_graph_run(
        request: GraphRunRequest,
        background_tasks: BackgroundTasks,
        idempotency_key: str = Header(..., alias="Idempotency-Key"),
    ) -> GraphRunResponse:
        payload_dict = request.dict()
        payload_hash = _payload_hash(payload_dict)
        cached = idempotency_cache.get(idempotency_key)
        if cached:
            if cached["payload_hash"] != payload_hash:
                _error("IDEMPOTENCY_CONFLICT", "Idempotency key reuse with different payload", 409)
            return cached["response"]

        missing = [eid for eid in request.evidence_ids if eid not in evidence_store]
        if missing:
            _error("MISSING_EVIDENCE", "Evidence IDs not found", 422, {"missing": missing})

        run_id = str(uuid.uuid4())
        run_store[run_id] = {
            "run_id": run_id,
            "status": "PENDING",
        }

        def _run_graph_task(run_id: str, evidence_ids: List[str]) -> None:
            run_store[run_id]["status"] = "RUNNING"
            run_store[run_id]["started_at"] = datetime.now(timezone.utc).isoformat()
            raw_events = [evidence_store[eid] for eid in evidence_ids if eid in evidence_store]
            from src.pipeline.graph_pipeline import run_graph_pipeline

            output_dir = f"data/runs/{run_id}"
            artifacts = run_graph_pipeline(raw_events, output_dir=output_dir, enable_kernel=False)
            artifact_list: List[Dict[str, Any]] = []
            for path in artifacts["reports"]:
                artifact_list.append({"artifact_id": str(uuid.uuid4()), "type": "report_md", "path": path})
            for path in artifacts["ledgers"]:
                artifact_list.append({"artifact_id": str(uuid.uuid4()), "type": "ledger_json", "path": path})
            for path in artifacts["graphs_html"]:
                artifact_list.append({"artifact_id": str(uuid.uuid4()), "type": "graph_html", "path": path})
            for path in artifacts["graphs_png"]:
                artifact_list.append({"artifact_id": str(uuid.uuid4()), "type": "graph_png", "path": path})
            artifact_store[run_id] = artifact_list
            run_store[run_id]["status"] = "SUCCEEDED"
            run_store[run_id]["finished_at"] = datetime.now(timezone.utc).isoformat()

        background_tasks.add_task(_run_graph_task, run_id, request.evidence_ids)

        response = GraphRunResponse(run_id=run_id, status="PENDING")
        idempotency_cache[idempotency_key] = {"payload_hash": payload_hash, "response": response}
        return response

    @app.get("/v1/runs/{run_id}", response_model=GraphRunStatus)
    def get_run(run_id: str) -> GraphRunStatus:
        run = run_store.get(run_id)
        if not run:
            _error("RUN_NOT_FOUND", "Run not found", 404)
        return GraphRunStatus(**run)

    @app.get("/v1/runs/{run_id}/artifacts", response_model=ArtifactList)
    def get_run_artifacts(run_id: str) -> ArtifactList:
        artifacts = artifact_store.get(run_id)
        if artifacts is None:
            _error("RUN_NOT_FOUND", "Run not found", 404)
        return ArtifactList(run_id=run_id, artifacts=[Artifact(**a) for a in artifacts])

    return app


app = create_app()
