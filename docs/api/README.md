# CIX Alerts API (Consolidated Pipeline)

## Run (Docker)

```bash
# From repo root
export AXODEN_KERNEL_PATH=/Users/erkanyalcinkaya/projects/axoden-kernel

docker compose up --build -d
```

The API listens on `http://localhost:8009`.

## Endpoints (v1)

- `POST /v1/ingest/events`
  - Ingests SIEM/SOAR events into the evidence ledger (kernel canonicalization).
- `POST /v1/runs/graph`
  - Builds a graph run from a list of ingested event IDs.
- `GET /v1/runs/{run_id}`
  - Fetches run status and metadata.
- `GET /v1/runs/{run_id}/artifacts`
  - Lists artifacts (graph HTML, reports, etc.) for a run.

See `openapi.yaml` for the full schema.

## Quickstart

```bash
curl -X POST http://localhost:8009/v1/ingest/events \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: demo-ingest-1" \
  -d '{"events":[{"source_id":"demo","event_id":"e1","source_timestamp":"2026-02-03T12:00:00Z","raw_payload":{"message":"test"}}],"profile_id":"axoden-cix-1-v0.2.0"}'
```

```bash
curl -X POST http://localhost:8009/v1/runs/graph \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: demo-run-1" \
  -d '{"evidence_ids":["<evidence_id_from_ingest>"],"profile_id":"axoden-cix-1-v0.2.0"}'
```

## Notes

- The kernel is mounted into the container via `AXODEN_KERNEL_PATH=/app/axoden-kernel`.
- Evidence records are stored in `data/ledger.jsonl` (append-only).
- Default kernel profile is `axoden-cix-1-v0.2.0`.
- Decision schema uses `reason_code` (single value).
- Graph outputs and reports are written under `data/runs/{run_id}/`.
