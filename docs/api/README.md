# CIX Alerts API (Consolidated Pipeline)

## Run (Docker)

```bash
# From repo root
export AXODEN_KERNEL_PATH=/Users/erkanyalcinkaya/projects/axoden-kernel

docker compose up --build -d
```

The API listens on `http://localhost:8009`.

## Endpoints (v1)

- `POST /api/v1/ingest/events`
  - Ingests SIEM/SOAR events into the evidence ledger (kernel canonicalization).
- `POST /api/v1/runs/graph`
  - Builds a graph run from a list of ingested event IDs.
- `GET /api/v1/runs/{run_id}`
  - Fetches run status and metadata.
- `GET /api/v1/runs/{run_id}/artifacts`
  - Lists artifacts (graph HTML, reports, etc.) for a run.

See `openapi.yaml` for the full schema.

## Quickstart

```bash
curl -X POST http://localhost:8009/api/v1/ingest/events \
  -H "Content-Type: application/json" \
  -d '{"events":[{"source_id":"demo","event_id":"e1","source_timestamp":"2026-02-03T12:00:00Z","raw_payload":{"message":"test"}}]}'
```

```bash
curl -X POST http://localhost:8009/api/v1/runs/graph \
  -H "Content-Type: application/json" \
  -d '{"event_ids":["e1"],"notes":"demo run"}'
```

## Notes

- The kernel is mounted into the container via `AXODEN_KERNEL_PATH=/app/axoden-kernel`.
- Evidence records are stored in `data/ledger.jsonl` (append-only).
- Graph outputs and reports are written under `data/runs/{run_id}/`.
