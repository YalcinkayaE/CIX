# cix-alerts

Prototype pipeline that ingests a SOC alert JSON, builds a graph, enriches it, and outputs a narrative + artifacts.

## AxoDen Kernel compatibility

This repo is wired to the AxoDen Kernel v0.6.0-style decision API.

- Default kernel profile: `axoden-cix-1-v0.2.0`
- Kernel decision output uses `reason_code` (single string), not `reason_codes`
- Graph admission path accepts `ARV.EXECUTE` and `ARV.THROTTLE`; `ARV.HALT` hard-stops ingest
- API endpoints are rooted at `/v1/*` for kernel ingest and graph runs
- Graph artifacts include `snapshot_html` entries

See:
- `docs/kernel_demo.md`
- `docs/AxoDen_Canonical_Blueprint.md`
- `docs/api/README.md`
- `docs/api/openapi.yaml`

## Local run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit .env with your API keys

python3 -u main.py
```

### Useful flags
- `--triage-only` stop after triage counts (no enrichment or reports)
- `--skip-enrichment` skip EFI enrichment (faster)
- `--arv-beta N` set entropy expansion budget (ARV)
- `--phi-limit-arv1 N` set Gate 1 phi limit (triage admission)
- `--phi-limit-arv2 N` set Gate 2 phi limit (post-enrichment)
- `--phi-limit-arv3 N` set Gate 3 phi limit (reporting)
- `--verbose` print ARV gate decisions
- `--profile-id` override AxoDen profile_id

## Docker

```bash
docker compose up --build
docker exec -it cix-alerts-container python -u main.py
```

Example (full run with explicit ARV limits):
```bash
docker exec -it cix-alerts-container python -u main.py /app/soc_alert_batch.json \
  --arv-beta 4 \
  --phi-limit-arv1 200 \
  --phi-limit-arv2 500 \
  --verbose
```
