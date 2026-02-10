# cix-alerts

Prototype pipeline that ingests a SOC alert JSON, builds a graph, enriches it, and outputs a narrative + artifacts.

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
