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

## Docker

```bash
docker compose up --build
docker exec -it cix-alerts-container python -u main.py
```
