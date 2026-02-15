# CIX Alerts

## Project Overview
CIX Alerts is a forensic pipeline designed to ingest SOC (Security Operations Center) alerts, strictly validate them via the **AxoDen Kernel**, construct a forensic knowledge graph, and synthesize narrative reports. It integrates Graph Theory (NetworkX) for relationship modeling and Generative AI (Google Gemini) for reasoning, all governed by entropy-based admissibility gates.

### Key Technologies
*   **Language:** Python 3.12
*   **Graph Database (In-Memory):** NetworkX
*   **AI/LLM:** Google Generative AI (`gemini-2.0-flash`)
*   **External APIs:** VirusTotal, AlienVault OTX, NVD (National Vulnerability Database), Brave Search
*   **Infrastructure:** Docker, Docker Compose, FastAPI

### Architecture: The AxoDen Canonical Flow
The pipeline follows a rigorous 5-stage execution flow (detailed in `docs/AxoDen_Canonical_Blueprint.md`):

1.  **Stage 0/1 (Ingestion & Triage):** 
    *   Parses raw alerts (SIEM formats like CEF, LEEF, JSON).
    *   Performs initial entropy-based classification and deduplication to filter noise.
2.  **Stage 2 (Kernel Admission Gate):** 
    *   Invokes the **AxoDen Kernel** to decide: `EXECUTE` (high value), `THROTTLE` (marginal), or `HALT` (noise).
    *   Enforces entropy limits (e.g., max 5.28 bits) to prevent hallucination.
3.  **Stage 3 (World Graph Build):** 
    *   Constructs the initial forensic knowledge graph.
    *   Maps alerts to entities (IPs, Hashes) and MITRE ATT&CK techniques.
4.  **Stage 4 (ARV Gates):** 
    *   **Admission/Relevance/Verification (ARV)** gates manage enrichment.
    *   Queries external intelligence (VirusTotal, OTX) and performs "Lead Chasing" (web search) only for admitted artifacts.
5.  **Stage 5 (Synthesis & Reporting):** 
    *   Splits the graph into distinct campaigns.
    *   Synthesizes structured forensic reports for each campaign using Gemini.
    *   Audits decisions to a forensic ledger.

## Building and Running

### Prerequisites
*   Python 3.12+ or Docker Desktop
*   API Keys: Google Gemini, VirusTotal, AlienVault OTX, NVD, Brave Search

### Local Development
1.  **Setup Environment:**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    ```

2.  **Configuration:**
    Copy `.env.example` to `.env` and populate keys.
    ```bash
    cp .env.example .env
    ```

3.  **Run Pipeline (CLI):**
    ```bash
    python3 -u main.py
    ```
    *   Use flags like `--skip-enrichment`, `--phi-limit`, or `--output-dir` to tune execution.

### Docker & API
1.  **Build and Run:**
    ```bash
    docker compose up --build
    ```
2.  **API Access:**
    *   The API listens on `http://localhost:8009`.
    *   Endpoints: `POST /v1/ingest/events`, `POST /v1/runs/graph`.

## Benchmark & Verification
CIX Alerts includes a full benchmark suite for AI SOC middleware comparison (located in `docs/benchmark/`):
*   **Quantitative Rubric:** 100-point rubric for fairness and performance.
*   **Feature Matrix:** Repeatable `Y/P/U` scoring for feature availability.
*   **Automated Scoring:** `scripts/score_feature_benchmark.py` generates weighted scores.

## Development Conventions

*   **Structure:**
    *   `src/api/`: FastAPI endpoints.
    *   `src/kernel/`: AxoDen Kernel integration (gating, hashing, ledger).
    *   `src/pipeline/`: Pipeline orchestration, ARV logic, and verification.
    *   `src/`: Core domain logic (graph models, enrichment agents, synthesis).
*   **Code Style:** Standard Python PEP 8.
*   **Typing:** Extensive use of `typing` hints and Pydantic models.
*   **Graph Schema:** Typed Nodes (`Alert`, `IP`, `EFI`) and Semantic Edges (`HAS_FILE_HASH`, `INDICATES_TECHNIQUE`).
*   **Data Persistence:**
    *   Outputs campaign-specific reports and a unified `data/forensic_ledger.json`.
    *   Maintains run-scoped artifacts in `data/runs/`.
