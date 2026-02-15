# CIX Alerts

## Project Overview
CIX Alerts is a prototype pipeline designed to ingest SOC (Security Operations Center) alerts, construct a forensic knowledge graph, enrich it with internal and external intelligence, and synthesize a narrative report. It leverages Graph Theory (NetworkX) for relationship modeling and Generative AI (Google Gemini) for reasoning and report generation.

### Key Technologies
*   **Language:** Python 3.12
*   **Graph Database (In-Memory):** NetworkX
*   **AI/LLM:** Google Generative AI (`gemini-2.0-flash`)
*   **External APIs:** VirusTotal, AlienVault OTX, NVD (National Vulnerability Database), Brave Search
*   **Infrastructure:** Docker, Docker Compose

### Architecture
The pipeline follows a linear execution flow:
1.  **Ingestion:** Parses raw JSON alerts (e.g., `samples/cix_kernel_demo_alerts.json`) into a standardized model.
2.  **Modeling:** Converts raw data into a `GraphReadyAlert` object.
3.  **Graph Construction:** Builds an initial graph connecting the Alert to entities like IPs, File Hashes, and mapped MITRE ATT&CK techniques.
4.  **Enrichment (Internal):** Queries VirusTotal, OTX, and NVD based on graph nodes (SHA256, MalwareFamily). Generates "Search Leads" using Gemini.
5.  **Lead Chasing (External):** Executes web searches (Brave) for generated leads and refines results into new graph artifacts (C2 Domains, Registry Keys) using Gemini.
6.  **Synthesis:** Walks the final graph and uses Gemini to generate a structured forensic report.
7.  **Audit & Visualization:** Exports a forensic ledger JSON and generates a PNG visualization of the graph.

## Building and Running

### Prerequisites
*   Python 3.12+ or Docker Desktop
*   API Keys for: Google Gemini, VirusTotal, AlienVault OTX, NVD, Brave Search (optional but recommended for full functionality)

### Local Development
1.  **Setup Environment:**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    ```

2.  **Configuration:**
    Copy `.env.example` to `.env` and populate your API keys.
    ```bash
    cp .env.example .env
    ```

3.  **Run Pipeline:**
    ```bash
    python3 -u main.py
    ```

### Docker
1.  **Build and Run:**
    ```bash
    docker compose up --build
    ```
    This will start the `cix-alerts-container`.

2.  **Execute Pipeline inside Container:**
    ```bash
    docker exec -it cix-alerts-container python -u main.py
    ```

## Development Conventions

*   **Code Style:** Standard Python PEP 8.
*   **Typing:** Extensive use of `typing` hints and Pydantic models for data validation.
*   **Graph Schema:**
    *   **Nodes:** Typed (e.g., `Alert`, `IP`, `SHA256`, `MITRE_Technique`, `EFI` (External Fact/Intelligence)).
    *   **Edges:** semantic relationships (e.g., `HAS_FILE_HASH`, `INDICATES_TECHNIQUE`, `ENRICHED_BY_VT`).
*   **AI Integration:**
    *   **Prompts:** Located within their respective classes (`EnrichmentAgent`, `IntelligenceRefiner`, `GraphNarrator`).
    *   **Roles:** AI agents have specific personas (e.g., "CIX Alerts Intelligence Refiner").
    *   **Output:** strictly structured JSON for intermediate steps or Markdown for final reports.
*   **Data Persistence:**
    *   Input: `samples/cix_kernel_demo_alerts.json`
    *   Output: `data/forensic_ledger.json`, `data/investigation_graph.png`
