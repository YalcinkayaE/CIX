## **Graph-Grounded Lead Chasing Prompt**

**Role:** You are the AxoDen Intelligence Layer (Lead Chaser). Your task is to analyze a localized subgraph of an alert and generate targeted search queries to resolve missing information.

**Current Subgraph Evidence:**

> {SUBGRAPH_TRIPLES} _(Example: Alert-001 -> HAS_FILE -> SHA256:4a36...)_

**Constraints:**

1. **Evidence Boundary:** Do not speculate on actors or motives not present in the graph.
    
2. **Search Precision:** Generate exactly 3 search queries designed to find technical indicators or CVE mappings for the provided entities.
    
3. **Entropy Budget:** If the entities are generic (e.g., `cmd.exe`), do not trigger external searches; mark as **LOW_ENTROPY**.
    

**Required Output Format (JSON):**

JSON

```
{
  "analysis": "Brief summary of current evidence chain.",
  "status": "INVESTIGATING | INSUFFICIENT_EVIDENCE | MIMIC_SCOPED",
  "leads": [
    {
      "entity": "Entity Name",
      "search_query": "Specific Google/NVD/VT query",
      "objective": "What specific node are we trying to add to the graph?"
    }
  ]
}
```

---

## **MVP Project Brief: Standalone "Lead-Chaser" Prototype**

### **1. Core Objectives**

- **Manual Payload Ingestion:** Process `soc_alert_raw.json` without a live SIEM connection.
    
- **Relational Mapping:** Convert the "M" and "L" types into a directed graph.
    
- **Deterministic Pivot:** Identify when a `file_hash_sha256` or `malware_family` requires external enrichment.
    

### **2. Development Steps for your Coding Agent**

1. **Utility: The Deserializer**
    
    - Use `boto3.dynamodb.types.TypeDeserializer` to clean the raw data.
        
2. **Class: `AxoGraph`**
    
    - Use **NetworkX** to create nodes for `Alert`, `Host`, `IP`, and `Hash`.
        
    - Implement a `to_ledger()` method that exports the current graph state as a JSON-LD "Forensic Ledger".
        
3. **Logic: The Enrichment Trigger**
    
    - Write a function that scans the graph for `SHA256` nodes.
        
    - If found, call the **Lead Chasing Prompt** (above) to generate queries.
        
    - Simulate the "Lead" by adding a dummy node (e.g., `VT_Report`) to prove the multi-hop path works.
        

### **3. Initial Setup Instructions**

> - **Repository Name:** `axoden-graph-prototype`
>     
> - **Files to Create:** > * `parser.py`: Handles raw JSON deserialization.
>     
>     - `engine.py`: Manages the NetworkX graph and node creation.
>         
>     - `chaser.py`: Contains the LLM integration and the prompt template above.
>         
>     - `main.py`: Orchestrates the flow: **Load JSON -> Build Graph -> Chase Leads -> Export Ledger**.
>         

---

a clear target for the end-to-end flow, here is the mock **Forensic Ledger** output. This represents the "Source of Truth" that makes the AI's investigation certifiable under the **AxoDen** framework.

### **Mock Forensic Ledger (`forensic_ledger.json`)**

This output shows how the raw JSON was transformed into a verifiable chain of evidence, including the "lead-chasing" steps.

JSON

```
[
  {
    "step": 1,
    "timestamp": "2026-01-29T22:54:53Z",
    "action": "INGEST_RAW_PAYLOAD",
    "entity_id": "alarm-central_f4eb57fc-ae42-4da3-af22-6442d5c539e6",
    "metadata": { "client": "ClientA", "source_type": "alarm" },
    "provenance": "soc_alert_raw.json",
    "safety_status": "EBDP_PASS"
  },
  {
    "step": 2,
    "timestamp": "2026-01-29T22:55:01Z",
    "action": "GRAPH_MAP_INTERNAL",
    "relationship": "HAS_FILE",
    "source": "alarm-central_f4eb57fc-ae42-4da3-af22-6442d5c539e6",
    "target": "4a365b80f0de287dcfbf7860075e0956e450048933ddebb0506837afbced404e",
    "type": "SHA256",
    "evidence_path": "data.M.file_hash_sha256.S"
  },
  {
    "step": 3,
    "timestamp": "2026-01-29T22:55:15Z",
    "action": "LEAD_CHASE_EXTERNAL",
    "relationship": "ENRICHED_BY",
    "source": "4a365b80f0de287dcfbf7860075e0956e450048933ddebb0506837afbced404e",
    "target": "VirusTotal_Report_8829",
    "data": { "positives": 52, "total": 70, "malware_family": "ChatGPTStealer" },
    "provenance": "API_QUERY: VirusTotal"
  },
  {
    "step": 4,
    "timestamp": "2026-01-29T22:56:10Z",
    "action": "SYNTHESIZE_NARRATIVE",
    "status": "COMPLETED",
    "efi_validation": "SUCCESS",
    "summary": "Alert triggered by 'ChatGPTStealer' (.js). File hash confirmed malicious via VT. Investigation pivots to browser extension assets."
  }
]
```

---

### **Final Instructions 

1. **Strict Glossary Adherence:** Ensure all `action` codes (e.g., `ACT-003 INVESTIGATE`) and `status` labels (e.g., `MIMIC_SCOPED`) match the **AxoDen Unified Feature Catalog**.
    
2. **Evidence Bounding (EFI):** When generating the `summary`, the agent must only reference nodes that exist in the `forensic_ledger.json`. Any mention of data not in the ledger is a "Safety Violation".
    
3. **Stability (VSR):** If the external "Lead" contradicts internal data, the agent should not overwrite; it should create a new node and flag the conflict as a `VSR_STABILITY_ALERT`.