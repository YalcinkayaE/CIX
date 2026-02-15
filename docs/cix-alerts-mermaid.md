graph TD

%% 1) Ingest

subgraph sg_ingest["1. Ingest"]

RAW["Batch Ingestion: JSON Array/Stream"]

end

%% 4) Validate (ARV)

subgraph sg_validate["4. Validate (ARV)"]

ARV1["ARV Resilience Validator"]

ARV2["ARV Gate 2: Entropy Drift D+"]

ARV3["ARV Gate 3: Correlation Risk dist_2"]

FL["Forensic Ledger: Validation Audit Trail"]

end

%% 2) Correlate

subgraph sg_correlate["2. Correlate"]

WG["Unified World Graph Composition"]

COR["Automatic Cross-Correlation"]

CC["Campaign Clustering: Connected Components"]

end

%% 3) Enrich (EFI)

subgraph sg_enrich["3. Enrich (EFI)"]

LC["Lead-Chasing Module"]

EXT["External Intel Discovery"]

subgraph sg_external["External Intelligence Sources"]

NVD["NVD / CVE Database"]

OTX["AlienVault OTX"]

MA_WEB["MITRE Knowledge Base"]

VT["VirusTotal: EFI Signature Check"]

end

end

%% 5) Synthesize

subgraph sg_synthesize["5. Synthesize"]

SYN["Synthesis: Campaign Story"]

SUM["Strategic Campaign Summaries"]

DASH["PyVis Dashboard: Zoom/Pan/Click"]

end

%% Flow & Gates

RAW -->|"ARV Gate 1: Burden Baseline"| ARV1

ARV1 -->|"Evidence Admissible"| WG

WG -->|"Shared Hubs: IPs/Hashes/Domains"| COR

COR -->|"EFI-Deduplicated Targets"| LC

LC -->|"Brave Search API Gateway"| EXT

EXT -->|"Query"| NVD

EXT -->|"Query"| OTX

EXT -->|"Query"| MA_WEB

NVD & OTX & MA_WEB & VT -->|"New Artifacts"| ARV2

ARV2 -->|"Graph Partitioning"| CC

CC -->|"Cluster Isolation"| ARV3

ARV3 -->|"CFS Certified"| SYN

SYN -->|"Narrative Output"| SUM

SUM -->|"Interactive Visualization"| DASH

%% Audit Trail

ARV1 -.->|"Log"| FL

ARV2 -.->|"Log"| FL

ARV3 -.->|"Log"| FL

SUM & DASH -->|"Immutable History"| FL

  

%% Component Styling

classDef safety fill:#f96,stroke:#333,stroke-width:2px;

classDef topology fill:#fdfd96,stroke:#333,stroke-width:2px;

classDef external fill:#4db8ff,stroke:#333,stroke-width:2px;

classDef audit fill:#e1d5e7,stroke:#333,stroke-width:2px;

  

class ARV1,ARV2,ARV3 safety;

class WG,COR,LC,CC topology;

class VT,NVD,OTX,MA_WEB external;

class FL,SUM,DASH,SYN audit;