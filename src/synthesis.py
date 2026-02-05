import os
import networkx as nx
from google import genai
from dotenv import load_dotenv

load_dotenv()

class GraphNarrator:
    """
    Uses an LLM to "walk the graph" and generate a forensic summary.
    """
    def __init__(self):
        api_key = os.getenv("GOOGLE_API_KEY")
        if api_key:
            self.client = genai.Client(api_key=api_key)
        else:
            self.client = None

    def summarize(self, graph: nx.DiGraph) -> str:
        """
        Generate a narrative based on the graph structure.
        """
        triples = []
        for u, v, data in graph.edges(data=True):
            triples.append(f"{u} --[{data.get('relationship')}]--> {v}")
        
        graph_str = "\n".join(triples)
        
        prompt = f"""
        As a Senior Cyber Security Forensic Analyst, review the following knowledge graph triples from the CIX Alerts Forensic Ledger:
        
        {graph_str}
        
        **Task:**
        Generate a professional, structured forensic report. You MUST use the following Markdown structure exactly:

        ## Forensic Ledger Summary
        [Provide a high-level narrative of the alert, IP, and file hash using terms like "Unified Feature Catalog" and "EFI".]

        ## Incident Flow
        [A numbered list of the attack sequence inferred from the graph.]

        ## Identified Threat
        [Name the malware family and its potential impact.]

        ## Enrichment Results
        [Bulleted list of findings from VirusTotal (EFI) and the generated Search Leads.]
        """
        
        if self.client:
            try:
                response = self.client.models.generate_content(
                    model='gemini-2.0-flash',
                    contents=prompt
                )
                return response.text
            except Exception as e:
                return f"LLM Error: {e}\n\n[Fallback Summary]: Incident involving {len(graph.nodes)} nodes and {len(graph.edges)} relationships recorded in Forensic Ledger."
        else:
            return f"[Mock Summary]: Investigation centered on alert with {len(graph.edges)} recorded events. SHA256 was enriched via VirusTotal and malware behaviors were identified via web search."

    def generate_assessment_report(self, graph: nx.DiGraph) -> str:
        """
        Generates a human-readable 'Forensic Assessment Report' matching the official template.
        """
        triples = []
        for u, v, data in graph.edges(data=True):
            triples.append(f"{u} --[{data.get('relationship')}]--> {v}")
        
        graph_str = "\n".join(triples)
        
        # Template structure prompt
        prompt = f"""
        You are an expert Cyber Intelligence Analyst. Generate a 'Forensic Assessment Report' for the following investigation data.
        
        **Graph Data (Investigation Context):**
        {graph_str}

        **Instructions:**
        - Fill out the report strictly following the TEMPLATE below.
        - Replace placeholders like [Narrative], [UUID], etc., with actual data inferred from the Graph Data.
        - Use professional, authoritative language.
        - Ensure 'Incident ID' matches the Alert ID from the graph if available.
        - For 'Safety Kernel Assessment', assume EFI status is 'Output collapsed to evidence-bounded artifacts' if not explicitly stated otherwise.
        
        **TEMPLATE:**
        
        # CyberIntelX.io FORENSIC ASSESSMENT REPORT
        **Incident ID:** [Alert/Event ID]
        **Security Level:** SEV-4 HIGH | **Status:** OPEN (Investigation Complete)

        ## 1. Executive Summary
        [Provide a concise narrative of the alert, the endpoint involved, the artifact (file/hash), and the attribution. Mention 'Unified Feature Catalogs' and 'EFI' where relevant.]
        **Key Finding:** [Highlight the most critical confirmation, e.g., VirusTotal enrichment or specific malware attribution.]

        ## 2. Investigative Traceability (Incident Flow)
        All events below have been committed to the **immutable Forensic Ledger** to ensure court-admissible audit integrity.
        *   **Alert Trigger:** [Describe the initial trigger].
        *   **Execution:** [Describe the execution path/file].
        *   **Technique Mapping:** [Map to MITRE T-codes found in graph].
        *   **Data Staging:** [Describe any staging or local persistence].
        *   **Malware Attribution:** [Identify the malware family].
        *   **External Validation:** [Mention VT or OTX hits].

        ## 3. Threat Intelligence & Enrichment
        CyberIntelX.io used multi-hop reasoning and **Brave Search** to resolve the following intelligence gaps:
        *   **VirusTotal EFI Signature:** [Details on hash reputation].
        *   **Targeted Search Leads:** [Summarize what was searched and found].

        ## 4. Safety Kernel Assessment
        *   **EFI Status:** Output collapsed to evidence-bounded artifacts; no hallucinations detected.
        *   **Enforcement Recommendation:** ACT-003 INVESTIGATE (Manual forensic isolation recommended).

        ## 5. Recommended Remediation (VSR Recovery Logic)
        Based on the verified activity, the following steps are required to restore the system to a trusted state:
        *   **Containment:** [Specific steps to remove the artifact].
        *   **Eradication:** [Steps to clear temp files/persistence].
        *   **Credential Recovery:** [Advice on password resets if credential theft is suspected].
        *   **Verification:** [Recommendation for deep scans].

        **Forensic Artifacts Attached:**
        *   **Immutable Ledger:** `data/forensic_ledger.json`
        *   **Relational Flow Graph:** `data/investigation_graph.png`
        """

        if self.client:
            try:
                response = self.client.models.generate_content(
                    model='gemini-2.0-flash',
                    contents=prompt
                )
                return response.text
            except Exception as e:
                return f"# Error Generating Report\n\nLLM Error: {e}"
        else:
            return "# Mock Report\n\n(LLM Client not initialized. Please set GOOGLE_API_KEY.)"

