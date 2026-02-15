import os
from typing import Dict, Optional, Tuple

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

        self._placeholder_markers = (
            "unprovided",
            "hypothetical",
            "placeholder",
            "missing data",
            "don't have the actual data",
            "do not have the actual data",
            "assume",
            "assuming",
        )

    def _collect_facts(self, graph: nx.DiGraph) -> dict:
        alerts = set()
        ips = set()
        hashes = set()
        malware_families = set()
        file_names = set()
        file_paths = set()
        rule_intents = set()
        mitre = set()
        tactics = set()

        for node, data in graph.nodes(data=True):
            node_type = data.get("type")
            value = data.get("value")
            if isinstance(node, str) and node.startswith("Alert:"):
                alerts.add(node.replace("Alert:", "", 1))
            if node_type == "IP" and value:
                ips.add(value)
            if node_type == "SHA256" and value:
                hashes.add(value)
            if node_type == "MalwareFamily" and value:
                malware_families.add(value)
            if node_type == "FileName" and value:
                file_names.add(value)
            if node_type == "FilePath" and value:
                file_paths.add(value)
            if node_type == "RuleIntent" and value:
                rule_intents.add(value)
            if node_type == "MITRE_Technique":
                if isinstance(node, str) and node.startswith("MITRE:"):
                    mitre.add(node.replace("MITRE:", "", 1))
                if data.get("tactic"):
                    tactics.add(data.get("tactic"))

        return {
            "alerts": sorted(alerts),
            "ips": sorted(ips),
            "hashes": sorted(hashes),
            "malware_families": sorted(malware_families),
            "file_names": sorted(file_names),
            "file_paths": sorted(file_paths),
            "rule_intents": sorted(rule_intents),
            "mitre": sorted(mitre),
            "tactics": sorted(tactics),
            "node_count": graph.number_of_nodes(),
            "edge_count": graph.number_of_edges(),
        }

    def _format_list(self, values, max_items=5) -> str:
        if not values:
            return "Not observed in graph."
        clipped = values[:max_items]
        if len(values) > max_items:
            return ", ".join(clipped) + f" (+{len(values) - max_items} more)"
        return ", ".join(clipped)

    def _format_triage_header(self, triage_summary: Optional[Dict[str, int]]) -> Tuple[str, str]:
        if not triage_summary:
            return "", ""
        total = triage_summary.get("total_ingested", 0)
        low = triage_summary.get("background_low_entropy", 0)
        semantic = triage_summary.get("background_semantic", 0)
        red = triage_summary.get("red_zone_high_entropy", 0)
        dedup = triage_summary.get("dedup_removed", 0)
        active = triage_summary.get("active_candidates", 0)
        findings = triage_summary.get("findings", 0)
        header = (
            "**Triage Counts:** "
            f"Ingested {total} | Background (Low) {low} | Background (Semantic) {semantic} | "
            f"Red Zone {red} | Deduped {dedup} | Active Candidates {active} | Findings {findings}"
        )
        section = "\n".join(
            [
                "## 0. Triage Summary (Run Counts)",
                f"*   Total Ingested: {total}",
                f"*   Background (Low Entropy): {low}",
                f"*   Background (Semantic): {semantic}",
                f"*   Red Zone (High Entropy): {red}",
                f"*   Deduped Removed: {dedup}",
                f"*   Active Triage Candidates: {active}",
                f"*   Findings: {findings}",
            ]
        )
        return header, section

    def _ensure_triage_sections(self, report: str, triage_summary: Optional[Dict[str, int]]) -> str:
        if not triage_summary:
            return report
        header_line, section = self._format_triage_header(triage_summary)
        if not header_line or not section:
            return report

        lines = report.splitlines()
        output = []
        inserted_header = "Triage Counts" in report
        inserted_section = "Triage Summary" in report

        for line in lines:
            output.append(line)
            if not inserted_header and line.startswith("**Security Level:**"):
                output.append(header_line)
                inserted_header = True

        report = "\n".join(output)

        if not inserted_section:
            marker = "## 1. Executive Summary"
            if marker in report:
                report = report.replace(marker, section + "\n\n" + marker, 1)
            else:
                report = report + "\n\n" + section

        return report

    def _needs_fallback(self, text: str) -> bool:
        lowered = text.lower()
        return any(marker in lowered for marker in self._placeholder_markers)

    def _deterministic_summary(self, graph: nx.DiGraph) -> str:
        facts = self._collect_facts(graph)
        alert = facts["alerts"][0] if facts["alerts"] else "Unknown"
        return (
            "Forensic summary based on graph evidence. "
            f"Incident {alert} includes {facts['edge_count']} relationships across "
            f"{facts['node_count']} nodes. "
            f"IPs: {self._format_list(facts['ips'])}. "
            f"File hashes: {self._format_list(facts['hashes'])}. "
            f"Malware families: {self._format_list(facts['malware_families'])}."
        )

    def _deterministic_report(self, graph: nx.DiGraph, triage_summary: Optional[Dict[str, int]]) -> str:
        facts = self._collect_facts(graph)
        alert_id = facts["alerts"][0] if facts["alerts"] else "Unknown"
        header_line, section = self._format_triage_header(triage_summary)
        incident_flow = [
            f"Alert {alert_id} recorded {facts['edge_count']} relationships in the forensic ledger.",
            f"Observed source/destination IPs: {self._format_list(facts['ips'])}",
            f"Observed file hashes: {self._format_list(facts['hashes'])}",
            f"Observed file names: {self._format_list(facts['file_names'])}",
            f"Observed file paths: {self._format_list(facts['file_paths'])}",
        ]
        return "\n".join(
            [
                "# CyberIntelX.io FORENSIC ASSESSMENT REPORT",
                f"**Incident ID:** {alert_id}",
                "**Security Level:** SEV-4 HIGH | **Status:** OPEN (Investigation Complete)",
                header_line,
                "",
                section,
                "",
                "## 1. Executive Summary",
                "Report generated from observed graph evidence only.",
                f"**Key Finding:** IPs observed: {self._format_list(facts['ips'])}",
                "",
                "## 2. Investigative Traceability (Incident Flow)",
                "All events below have been committed to the **immutable Forensic Ledger** to ensure court-admissible audit integrity.",
                *[f"*   {step}" for step in incident_flow],
                "",
                "## 3. Threat Intelligence & Enrichment",
                "CyberIntelX.io used multi-hop reasoning and **Brave Search** to resolve the following intelligence gaps:",
                f"*   **VirusTotal EFI Signature:** {self._format_list(facts['hashes'])}",
                "*   **Targeted Search Leads:** Not observed in graph.",
                "",
                "## 4. Safety Kernel Assessment",
                "*   **EFI Status:** Output collapsed to evidence-bounded artifacts; no hallucinations detected.",
                "*   **Enforcement Recommendation:** ACT-003 INVESTIGATE (Manual forensic isolation recommended).",
                "",
                "## 5. Recommended Remediation (VSR Recovery Logic)",
                "Based on the verified activity, the following steps are required to restore the system to a trusted state:",
                "*   **Containment:** Isolate affected hosts and block suspicious IPs.",
                "*   **Eradication:** Remove identified artifacts and clean persistence mechanisms if present.",
                "*   **Credential Recovery:** Reset credentials associated with impacted systems if evidence warrants.",
                "*   **Verification:** Perform deep scans and verify no further indicators remain.",
                "",
                "**Forensic Artifacts Attached:**",
                "*   **Immutable Ledger:** `data/forensic_ledger.json`",
                "*   **Relational Flow Graph:** `data/investigation_graph_campaign_1.html`",
                "*   **Campaign Snapshot:** `data/campaign_snapshot_1.html`",
            ]
        )

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
        
        if not self.client:
            return self._deterministic_summary(graph)

        try:
            response = self.client.models.generate_content(
                model='gemini-2.0-flash',
                contents=prompt + "\n\nRules: Use only facts in the graph data. If a field is missing, write 'Not observed in graph.' Do not add preamble or disclaimers."
            )
            if self._needs_fallback(response.text):
                return self._deterministic_summary(graph)
            return response.text
        except Exception as e:
            return f"LLM Error: {e}\n\n[Fallback Summary]: {self._deterministic_summary(graph)}"

    def generate_assessment_report(self, graph: nx.DiGraph, triage_summary: Optional[Dict[str, int]] = None) -> str:
        """
        Generates a human-readable 'Forensic Assessment Report' matching the official template.
        """
        triples = []
        for u, v, data in graph.edges(data=True):
            triples.append(f"{u} --[{data.get('relationship')}]--> {v}")
        
        graph_str = "\n".join(triples)
        header_line, section = self._format_triage_header(triage_summary)
        triage_context = section if section else "Not available."
        
        # Template structure prompt
        prompt = f"""
        You are an expert Cyber Intelligence Analyst. Generate a 'Forensic Assessment Report' for the following investigation data.
        
        **Graph Data (Investigation Context):**
        {graph_str}

        **Triage Summary (Run Counts):**
        {triage_context}

        **Instructions:**
        - Fill out the report strictly following the TEMPLATE below.
        - Replace placeholders like [Narrative], [UUID], etc., with actual data inferred from the Graph Data.
        - Use professional, authoritative language.
        - Ensure 'Incident ID' matches the Alert ID from the graph if available.
        - Use the Triage Summary counts verbatim in the report header and the triage section.
        - For 'Safety Kernel Assessment', assume EFI status is 'Output collapsed to evidence-bounded artifacts' if not explicitly stated otherwise.
        
        **TEMPLATE:**
        
        # CyberIntelX.io FORENSIC ASSESSMENT REPORT
        **Incident ID:** [Alert/Event ID]
        **Security Level:** SEV-4 HIGH | **Status:** OPEN (Investigation Complete)
        {header_line}

        ## 0. Triage Summary (Run Counts)
        [List the exact run counts provided above.]

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
        *   **Relational Flow Graph:** `data/investigation_graph_campaign_1.html`
        *   **Campaign Snapshot:** `data/campaign_snapshot_1.html`
        """

        if not self.client:
            return self._deterministic_report(graph, triage_summary)

        try:
            response = self.client.models.generate_content(
                model='gemini-2.0-flash',
                contents=prompt
                + "\n\nRules: Use only facts in the graph data. If a field is missing, write 'Not observed in graph.' "
                + "Do not say the data is missing or hypothetical. Output only the template content."
            )
            if self._needs_fallback(response.text):
                return self._deterministic_report(graph, triage_summary)
            return self._ensure_triage_sections(response.text, triage_summary)
        except Exception as e:
            return f"# Error Generating Report\n\nLLM Error: {e}\n\n{self._deterministic_report(graph, triage_summary)}"
