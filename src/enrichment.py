import json
import os
import time
import requests
import networkx as nx
import ipaddress
from google import genai
from dotenv import load_dotenv
from src.canon_registry import vsr_drift, mq_m1, mq_m4, MQ_TAU_D, efi_surplus

load_dotenv()

class EnrichmentAgent:
    """
    Identifies enrichment triggers and adds intelligence nodes (EFI/EBDP) to the graph.
    Integrates VirusTotal, AlienVault OTX, NVD, and Gemini LLM.
    """
    def __init__(self):
        # Load API Keys
        self.vt_key = os.getenv("VT_API_KEY")
        self.otx_key = os.getenv("OTX_API_KEY")
        self.nvd_key = os.getenv("NVD_API_KEY")
        self.gemini_key = os.getenv("GOOGLE_API_KEY")

        # Configure Gemini
        if self.gemini_key:
            self.client = genai.Client(api_key=self.gemini_key)
        else:
            self.client = None

    def _calculate_monitoring_vector(self, graph: nx.DiGraph) -> list:
        """
        Computes the Monitoring Quad (M1-M4) proxy vector for the graph.
        Vector: [M1(Alignment), M2(Consistency), M3(Novelty), M4(Independence)]
        """
        # Simplified proxies for prototype
        node_count = len(graph.nodes)
        if node_count == 0: return [0.0, 0.0, 0.0, 0.0]
        
        # M1: Alignment (Fraction of nodes with defined source/provenance)
        provenance_count = sum(1 for n, d in graph.nodes(data=True) if d.get("source"))
        m1 = mq_m1(coverage=provenance_count/node_count, freshness=1.0, provenance=1.0, contradiction=0.0)
        
        # M4: Independence (1 - max degree centrality as proxy for correlation)
        # Real M4 uses pairwise correlation; here we use centrality as a structural proxy
        if len(graph) > 1:
            centralities = list(nx.degree_centrality(graph).values())
            m4 = mq_m4(centralities) 
        else:
            m4 = 1.0

        return [m1, 1.0, 0.5, m4] # M2, M3 static for prototype

    def chase_leads(self, graph: nx.DiGraph):
        """
        Scan graph for triggers (SHA256, MalwareFamily) and enrich.
        """
        # [VSR] 1. Baseline Monitoring Vector
        m_0 = self._calculate_monitoring_vector(graph)
        
        nodes_to_process = list(graph.nodes(data=True))
        
        for node_id, data in nodes_to_process:
            node_type = data.get("type")
            
            # Trigger 1: SHA256 node -> VirusTotal & OTX
            if node_type == "SHA256":
                hash_val = data.get("value")
                self._enrich_vt(graph, node_id, hash_val)
                self._enrich_otx(graph, node_id, hash_val)
            
            # Trigger 2: IP Node -> VirusTotal (Public IPs only)
            if node_type == "IP":
                ip_addr = data.get("value")
                self._enrich_ip(graph, node_id, ip_addr)

            # Trigger 3: MalwareFamily -> NVD & LLM Lead Chasing
            if node_type == "MalwareFamily":
                family_name = data.get("value")
                self._enrich_nvd(graph, node_id, family_name)
                self._generate_leads(graph, node_id, data)
                
        # [VSR] 2. Post-Enrichment Drift Check
        m_t = self._calculate_monitoring_vector(graph)
        drift = vsr_drift(m_t, m_0)
        
        print(f"  [VSR] Monitoring Drift: {drift:.4f} (Threshold: {MQ_TAU_D})")
        if drift > MQ_TAU_D:
            print(f"  [!] VSR ALERT: High Drift Detected! Requesting Safety Review.")

    def _enrich_ip(self, graph, node_id, ip_addr):
        """Query VirusTotal for IP reputation (Public IPs only)."""
        try:
            # check if public
            ip = ipaddress.ip_address(ip_addr)
            if not ip.is_global:
                return # Skip internal/private IPs
        except ValueError:
            return # Invalid IP

        if not self.vt_key: return

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_addr}"
        headers = {"x-apikey": self.vt_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                
                if malicious > 0:
                    efi_node = f"EFI:VT:{ip_addr}"
                    graph.add_node(efi_node, 
                                   type="EFI", 
                                   source="VirusTotal_IP",
                                   score=malicious,
                                   country=data.get("country", "Unknown"))
                    graph.add_edge(node_id, efi_node, relationship="MALICIOUS_IP")
                    print(f"  [+] VT IP Hit: {ip_addr} (Score: {malicious})")
            elif response.status_code == 404:
                print(f"  [-] VT: IP not found.")
        except Exception as e:
            print(f"  [!] VT IP Exception: {e}")

    def _enrich_vt(self, graph, node_id, hash_val):
        """Query VirusTotal for file reputation."""
        if not self.vt_key: return

        url = f"https://www.virustotal.com/api/v3/files/{hash_val}"
        headers = {"x-apikey": self.vt_key}
        
        try:
            # Using verify=False strictly for prototype flexibility/avoiding cert issues on some envs
            # In production, ALWAYS verify SSL.
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                threat_label = data.get("popular_threat_classification", {}).get("suggested_threat_label", "Unknown")

                efi_node = f"EFI:VT:{hash_val[:8]}"
                graph.add_node(efi_node, 
                               type="EFI", 
                               source="VirusTotal",
                               score=malicious,
                               threat=threat_label)
                graph.add_edge(node_id, efi_node, relationship="ENRICHED_BY_VT")
                
                print(f"  [+] VT Hit: {threat_label} (Score: {malicious})")
            elif response.status_code == 404:
                print(f"  [-] VT: Hash not found.")
            else:
                print(f"  [!] VT Error: {response.status_code}")
                
        except Exception as e:
            print(f"  [!] VT Exception: {e}")

    def _enrich_otx(self, graph, node_id, hash_val):
        """Query AlienVault OTX for pulses."""
        if not self.otx_key: return

        url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_val}/general"
        headers = {"X-OTX-API-KEY": self.otx_key}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                
                if pulse_count > 0:
                    otx_node = f"EFI:OTX:{hash_val[:8]}"
                    graph.add_node(otx_node, 
                                   type="EFI", 
                                   source="AlienVault_OTX",
                                   pulses=pulse_count)
                    graph.add_edge(node_id, otx_node, relationship="ENRICHED_BY_OTX")
                    print(f"  [+] OTX Hit: {pulse_count} pulses found.")
            elif response.status_code == 404:
                print(f"  [-] OTX: Hash not found.")
                
        except Exception as e:
            print(f"  [!] OTX Exception: {e}")

    def _enrich_nvd(self, graph, node_id, keyword):
        """Search NVD for CVEs related to the malware family."""
        if not self.nvd_key: return

        # NVD 2.0 API - Keyword Search
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"apiKey": self.nvd_key}
        params = {"keywordSearch": keyword, "resultsPerPage": 3}

        try:
            # NVD can be slow, giving it more time
            response = requests.get(url, headers=headers, params=params, timeout=15)
            
            if response.status_code == 200:
                vulnerabilities = response.json().get("vulnerabilities", [])
                
                if vulnerabilities:
                    for item in vulnerabilities:
                        cve_id = item["cve"]["id"]
                        desc = item["cve"]["descriptions"][0]["value"][:50] + "..."
                        
                        cve_node = f"Vuln:{cve_id}"
                        graph.add_node(cve_node, 
                                       type="Vulnerability", 
                                       source="NVD",
                                       description=desc)
                        graph.add_edge(node_id, cve_node, relationship="RELATED_CVE")
                    print(f"  [+] NVD Hit: Found {len(vulnerabilities)} related CVEs.")
                else:
                    print(f"  [-] NVD: No CVEs found for '{keyword}'.")
                    
        except Exception as e:
            print(f"  [!] NVD Exception: {e}")

    def _generate_leads(self, graph, node_id, node_data):
        """
        Uses the Lead Chaser prompt to generate search queries.
        """
        if not self.client: return

        # 1. Extract Local Subgraph (Context)
        subgraph_triples = []
        for u, v, edge_data in graph.edges(node_id, data=True): 
            subgraph_triples.append(f"{u} -> {edge_data.get('relationship')} -> {v}")
        
        context_str = "\n".join(subgraph_triples)

        # 2. Construct Prompt
        prompt = f"""
        **Role:** You are the CIX Alerts Intelligence Layer (Lead Chaser).
        
        **Context:**
        The following triples represent a localized subgraph of a security alert, including potential MITRE ATT&CK mappings:
        {context_str}

        **Task:** 
        Analyze the evidence (File Paths, Extensions, Malware Families) and the existing MITRE nodes.
        Suggest the **Most Likely MITRE Technique ID** that explains the adversary's objective.
        
        **Conditions:**
        - If the evidence supports a specific technique (e.g., .js file -> T1059.007), confirm it.
        - If the evidence is insufficient, return status "MIMIC_SCOPED".

        **Output JSON:**
        {{
          "leads": [
            {{ 
               "search_query": "site:attack.mitre.org [Technique ID]", 
               "objective": "Confirm usage of [Technique Name] via [Evidence]" 
            }}
          ]
        }}
        """

        try:
            response = self.client.models.generate_content(
                model='gemini-2.0-flash',
                contents=prompt,
                config={
                    'response_mime_type': 'application/json'
                }
            )
            result = json.loads(response.text)
            
            for lead in result.get("leads", []):
                query = lead.get("search_query")
                lead_node = f"Lead:{query[:20]}..."
                graph.add_node(lead_node, type="SearchLead", query=query, status="PROPOSED")
                graph.add_edge(node_id, lead_node, relationship="PROPOSED_SEARCH")
                print(f"  [+] LLM Lead: {query}")

        except Exception as e:
            print(f"  [!] LLM Exception: {e}")