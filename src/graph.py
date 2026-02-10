import networkx as nx
from src.models import GraphReadyAlert

class GraphConstructor:
    """
    Creates a star-schema graph centered on the eventId with MITRE ATT&CK integration.
    """
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_to_graph(self, graph: nx.DiGraph, alert: GraphReadyAlert):
        """
        Composes a single alert into an existing graph (World Graph).
        """
        # Central node: The Alert
        alert_node = f"Alert:{alert.event_id}"
        graph.add_node(alert_node, type="Alert", event_id=alert.event_id)

        # File Hash Node
        if alert.file_hash_sha256:
            hash_node = f"Hash:{alert.file_hash_sha256}"
            graph.add_node(hash_node, type="SHA256", value=alert.file_hash_sha256)
            graph.add_edge(alert_node, hash_node, relationship="HAS_FILE_HASH")

        # File Name Node
        if alert.file_name:
            file_node = f"File:{alert.file_name}"
            graph.add_node(file_node, type="FileName", value=alert.file_name)
            graph.add_edge(alert_node, file_node, relationship="HAS_FILE_NAME")

        # File Path Node
        if alert.file_path:
            path_node = f"Path:{alert.file_path}"
            graph.add_node(path_node, type="FilePath", value=alert.file_path)
            graph.add_edge(alert_node, path_node, relationship="HAS_FILE_PATH")

        # Host Node
        if alert.hostname:
            host_node = f"Host:{alert.hostname}"
            graph.add_node(host_node, type="Host", value=alert.hostname)
            graph.add_edge(alert_node, host_node, relationship="ON_HOST")

        # User Node
        if alert.user:
            user_node = f"User:{alert.user}"
            graph.add_node(user_node, type="User", value=alert.user)
            graph.add_edge(alert_node, user_node, relationship="OBSERVED_USER")

        # Process Node
        if alert.process_image:
            proc_node = f"Process:{alert.process_image}"
            graph.add_node(proc_node, type="Process", value=alert.process_image)
            graph.add_edge(alert_node, proc_node, relationship="OBSERVED_PROCESS")

        # Parent Process Node
        if alert.parent_process:
            parent_node = f"Process:{alert.parent_process}"
            graph.add_node(parent_node, type="Process", value=alert.parent_process)
            graph.add_edge(alert_node, parent_node, relationship="OBSERVED_PARENT")

        # Command Line Node
        if alert.command_line:
            cmd_node = f"Command:{alert.command_line}"
            graph.add_node(cmd_node, type="CommandLine", value=alert.command_line)
            graph.add_edge(alert_node, cmd_node, relationship="OBSERVED_COMMAND")

        # Source IP Node
        if alert.source_ip:
            ip_node = f"IP:{alert.source_ip}"
            graph.add_node(ip_node, type="IP", value=alert.source_ip)
            graph.add_edge(alert_node, ip_node, relationship="HAS_SOURCE_IP")
        
        # Destination IP Node (Lateral Movement)
        if alert.destination_ip:
            dest_node = f"IP:{alert.destination_ip}"
            graph.add_node(dest_node, type="IP", value=alert.destination_ip)
            graph.add_edge(alert_node, dest_node, relationship="HAS_DEST_IP")
            
            # If both exist, link them to show flow
            if alert.source_ip:
                src_node = f"IP:{alert.source_ip}"
                graph.add_edge(src_node, dest_node, relationship="TARGETS")

        # Malware Family Node
        if alert.malware_family:
            family_node = f"Malware:{alert.malware_family}"
            graph.add_node(family_node, type="MalwareFamily", value=alert.malware_family)
            graph.add_edge(alert_node, family_node, relationship="IDENTIFIED_AS_FAMILY")

        # Rule Intent Node
        if alert.rule_intent:
            intent_node = f"Rule:{alert.rule_intent}"
            graph.add_node(intent_node, type="RuleIntent", value=alert.rule_intent)
            graph.add_edge(alert_node, intent_node, relationship="HAS_RULE_INTENT")

        # --- MITRE ATT&CK Mappings ---
        self._map_mitre_techniques(graph, alert_node, alert)

    def build_graph(self, alert: GraphReadyAlert) -> nx.DiGraph:
        """
        Add nodes and edges from a GraphReadyAlert.
        """
        self.add_to_graph(self.graph, alert)
        return self.graph

    def _map_mitre_techniques(self, graph: nx.DiGraph, alert_node: str, alert: GraphReadyAlert):
        """
        Maps raw alert fields to MITRE ATT&CK Techniques.
        """
        # Mapping 1: File Extension -> Execution Technique
        if alert.file_name and alert.file_name.lower().endswith(".js"):
            tech_node = "MITRE:T1059.007"
            graph.add_node(tech_node, type="MITRE_Technique", 
                                name="Command and Scripting Interpreter: JavaScript",
                                tactic="Execution")
            graph.add_edge(alert_node, tech_node, relationship="INDICATES_TECHNIQUE")
            # Link file name to technique for traceability
            file_node = f"File:{alert.file_name}"
            graph.add_node(file_node, type="FileArtifact", value=alert.file_name)
            graph.add_edge(alert_node, file_node, relationship="HAS_FILE_NAME")
            graph.add_edge(file_node, tech_node, relationship="MAPPED_TO")

        # Mapping 2: File Path -> Collection/Staging
        if alert.file_path and ("temp" in alert.file_path.lower() or "tmp" in alert.file_path.lower()):
            tech_node = "MITRE:T1074.001"
            graph.add_node(tech_node, type="MITRE_Technique", 
                                name="Data Staged: Local Data Staging",
                                tactic="Collection")
            graph.add_edge(alert_node, tech_node, relationship="INDICATES_TECHNIQUE")
            # Link path to technique
            path_node = f"Path:{alert.file_path}"
            graph.add_node(path_node, type="FileArtifact", value=alert.file_path)
            graph.add_edge(alert_node, path_node, relationship="HAS_FILE_PATH")
            graph.add_edge(path_node, tech_node, relationship="MAPPED_TO")

        # Mapping 2b: VBScript execution via wscript/cscript or .vbs
        cmd = (alert.command_line or "").lower()
        file_name = (alert.file_name or "").lower()
        process_image = (alert.process_image or "").lower()
        if file_name.endswith(".vbs") or "wscript.exe" in cmd or "cscript.exe" in cmd or "wscript.exe" in process_image:
            tech_node = "MITRE:T1059.005"
            graph.add_node(
                tech_node,
                type="MITRE_Technique",
                name="Command and Scripting Interpreter: Visual Basic",
                tactic="Execution",
            )
            graph.add_edge(alert_node, tech_node, relationship="INDICATES_TECHNIQUE")

        # Mapping 2c: PowerShell encoded/exec policy bypass
        if "powershell.exe" in cmd and (" -enc" in cmd or " -encodedcommand" in cmd or " -nop" in cmd):
            tech_node = "MITRE:T1059.001"
            graph.add_node(
                tech_node,
                type="MITRE_Technique",
                name="Command and Scripting Interpreter: PowerShell",
                tactic="Execution",
            )
            graph.add_edge(alert_node, tech_node, relationship="INDICATES_TECHNIQUE")

        # Mapping 2d: System information discovery (whoami)
        if "whoami.exe" in cmd or file_name == "whoami.exe":
            tech_node = "MITRE:T1082"
            graph.add_node(
                tech_node,
                type="MITRE_Technique",
                name="System Information Discovery",
                tactic="Discovery",
            )
            graph.add_edge(alert_node, tech_node, relationship="INDICATES_TECHNIQUE")

        # Mapping 3: Rule Intent -> Tactic
        if alert.rule_intent == "System Compromise":
            pass 

        # Additional Mapping per brief: Malware Family -> Credential Access
        if alert.malware_family == "ChatGPTStealer":
            tech_node = "MITRE:T1555"
            graph.add_node(tech_node, type="MITRE_Technique", 
                                name="Credentials from Password Stores",
                                tactic="Credential Access")
            if alert.malware_family:
                family_node = f"Malware:{alert.malware_family}"
                graph.add_edge(family_node, tech_node, relationship="USES_TECHNIQUE")
                
        # Mapping 4: BlackCat/Ransomware
        if alert.malware_family == "BlackCat" or alert.rule_intent == "Ransomware Deployment":
             # T1486: Data Encrypted for Impact
             enc_node = "MITRE:T1486"
             graph.add_node(enc_node, type="MITRE_Technique", name="Data Encrypted for Impact", tactic="Impact")
             graph.add_edge(alert_node, enc_node, relationship="INDICATES_TECHNIQUE")
             
             # T1021: Remote Services (Lateral Movement) if we have movement
             if alert.destination_ip:
                 lat_node = "MITRE:T1021"
                 graph.add_node(lat_node, type="MITRE_Technique", name="Remote Services", tactic="Lateral Movement")
                 graph.add_edge(alert_node, lat_node, relationship="INDICATES_TECHNIQUE")
                 
             if alert.malware_family:
                family_node = f"Malware:{alert.malware_family}"
                graph.add_edge(family_node, enc_node, relationship="USES_TECHNIQUE")

    def get_triples(self):
        """
        Extract all triples (Source, Relationship, Target) for forensic ledger.
        """
        triples = []
        for u, v, data in self.graph.edges(data=True):
            triples.append({
                "source": u,
                "relationship": data.get("relationship", "CONNECTED_TO"),
                "target": v
            })
        return triples
