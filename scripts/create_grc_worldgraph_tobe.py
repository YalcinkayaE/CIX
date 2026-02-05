import networkx as nx
import matplotlib.pyplot as plt
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from pyvis.network import Network
import os

# --- Data Structures ---

@dataclass(frozen=True)
class RegulatoryImpact:
    framework: str
    justification: str
    notification_deadline_hours: Optional[int] = None
    required_actions: Tuple[str, ...] = ()
    fine_range: Optional[str] = None

# --- ENHANCED & NEW RULES (TO-BE STATE) ---
_TAG_RULES: Dict[str, List[RegulatoryImpact]] = {
    # --- Existing & Improved ---
    "bruteforce_external": [
        RegulatoryImpact(framework="NIST CSF", justification="Indicators of external intrusion attempt", required_actions=("Increase monitoring", "Enforce account lockout and MFA")),
        RegulatoryImpact(framework="SOC 2", justification="Repeated authentication failures weaken logical access controls", required_actions=("Document incident", "Revalidate access reviews")),
        # GAP FILLED: PCI DSS
        RegulatoryImpact(framework="PCI DSS", justification="Repeated login failures (Req 8.1.6)", required_actions=("Lockout account for 30 mins",))
    ],
    "credential_dumping": [
        RegulatoryImpact(framework="PCI DSS", justification="Compromise of cardholder authentication data", required_actions=("Engage QSA", "Rotate credentials")),
        RegulatoryImpact(framework="SOX", justification="Access to financial reporting systems", required_actions=("Initiate SOX 404 review",)),
        # GAP FILLED: NIST CSF
        RegulatoryImpact(framework="NIST CSF", justification="Credential Access (PR.AC)", required_actions=("Revoke compromised credentials",))
    ],
    "lateral_movement": [
        RegulatoryImpact(framework="NIST CSF", justification="Attacker movement threatens containment", required_actions=("Segment network",)),
        # GAP FILLED: PCI DSS
        RegulatoryImpact(framework="PCI DSS", justification="Failure of network segmentation (Req 11)", required_actions=("Verify CDE isolation",))
    ],
    
    # --- GAP FILLING: Previously Unmapped Tags ---
    "remote_services": [
        RegulatoryImpact(framework="ISO 27001", justification="Unauth remote access (A.9.2)", required_actions=("Review access logs", "Terminate session")),
        RegulatoryImpact(framework="PCI DSS", justification="Insecure remote access (Req 12.3)", required_actions=("Enforce MFA",))
    ],
    "rdp": [
        RegulatoryImpact(framework="NIST CSF", justification="Remote Access weakness (PR.AC-3)", required_actions=("Disable RDP internet exposure",))
    ],
    "ssh": [
        RegulatoryImpact(framework="SOC 2", justification="Unauthorized administrative access", required_actions=("Verify SSH key inventory",))
    ],
    "exfiltration": [
        RegulatoryImpact(framework="GDPR", justification="Data breach (Article 33)", notification_deadline_hours=72, fine_range="Up to 4% global revenue", required_actions=("Notify DPO",)),
        RegulatoryImpact(framework="CCPA", justification="Data theft", required_actions=("Notify consumers",))
    ],
    "archive_collection": [
        RegulatoryImpact(framework="HIPAA", justification="Potential aggregation of PHI", required_actions=("Audit access logs",))
    ],
    
    # --- NEW: AI GOVERNANCE (ISO 42001, EU AI Act, NIST AI RMF) ---
    "prompt_injection": [
        RegulatoryImpact(
            framework="ISO 42001",
            justification="Adversarial attack compromising AI system control (A.6.2)",
            required_actions=("Review input filters", "Patch model guardrails")
        ),
        RegulatoryImpact(
            framework="NIST AI RMF",
            justification="Evasion attack failure (Measure 2.4)",
            required_actions=("Test robustness", "Update risk map")
        ),
        RegulatoryImpact(
            framework="EU AI Act",
            justification="Exploitation of High-Risk AI System vulnerabilities (Art. 15)",
            fine_range="Up to 30M EUR or 6% turnover",
            required_actions=("Report serious incident", "Update technical documentation")
        )
    ],
    "training_data_poisoning": [
        RegulatoryImpact(
            framework="ISO 42001",
            justification="Compromise of Data Quality and Integrity (A.5.8)",
            required_actions=("Restore data from backup", "Retrain model")
        ),
        RegulatoryImpact(
            framework="EU AI Act",
            justification="Data governance failure (Art. 10)",
            required_actions=("Validate training sets",)
        )
    ],
    "model_inversion": [
        RegulatoryImpact(
            framework="GDPR",
            justification="Re-identification of subjects from model output (Privacy Attack)",
            notification_deadline_hours=72,
            required_actions=("Assess privacy impact",)
        ),
        RegulatoryImpact(
            framework="NIST AI RMF",
            justification="Privacy leak in map/measure function",
            required_actions=("Implement Differential Privacy",)
        )
    ],
    "shadow_ai_usage": [
        RegulatoryImpact(
            framework="ISO 42001",
            justification="Unauthorised use of AI resources (A.6.1)",
            required_actions=("Update AI inventory", "Enforce acceptable use policy")
        ),
        RegulatoryImpact(
            framework="SOC 2",
            justification="Unauthorized software/service usage",
            required_actions=("Vendor risk assessment",)
        )
    ],
    
    # --- Other standard tags (abbreviated for brevity) ---
    "data_staging": [
        RegulatoryImpact(framework="GDPR", justification="Possible exposure of EU personal data", notification_deadline_hours=72, required_actions=("Notify DPO",)),
    ],
    "persistence": [
        RegulatoryImpact(framework="ISO 27001", justification="Evidence of adversary persistence", required_actions=("Trigger IRP",))
    ],
    "malicious_service": [RegulatoryImpact(framework="ISO 27001", justification="Unapproved service", required_actions=("Remove service",))], 
    "dll_drop": [RegulatoryImpact(framework="HIPAA", justification="Malware on PHI systems", notification_deadline_hours=1440, required_actions=("Notify compliance",))], 
    "ingress_tool_transfer": [RegulatoryImpact(framework="NIS2", justification="Living-off-the-land binary", required_actions=("Alert CSIRT",))], 
    "privilege_escalation": [RegulatoryImpact(framework="SOX", justification="Privileged access change", required_actions=("Review audit logs",))],
}

_DATA_CATEGORY_RULES: Dict[str, List[RegulatoryImpact]] = {
    "credentials": [
        RegulatoryImpact(framework="PCI DSS", justification="Credential compromise", required_actions=("Rotate credentials",))
    ],
    "pii": [
        RegulatoryImpact(framework="GDPR", justification="PII accessed", notification_deadline_hours=72, fine_range="4% Revenue", required_actions=("Notify DPO",)),
        RegulatoryImpact(framework="CCPA", justification="Consumer data exposed", required_actions=("Notify consumers",))
    ],
    "phi": [
        RegulatoryImpact(framework="HIPAA", justification="PHI risk", notification_deadline_hours=1440, required_actions=("Notify HHS",))
    ],
    # --- NEW: AI Data Categories ---
    "ai_training_data": [
        RegulatoryImpact(framework="ISO 42001", justification="Core asset integrity risk", required_actions=("Verify data lineage",)),
        RegulatoryImpact(framework="EU AI Act", justification="Training data governance artifact", required_actions=("Audit data provenance",))
    ],
    "model_weights": [
        RegulatoryImpact(framework="ISO 27001", justification="Intellectual Property theft", required_actions=("Revoke access",))
    ]
}

# --- Graph Construction ---

def create_grc_worldgraph_tobe():
    G = nx.DiGraph()

    # Process Threat Tag Rules
    for threat, impacts in _TAG_RULES.items():
        threat_node = f"Threat:{threat}"
        # Determine type (AI threats vs Standard)
        t_type = "AI_Threat" if threat in {"prompt_injection", "training_data_poisoning", "model_inversion", "shadow_ai_usage"} else "ThreatTag"
        G.add_node(threat_node, type=t_type, label=threat)

        for impact in impacts:
            fw_node = f"Framework:{impact.framework}"
            # Differentiate AI Frameworks
            f_type = "AI_Framework" if impact.framework in {"ISO 42001", "EU AI Act", "NIST AI RMF"} else "Framework"
            G.add_node(fw_node, type=f_type, label=impact.framework)
            
            edge_attrs = {"justification": impact.justification}
            if impact.notification_deadline_hours:
                edge_attrs["deadline_hours"] = impact.notification_deadline_hours
            if impact.fine_range:
                edge_attrs["fine_range"] = impact.fine_range
            
            G.add_edge(threat_node, fw_node, relationship="IMPACTS", **edge_attrs)

            for action in impact.required_actions:
                action_node = f"Action:{action}"
                G.add_node(action_node, type="RequiredAction", label=action)
                G.add_edge(fw_node, action_node, relationship="MANDATES")

    # Process Data Category Rules
    for category, impacts in _DATA_CATEGORY_RULES.items():
        cat_node = f"DataCategory:{category}"
        G.add_node(cat_node, type="DataCategory", label=category)

        for impact in impacts:
            fw_node = f"Framework:{impact.framework}"
            f_type = "AI_Framework" if impact.framework in {"ISO 42001", "EU AI Act", "NIST AI RMF"} else "Framework"
            G.add_node(fw_node, type=f_type, label=impact.framework)
            
            edge_attrs = {"justification": impact.justification}
            if impact.notification_deadline_hours:
                edge_attrs["deadline_hours"] = impact.notification_deadline_hours
            if impact.fine_range:
                edge_attrs["fine_range"] = impact.fine_range
            
            G.add_edge(cat_node, fw_node, relationship="REGULATES", **edge_attrs)

            for action in impact.required_actions:
                action_node = f"Action:{action}"
                G.add_node(action_node, type="RequiredAction", label=action)
                G.add_edge(fw_node, action_node, relationship="MANDATES")

    return G

def visualize_graph(G, output_file="grc_worldgraph_tobe.png"):
    plt.figure(figsize=(22, 16))
    pos = nx.spring_layout(G, k=0.35, iterations=60, seed=42)

    # Node Colors
    color_map = []
    for node in G.nodes():
        node_type = G.nodes[node].get("type")
        if node_type == "ThreatTag":
            color_map.append("#FF9999") # Light Red
        elif node_type == "AI_Threat":
            color_map.append("#FF0000") # Deep Red
        elif node_type == "DataCategory":
            color_map.append("#FFCC99") # Light Orange
        elif node_type == "Framework":
            color_map.append("#99CCFF") # Light Blue
        elif node_type == "AI_Framework":
            color_map.append("#0000FF") # Deep Blue
        elif node_type == "RequiredAction":
            color_map.append("#99FF99") # Light Green
        else:
            color_map.append("#CCCCCC") # Grey

    # Draw Nodes
    nx.draw_networkx_nodes(G, pos, node_color=color_map, node_size=1800, alpha=0.9)
    nx.draw_networkx_edges(G, pos, edge_color="grey", arrows=True, alpha=0.5)

    labels = {node: G.nodes[node].get("label", node) for node in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=7, font_family="sans-serif")

    plt.title("TO-BE GRC World Graph (Inc. ISO 42001 & AI Governance)", fontsize=22)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(output_file, dpi=300)
    print(f"Static TO-BE graph saved to {output_file}")

def generate_interactive_html(graph: nx.DiGraph, output_path: str = "grc_worldgraph_tobe.html"):
    # Color Map for Interactive Graph
    color_map = {
        "ThreatTag": "#FF4C4C",       # Red
        "AI_Threat": "#8B0000",       # Dark Red (New)
        "DataCategory": "#FFA500",    # Orange
        "Framework": "#1E90FF",       # Dodger Blue
        "AI_Framework": "#00008B",    # Dark Blue (New)
        "RequiredAction": "#32CD32",  # Lime Green
    }
    default_color = "#D3D3D3"

    net = Network(height="calc(100vh - 50px)", width="100%", bgcolor="#ffffff", font_color="#000000", cdn_resources='in_line')
    net.barnes_hut(gravity=-2800, central_gravity=0.4, spring_length=220, spring_strength=0.04, damping=0.09)
    
    present_types = set()
    for node, data in graph.nodes(data=True):
        node_type = data.get("type", "Unknown")
        present_types.add(node_type)
        color = color_map.get(node_type, default_color)
        
        title_html = f"<div style='font-family: Calibri, sans-serif; color: black;'>"
        title_html += f"<b>{node}</b><br>Type: {node_type}<hr style='margin: 4px 0;'>"
        for k, v in data.items():
            if k != "type":
                title_html += f"<b>{k}:</b> {v}<br>"
        title_html += "</div>"
        
        label = data.get("label", node)
        
        # Make AI nodes slightly larger/different shape if desired (sticking to color diff for now)
        size = 30 if "AI" in node_type else 20
        
        net.add_node(
            node, 
            label=label, 
            title=title_html, 
            color=color, 
            shape="dot", 
            size=size,
            font={'face': 'Calibri, sans-serif', 'color': '#000000', 'size': 14}
        )

    for u, v, data in graph.edges(data=True):
        rel = data.get("relationship", "RELATED")
        edge_title = f"Relationship: {rel}"
        for k, val in data.items():
            if k != "relationship":
                edge_title += f"\n{k}: {val}"

        net.add_edge(
            u, v, 
            title=edge_title, 
            label=rel, 
            color="#666666", 
            arrows="to",
            font={'face': 'Calibri, sans-serif', 'color': '#333333', 'size': 10, 'align': 'top'}
        )

    try:
        html_content = net.generate_html()
        custom_style = """
        <style>
            body { margin: 0; padding: 0; overflow: hidden; background-color: #ffffff; }
            #mynetwork { border: none !important; }
            #graph-legend {
                position: absolute; top: 20px; right: 20px; width: 220px; 
                background: rgba(255,255,255,0.95); border: 1px solid #ddd; 
                padding: 15px; font-family: Calibri, sans-serif; z-index: 999; 
                box-shadow: 0 4px 12px rgba(0,0,0,0.1); border-radius: 10px;
            }
        </style>
        """
        legend_content = "<div id='graph-legend'>"
        legend_content += "<h3 style='margin: 0 0 10px 0; font-size: 16px; border-bottom: 1px solid #eee; padding-bottom: 5px; color: #000;'>Node Legend</h3>"
        for node_type, color in color_map.items():
            if node_type in present_types:
                legend_content += f"<div style='display: flex; align-items: center; margin-bottom: 8px;'>"
                legend_content += f"<div style='width: 16px; height: 18px; background: {color}; margin-right: 12px; border-radius: 4px; border: 1px solid #666;'></div>"
                legend_content += f"<span style='font-size: 14px; color: #333;'>{node_type}</span>"
                legend_content += "</div>"
        legend_content += "</div>"
        
        final_html = html_content.replace("<head>", f"<head>{custom_style}")
        final_html = final_html.replace("</body>", f"{legend_content}</body>")
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(final_html)
        print(f"Interactive TO-BE graph saved to {output_path}")
    except Exception as e:
        print(f"Error saving interactive graph: {e}")

if __name__ == "__main__":
    graph = create_grc_worldgraph_tobe()
    print(f"TO-BE Graph created with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges.")
    visualize_graph(graph)
    generate_interactive_html(graph)
