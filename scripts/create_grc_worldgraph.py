
import networkx as nx
import matplotlib.pyplot as plt
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from pyvis.network import Network
import os

# --- Data Structures (Mirrored from axoden-SFA/src/grc/regulatory_map.py) ---

@dataclass(frozen=True)
class RegulatoryImpact:
    framework: str
    justification: str
    notification_deadline_hours: Optional[int] = None
    required_actions: Tuple[str, ...] = ()
    fine_range: Optional[str] = None

_TAG_RULES: Dict[str, List[RegulatoryImpact]] = {
    "bruteforce_external": [
        RegulatoryImpact(
            framework="NIST CSF",
            justification="Indicators of external intrusion attempt",
            required_actions=("Increase monitoring", "Enforce account lockout and MFA"),
        ),
        RegulatoryImpact(
            framework="SOC 2",
            justification="Repeated authentication failures weaken logical access controls",
            required_actions=(
                "Document incident within change log",
                "Revalidate access reviews",
            ),
        ),
    ],
    "credential_dumping": [
        RegulatoryImpact(
            framework="PCI DSS",
            justification="Compromise of cardholder or authentication data",
            required_actions=("Engage QSA", "Rotate payment system credentials"),
        ),
        RegulatoryImpact(
            framework="SOX",
            justification="Potential access to financial reporting systems",
            required_actions=("Initiate SOX Section 404 control review",),
        ),
    ],
    "data_staging": [
        RegulatoryImpact(
            framework="GDPR",
            justification="Possible exposure of EU personal data",
            notification_deadline_hours=72,
            required_actions=(
                "Notify supervisory authority",
                "Evaluate data subject impact",
            ),
            fine_range="Up to 4% global revenue",
        ),
        RegulatoryImpact(
            framework="CCPA",
            justification="California resident data may be at risk",
            required_actions=("Inform legal counsel", "Prepare consumer notification"),
        ),
    ],
    "dll_drop": [
        RegulatoryImpact(
            framework="HIPAA",
            justification="Malware on systems processing health data may expose PHI",
            notification_deadline_hours=1440,  # 60 days
            required_actions=("Notify compliance officer", "Assess PHI footprint"),
        ),
        RegulatoryImpact(
            framework="ISO 27001",
            justification="Persistence via malicious DLL requires containment and eradication",
            required_actions=(
                "Trigger incident response plan",
                "Verify malware eradication",
            ),
        ),
    ],
    "exfiltration_channel": [
        RegulatoryImpact(
            framework="GDPR",
            justification="Potential exfiltration via anonymised channel",
            notification_deadline_hours=72,
            required_actions=(
                "Preserve forensic evidence",
                "Assess breach notification duties",
            ),
        )
    ],
    "group_modification": [
        RegulatoryImpact(
            framework="SOX",
            justification="Privileged group membership changed outside normal controls",
            required_actions=(
                "Review privileged account activity",
                "Document remediation",
            ),
        )
    ],
    "ingress_tool_transfer": [
        RegulatoryImpact(
            framework="NIS2",
            justification="Living-off-the-land binary used to retrieve payloads on essential service infrastructure",
            required_actions=(
                "Alert national CSIRT if required",
                "Increase monitoring on essential assets",
            ),
        ),
        RegulatoryImpact(
            framework="SOC 2",
            justification="Unsigned download pipeline indicates gaps in change management controls",
            required_actions=("Document incident", "Run compensating control review"),
        ),
    ],
    "lateral_movement": [
        RegulatoryImpact(
            framework="NIST CSF",
            justification="Attacker movement between hosts threatens containment",
            required_actions=(
                "Segment affected network",
                "Harden remote management interfaces",
            ),
        )
    ],
    "malicious_service": [
        RegulatoryImpact(
            framework="ISO 27001",
            justification="Unapproved long-lived service indicating persistence",
            required_actions=("Catalogue affected assets", "Remove malicious service"),
        )
    ],
    "persistence": [
        RegulatoryImpact(
            framework="ISO 27001",
            justification="Evidence of adversary persistence requires containment and eradication",
            required_actions=(
                "Trigger incident response plan",
                "Verify malware eradication",
            ),
        )
    ],
    "persistence_registry": [
        RegulatoryImpact(
            framework="ISO 27001",
            justification="Persistent malware foothold on critical assets",
            required_actions=("Trigger incident response plan",),
        )
    ],
    "powershell_bypass": [
        RegulatoryImpact(
            framework="NIS2",
            justification="Scripted execution bypassing security controls indicates compromise of essential services",
            required_actions=(
                "Notify competent authority when applicable",
                "Capture volatile evidence",
            ),
        )
    ],
    "privilege_escalation": [
        RegulatoryImpact(
            framework="SOX",
            justification="Privileged access to financial controls escalated",
            required_actions=(
                "Review privileged account activity",
                "Document remediation",
            ),
        ),
        RegulatoryImpact(
            framework="ISO 27001",
            justification="Elevation of privilege expands breach blast radius on protected assets",
            required_actions=(
                "Disable suspicious accounts",
                "Rotate administrative credentials",
            ),
        ),
    ],
    "remote_execution": [
        RegulatoryImpact(
            framework="SOC 2",
            justification="Remote code execution impacts the security and availability trust principles",
            required_actions=("Document incident", "Validate remote access controls"),
        )
    ],
    "sensitive_file_access": [
        RegulatoryImpact(
            framework="GDPR",
            justification="Sensitive records accessed outside normal patterns",
            notification_deadline_hours=72,
            required_actions=("Notify DPO", "Assess data subject impact"),
        )
    ],
    "signed_binary_proxy": [
        RegulatoryImpact(
            framework="NIS2",
            justification="Abuse of signed binaries indicates sophisticated intrusion techniques",
            required_actions=(
                "Alert national CSIRT if required",
                "Review application whitelisting controls",
            ),
        )
    ],
    "tor_egress": [
        RegulatoryImpact(
            framework="GDPR",
            justification="Potential exfiltration via anonymised channel",
            notification_deadline_hours=72,
            required_actions=(
                "Preserve forensic evidence",
                "Assess breach notification duties",
            ),
        )
    ],
}

_DATA_CATEGORY_RULES: Dict[str, List[RegulatoryImpact]] = {
    "credentials": [
        RegulatoryImpact(
            framework="PCI DSS",
            justification="Credential compromise impacting payment systems",
            required_actions=("Rotate credentials", "Perform access review"),
        )
    ],
    "pii": [
        RegulatoryImpact(
            framework="GDPR",
            justification="Personally identifiable information accessed",
            notification_deadline_hours=72,
            required_actions=("Notify DPO", "Assess data subject impact"),
            fine_range="Up to 4% global revenue",
        ),
        RegulatoryImpact(
            framework="CCPA",
            justification="Consumer personal data potentially exposed",
            required_actions=("Prepare notice of data breach",),
        ),
    ],
    "phi": [
        RegulatoryImpact(
            framework="HIPAA",
            justification="Protected health information at risk",
            notification_deadline_hours=1440,
            required_actions=("Notify HHS", "Inform affected individuals"),
        )
    ],
}

# --- Graph Construction ---

def create_grc_worldgraph():
    G = nx.DiGraph()

    # Process Threat Tag Rules
    for threat, impacts in _TAG_RULES.items():
        threat_node = f"Threat:{threat}"
        G.add_node(threat_node, type="ThreatTag", label=threat)

        for impact in impacts:
            fw_node = f"Framework:{impact.framework}"
            G.add_node(fw_node, type="Framework", label=impact.framework)
            
            # Edge: Threat -> Framework
            # Attributes: Justification, Deadline, Fine
            edge_attrs = {"justification": impact.justification}
            if impact.notification_deadline_hours:
                edge_attrs["deadline_hours"] = impact.notification_deadline_hours
            if impact.fine_range:
                edge_attrs["fine_range"] = impact.fine_range
            
            G.add_edge(threat_node, fw_node, relationship="IMPACTS", **edge_attrs)

            # Actions
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
            G.add_node(fw_node, type="Framework", label=impact.framework)
            
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

def visualize_graph(G, output_file="grc_worldgraph.png"):
    plt.figure(figsize=(20, 15))
    pos = nx.spring_layout(G, k=0.3, iterations=50)

    # Node Colors
    color_map = []
    for node in G.nodes():
        node_type = G.nodes[node].get("type")
        if node_type == "ThreatTag":
            color_map.append("#FF9999") # Light Red
        elif node_type == "DataCategory":
            color_map.append("#FFCC99") # Light Orange
        elif node_type == "Framework":
            color_map.append("#99CCFF") # Light Blue
        elif node_type == "RequiredAction":
            color_map.append("#99FF99") # Light Green
        else:
            color_map.append("#CCCCCC") # Grey

    # Draw Nodes
    nx.draw_networkx_nodes(G, pos, node_color=color_map, node_size=2000, alpha=0.9)
    
    # Draw Edges
    nx.draw_networkx_edges(G, pos, edge_color="grey", arrows=True, alpha=0.5)

    # Labels
    labels = {node: G.nodes[node].get("label", node) for node in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=8, font_family="sans-serif")
    
    # Edge Labels (Optional - can be cluttered)
    # edge_labels = nx.get_edge_attributes(G, 'relationship')
    # nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=6)

    plt.title("GRC Threat-Compliance World Graph", fontsize=20)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(output_file, dpi=300)
    print(f"Graph visualization saved to {output_file}")

def generate_interactive_html(graph: nx.DiGraph, output_path: str = "grc_worldgraph.html"):
    """
    Generates a zoomable, interactive HTML graph using PyVis with a clean light theme and a legend.
    """
    # Color Map for Interactive Graph
    color_map = {
        "ThreatTag": "#FF4C4C",       # Red
        "DataCategory": "#FFA500",    # Orange
        "Framework": "#1E90FF",       # Dodger Blue
        "RequiredAction": "#32CD32",  # Lime Green
    }
    default_color = "#D3D3D3"

    # Create PyVis Network with dynamic height
    net = Network(height="calc(100vh - 50px)", width="100%", bgcolor="#ffffff", font_color="#000000", cdn_resources='in_line')
    
    # Configure Physics
    net.barnes_hut(gravity=-2500, central_gravity=0.3, spring_length=200, spring_strength=0.05, damping=0.09)
    
    present_types = set()
    # Populate Network
    for node, data in graph.nodes(data=True):
        node_type = data.get("type", "Unknown")
        present_types.add(node_type)
        color = color_map.get(node_type, default_color)
        
        # Tooltip
        title_html = f"<div style='font-family: Calibri, sans-serif; color: black;'>"
        title_html += f"<b>{node}</b><br>Type: {node_type}<hr style='margin: 4px 0;'>"
        for k, v in data.items():
            if k != "type":
                title_html += f"<b>{k}:</b> {v}<br>"
        title_html += "</div>"
        
        label = data.get("label", node)
        
        net.add_node(
            node, 
            label=label, 
            title=title_html, 
            color=color, 
            shape="dot", 
            size=25,
            font={'face': 'Calibri, sans-serif', 'color': '#000000', 'size': 14}
        )

    for u, v, data in graph.edges(data=True):
        rel = data.get("relationship", "RELATED")
        
        # Build tooltip for edges (Justification, etc.)
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

    # Save and Inject Legend
    try:
        # Generate the raw HTML string
        html_content = net.generate_html()
        
        # CSS for layout and legend
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
        
        # Create Legend Content
        legend_content = "<div id='graph-legend'>"
        legend_content += "<h3 style='margin: 0 0 10px 0; font-size: 16px; border-bottom: 1px solid #eee; padding-bottom: 5px; color: #000;'>Node Legend</h3>"
        
        for node_type, color in color_map.items():
            if node_type in present_types:
                legend_content += f"<div style='display: flex; align-items: center; margin-bottom: 8px;'>"
                legend_content += f"<div style='width: 16px; height: 18px; background: {color}; margin-right: 12px; border-radius: 4px; border: 1px solid #666;'></div>"
                legend_content += f"<span style='font-size: 14px; color: #333;'>{node_type}</span>"
                legend_content += "</div>"
        legend_content += "</div>"

        # Inject into the HTML
        final_html = html_content.replace("<head>", f"<head>{custom_style}")
        final_html = final_html.replace("</body>", f"{legend_content}</body>")
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(final_html)
            
        print(f"Interactive optimized graph saved to {output_path}")
    except Exception as e:
        print(f"Error saving interactive graph: {e}")

if __name__ == "__main__":
    graph = create_grc_worldgraph()
    print(f"Graph created with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges.")
    visualize_graph(graph)
    generate_interactive_html(graph)
