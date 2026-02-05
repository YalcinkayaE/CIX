import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import networkx as nx
from pyvis.network import Network

class GraphVisualizer:
    """
    Generates a visual representation of the forensic graph.
    """
    def __init__(self):
        # AxoDen Palette
        self.color_map = {
            "Alert": "#FF4C4C",          # Red
            "SHA256": "#FFA500",         # Orange
            "MalwareFamily": "#8B0000",  # Dark Red
            "EFI": "#32CD32",            # Lime Green (Verified)
            "SearchLead": "#1E90FF",     # Dodger Blue (Proposed)
            "IP": "#808080",             # Grey
            "ThreatLabel": "#FFD700",    # Gold
            "MITRE_Technique": "#800080", # Purple
            "FileArtifact": "#A9A9A9",    # Dark Grey
            "C2_Domain": "#DC143C",       # Crimson (High Threat)
            "RegistryKey": "#008B8B",     # Dark Cyan
            "VSR_CONFLICT": "#FF1493"     # Deep Pink (Alert)
        }
        self.default_color = "#D3D3D3"   # Light Grey

    def generate_interactive_html(self, graph: nx.DiGraph, output_path: str = "data/investigation_graph_interactive.html"):
        """
        Generates a zoomable, interactive HTML graph using PyVis with a clean light theme and a legend.
        """
        # Create PyVis Network with dynamic height
        net = Network(height="calc(100vh - 50px)", width="100%", bgcolor="#ffffff", font_color="#000000", cdn_resources='in_line')
        
        # Configure Physics
        net.barnes_hut(gravity=-2500, central_gravity=0.3, spring_length=250, spring_strength=0.05, damping=0.09)
        
        present_types = set()
        # Populate Network
        for node, data in graph.nodes(data=True):
            node_type = data.get("type", "Unknown")
            present_types.add(node_type)
            color = self.color_map.get(node_type, self.default_color)
            
            title_html = f"<div style='font-family: Calibri, sans-serif; color: black;'>"
            title_html += f"<b>{node}</b><br>Type: {node_type}<hr style='margin: 4px 0;'>"
            for k, v in data.items():
                if k != "type":
                    title_html += f"<b>{k}:</b> {v}<br>"
            title_html += "</div>"
            
            label = node
            if ":" in node:
                parts = node.split(":")
                if len(parts) > 1:
                    label = f"{parts[0]}\n{parts[1][:12]}..." if len(parts[1]) > 12 else f"{parts[0]}\n{parts[1]}"
            
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
            net.add_edge(
                u, v, 
                title=rel, 
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
            
            for node_type, color in self.color_map.items():
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

    def generate_image(self, graph: nx.DiGraph, output_path: str = "data/investigation_graph.png"):
        """
        Draws the graph and saves it as a PNG.
        """
        # Increase figure size for better spacing
        plt.figure(figsize=(16, 12))
        
        # Determine Layout
        # k=1.5 increases distance between nodes (default is usually smaller)
        # iterations=100 allows the algorithm more time to untangle
        pos = nx.spring_layout(graph, k=1.5, iterations=100, seed=42)

        # Assign colors based on node type
        node_colors = []
        present_types = set()
        for node, data in graph.nodes(data=True):
            node_type = data.get("type", "Unknown")
            present_types.add(node_type)
            node_colors.append(self.color_map.get(node_type, self.default_color))

        # Draw Nodes
        nx.draw_networkx_nodes(graph, pos, node_color=node_colors, node_size=3000, alpha=0.9, edgecolors='black')
        
        # Draw Labels (Clean up long IDs)
        labels = {}
        for node in graph.nodes():
            if "Alert:" in node:
                labels[node] = "ALERT\n" + node.split(":")[1][:6]
            elif "Hash:" in node:
                labels[node] = "SHA256\n" + node.split(":")[1][:6]
            elif "Lead:" in node:
                # Wrap long search queries
                query = node.split(":")[1]
                if len(query) > 20:
                    query = query[:20] + "..."
                labels[node] = "LEAD\n" + query
            elif "EFI:" in node:
                labels[node] = "INTEL\n" + node.split(":")[-1]
            elif "MITRE:" in node:
                labels[node] = node.split(":")[1]
            elif "Path:" in node:
                # Truncate paths heavily
                path_part = node.split("\\")[-1]
                if len(path_part) > 20: path_part = path_part[:20] + "..."
                labels[node] = "PATH\n" + path_part
            else:
                text = node.split(":")[-1] if ":" in node else node
                if len(text) > 15: text = text[:15] + "..."
                labels[node] = text
                
        nx.draw_networkx_labels(graph, pos, labels=labels, font_size=8, font_family="sans-serif", font_weight="bold")

        # Draw Edges with Arrows
        nx.draw_networkx_edges(graph, pos, width=1.5, alpha=0.5, arrowstyle='-|>', arrowsize=20, node_size=3000)
        
        # Edge Labels (Relationship types)
        edge_labels = nx.get_edge_attributes(graph, "relationship")
        # Add bbox to make text readable over lines
        nx.draw_networkx_edge_labels(
            graph, pos, 
            edge_labels=edge_labels, 
            font_size=7, 
            bbox=dict(facecolor='white', alpha=0.8, edgecolor='none', pad=0.5)
        )

        # Create Dynamic Legend
        legend_handles = []
        for node_type, color in self.color_map.items():
            if node_type in present_types:
                patch = mpatches.Patch(color=color, label=node_type)
                legend_handles.append(patch)
        
        plt.legend(handles=legend_handles, loc="upper left", title="Node Types", frameon=True)

        plt.title("CIX Alerts Forensic Graph: Event Flow & Enrichment", fontsize=16)
        plt.axis("off")
        
        try:
            plt.savefig(output_path, bbox_inches="tight", dpi=300)
            print(f"Graph visualization saved to {output_path}")
        except Exception as e:
            print(f"Error saving visualization: {e}")
        finally:
            plt.close()