
import json
import networkx as nx
from pyvis.network import Network

def generate_framework_graph():
    # 1. Define Nodes
    nodes = [
        # International Standards
        {"id": "ISO_27001", "label": "ISO/IEC 27001", "type": "Security Standard", "version": "2022", "geography": "International"},
        {"id": "ISO_42001", "label": "ISO/IEC 42001", "type": "AI Governance", "version": "2023", "geography": "International"},
        {"id": "PCI_DSS", "label": "PCI DSS", "type": "Security Standard", "version": "4.0", "geography": "International"},
        
        # USA Frameworks & Regulations
        {"id": "NIST_CSF", "label": "NIST CSF", "type": "Security Framework", "version": "2.0", "geography": "USA"},
        {"id": "NIST_AI_RMF", "label": "NIST AI RMF", "type": "AI Governance", "version": "1.0", "geography": "USA"},
        {"id": "SOX", "label": "Sarbanes-Oxley (SOX)", "type": "Financial Regulation", "version": "2002", "geography": "USA"},
        {"id": "HIPAA", "label": "HIPAA", "type": "Privacy Regulation", "version": "1996", "geography": "USA"},
        {"id": "CCPA_CPRA", "label": "CCPA / CPRA", "type": "Privacy Regulation", "version": "2018/2020", "geography": "USA (California)"},
        
        # EU Regulations
        {"id": "GDPR", "label": "GDPR", "type": "Privacy Regulation", "version": "2016/679", "geography": "EU"},
        {"id": "EU_AI_Act", "label": "EU AI Act", "type": "AI Governance", "version": "2024", "geography": "EU"},
        {"id": "NIS2", "label": "NIS2 Directive", "type": "Resilience Regulation", "version": "2022/2555", "geography": "EU"},
        {"id": "DORA", "label": "DORA", "type": "Resilience Regulation", "version": "2022/2554", "geography": "EU"},
    ]

    # 2. Define Edges (Relationships)
    edges = [
        {"source": "ISO_42001", "target": "ISO_27001", "label": "extends management system of"},
        {"source": "NIST_CSF", "target": "ISO_27001", "label": "aligns with"},
        {"source": "NIST_AI_RMF", "target": "NIST_CSF", "label": "related to"},
        {"source": "EU_AI_Act", "target": "GDPR", "label": "complements"},
        {"source": "EU_AI_Act", "target": "ISO_42001", "label": "can be operationalized by"},
        {"source": "GDPR", "target": "CCPA_CPRA", "label": "influences"},
        {"source": "NIS2", "target": "ISO_27001", "label": "references controls from"},
        {"source": "DORA", "target": "NIS2", "label": "lex specialis to"},
        {"source": "SOX", "target": "NIST_CSF", "label": "often mapped to"},
        {"source": "HIPAA", "target": "NIST_CSF", "label": "often mapped to"},
        {"source": "PCI_DSS", "target": "ISO_27001", "label": "subset of controls in"},
        {"source": "NIST_AI_RMF", "target": "EU_AI_Act", "label": "shares risk-based approach with"},
    ]

    # 3. Output JSON Data
    graph_data = {
        "nodes": nodes,
        "edges": edges
    }
    
    with open("frameworks_graph.json", "w", encoding="utf-8") as f:
        json.dump(graph_data, f, indent=2)
    print("JSON data saved to frameworks_graph.json")

    # 4. Generate Visualization (PyVis)
    net = Network(height="calc(100vh - 50px)", width="100%", bgcolor="#ffffff", font_color="#000000", cdn_resources='in_line')
    
    # Physics settings for a nice layout
    net.barnes_hut(gravity=-4000, central_gravity=0.3, spring_length=150, spring_strength=0.05, damping=0.09)

    # Color mapping for Category (Type)
    type_colors = {
        "Security Standard": "#4CAF50",    # Green
        "Security Framework": "#8BC34A",   # Light Green
        "Privacy Regulation": "#2196F3",   # Blue
        "AI Governance": "#FF5722",        # Deep Orange
        "Financial Regulation": "#FFC107", # Amber
        "Resilience Regulation": "#9C27B0" # Purple
    }
    
    # Add Nodes
    for n in nodes:
        color = type_colors.get(n["type"], "#9E9E9E")
        
        # Tooltip content
        title_html = (
            f"<div style='font-family: Arial; color: black; padding: 5px;'>"
            f"<b>{n['label']}</b><br>"
            f"Type: {n['type']}<br>"
            f"Version: {n['version']}<br>"
            f"Geography: {n['geography']}"
            f"</div>"
        )
        
        # Label with name + version
        label_text = f"{n['label']}\n(v{n['version']})"

        net.add_node(
            n["id"],
            label=label_text,
            title=title_html,
            color=color,
            shape="box",  # Box shape fits text better
            font={'face': 'Arial', 'color': '#FFFFFF', 'size': 16}
        )

    # Add Edges
    for e in edges:
        net.add_edge(
            e["source"],
            e["target"],
            label=e["label"],
            title=e["label"],
            color="#BDBDBD",
            arrows="to",
            font={'align': 'middle', 'size': 10}
        )

    # 5. Inject Legend & Custom Style
    try:
        html_content = net.generate_html()
        
        custom_style = """
        <style>
            body { margin: 0; padding: 0; font-family: Arial, sans-serif; }
            #mynetwork { width: 100%; height: 100vh; border: none; }
            
            /* Legend Container */
            .legend-container {
                position: absolute;
                top: 20px;
                right: 20px;
                background: rgba(255, 255, 255, 0.95);
                padding: 15px;
                border: 1px solid #ccc;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                z-index: 1000;
                max-width: 250px;
            }
            
            .legend-title {
                margin: 0 0 10px 0;
                font-size: 14px;
                font-weight: bold;
                border-bottom: 1px solid #eee;
                padding-bottom: 5px;
            }
            
            .legend-section {
                margin-bottom: 15px;
            }
            
            .legend-item {
                display: flex;
                align-items: center;
                margin-bottom: 5px;
                font-size: 12px;
            }
            
            .color-box {
                width: 15px;
                height: 15px;
                margin-right: 10px;
                border-radius: 3px;
            }
            
            .geo-badge {
                display: inline-block;
                padding: 2px 6px;
                background: #eee;
                border-radius: 4px;
                font-size: 10px;
                margin-right: 5px;
                font-weight: bold;
                color: #555;
                border: 1px solid #ccc;
            }
        </style>
        """
        
        legend_html = "<div class='legend-container'>"
        
        # Framework Types Legend
        legend_html += "<div class='legend-section'>"
        legend_html += "<div class='legend-title'>Framework Categories</div>"
        for type_name, color_code in type_colors.items():
            legend_html += f"""
            <div class='legend-item'>
                <div class='color-box' style='background: {color_code};'></div>
                <span>{type_name}</span>
            </div>
            """
        legend_html += "</div>"
        
        # Geography Note
        legend_html += "<div class='legend-section'>"
        legend_html += "<div class='legend-title'>Geographies</div>"
        legend_html += "<div class='legend-item'><i>Specified in Node Tooltips</i></div>"
        legend_html += "<div class='legend-item'><span class='geo-badge'>USA</span> <span class='geo-badge'>EU</span> <span class='geo-badge'>INTL</span></div>"
        legend_html += "</div>"
        
        legend_html += "</div>"

        # Inject Style and Legend
        final_html = html_content.replace("<head>", f"<head>{custom_style}")
        final_html = final_html.replace("</body>", f"{legend_html}</body>")
        
        with open("frameworks_graph.html", "w", encoding="utf-8") as f:
            f.write(final_html)
        print("Interactive visual saved to frameworks_graph.html")
        
    except Exception as e:
        print(f"Error generating visual: {e}")

if __name__ == "__main__":
    generate_framework_graph()
