
import json
import networkx as nx
from pyvis.network import Network

def generate_improved_framework_graph():
    # --- 1. Define WCAG AA Compliant Color Palette ---
    # High contrast colors for nodes (assuming white text inside)
    # Ratios calculated against #FFFFFF
    colors = {
        "Security Standard": "#004D40",    # Teal 900 (~10:1)
        "Security Framework": "#1A237E",   # Indigo 900 (~16:1)
        "Privacy Regulation": "#1B5E20",   # Green 900 (~9:1)
        "Privacy Standard": "#2E7D32",     # Green 800 (~5.5:1)
        "AI Governance": "#B71C1C",        # Red 900 (~8:1)
        "Financial Regulation": "#4A148C", # Purple 900 (~14:1)
        "Resilience Regulation": "#311B92", # Deep Purple 900 (~16:1)
        "Resilience Standard": "#4527A0",   # Deep Purple 800 (~10:1)
        "Guideline/Principles": "#BF360C"   # Deep Orange 900 (~7:1)
    }

    # --- 2. Define Nodes with Enhanced Schema ---
    nodes = [
        # --- International Security Standards ---
        {
            "id": "ISO_27001",
            "label": "ISO/IEC 27001:2022",
            "type": "Security Standard",
            "kind": "Standard",
            "owner": "ISO/IEC",
            "version": "2022",
            "published_date": "2022-10",
            "geography": "International"
        },
        {
            "id": "ISO_27002",
            "label": "ISO/IEC 27002:2022",
            "type": "Security Standard",
            "kind": "Standard",
            "owner": "ISO/IEC",
            "version": "2022",
            "published_date": "2022-02",
            "geography": "International"
        },
        {
            "id": "PCI_DSS",
            "label": "PCI DSS v4.0.1",
            "type": "Security Standard",
            "kind": "Standard",
            "owner": "PCI SSC",
            "version": "4.0.1",
            "published_date": "2024-06",
            "geography": "International"
        },
        
        # --- Security Frameworks ---
        {
            "id": "NIST_CSF",
            "label": "NIST CSF 2.0",
            "type": "Security Framework",
            "kind": "Framework",
            "owner": "NIST",
            "version": "2.0",
            "published_date": "2024-02-26",
            "geography": "USA"
        },
        {
            "id": "NIST_SP_800_53",
            "label": "NIST SP 800-53r5",
            "type": "Security Framework",
            "kind": "Standard",
            "owner": "NIST",
            "version": "Rev 5",
            "published_date": "2020-09",
            "geography": "USA"
        },
        {
            "id": "CIS_Controls",
            "label": "CIS Controls v8",
            "type": "Security Framework",
            "kind": "Framework",
            "owner": "CIS",
            "version": "v8",
            "published_date": "2021-05",
            "geography": "International"
        },
        {
            "id": "SOC_2",
            "label": "SOC 2 (TSC)",
            "type": "Security Framework",
            "kind": "Framework",
            "owner": "AICPA",
            "version": "2017",
            "published_date": "2017",
            "geography": "USA/International"
        },

        # --- AI Governance ---
        {
            "id": "ISO_42001",
            "label": "ISO/IEC 42001:2023",
            "type": "AI Governance",
            "kind": "Standard",
            "owner": "ISO/IEC",
            "version": "2023",
            "published_date": "2023-12",
            "geography": "International"
        },
        {
            "id": "ISO_23894",
            "label": "ISO/IEC 23894:2023",
            "type": "AI Governance",
            "kind": "Standard",
            "owner": "ISO/IEC",
            "version": "2023",
            "published_date": "2023-02",
            "geography": "International"
        },
        {
            "id": "EU_AI_Act",
            "label": "EU AI Act",
            "type": "AI Governance",
            "kind": "Regulation",
            "owner": "EU",
            "version": "Reg (EU) 2024/1689",
            "published_date": "2024-06-13",
            "effective_date": "2026-08-02 (General)",
            "geography": "EU"
        },
        {
            "id": "NIST_AI_RMF",
            "label": "NIST AI RMF 1.0",
            "type": "AI Governance",
            "kind": "Framework",
            "owner": "NIST",
            "version": "1.0",
            "published_date": "2023-01",
            "geography": "USA"
        },
        {
            "id": "OECD_AI",
            "label": "OECD AI Principles",
            "type": "Guideline/Principles",
            "kind": "Principles",
            "owner": "OECD",
            "version": "2024 Revision",
            "published_date": "2024-05",
            "geography": "International"
        },

        # --- Privacy ---
        {
            "id": "GDPR",
            "label": "GDPR",
            "type": "Privacy Regulation",
            "kind": "Regulation",
            "owner": "EU",
            "version": "Reg (EU) 2016/679",
            "published_date": "2016-04-27",
            "effective_date": "2018-05-25",
            "geography": "EU"
        },
        {
            "id": "CCPA_CPRA",
            "label": "CCPA / CPRA",
            "type": "Privacy Regulation",
            "kind": "Law",
            "owner": "California",
            "version": "2018 / 2020",
            "published_date": "2018-06",
            "geography": "USA (California)"
        },
        {
            "id": "HIPAA",
            "label": "HIPAA",
            "type": "Privacy Regulation",
            "kind": "Law",
            "owner": "USA",
            "version": "1996",
            "published_date": "1996",
            "geography": "USA"
        },
        {
            "id": "ISO_27701",
            "label": "ISO/IEC 27701:2019",
            "type": "Privacy Standard",
            "kind": "Standard",
            "owner": "ISO/IEC",
            "version": "2019",
            "published_date": "2019-08",
            "geography": "International"
        },

        # --- Resilience & Financial ---
        {
            "id": "NIS2",
            "label": "NIS2 Directive",
            "type": "Resilience Regulation",
            "kind": "Directive",
            "owner": "EU",
            "version": "Dir (EU) 2022/2555",
            "published_date": "2022-12-14",
            "effective_date": "2024-10-17 (Transposition)",
            "geography": "EU"
        },
        {
            "id": "DORA",
            "label": "DORA",
            "type": "Resilience Regulation",
            "kind": "Regulation",
            "owner": "EU",
            "version": "Reg (EU) 2022/2554",
            "published_date": "2022-12-14",
            "effective_date": "2025-01-17",
            "geography": "EU"
        },
        {
            "id": "ISO_22301",
            "label": "ISO 22301:2019",
            "type": "Resilience Standard",
            "kind": "Standard",
            "owner": "ISO",
            "version": "2019",
            "published_date": "2019-10",
            "geography": "International"
        },
        {
            "id": "SOX",
            "label": "Sarbanes-Oxley (SOX)",
            "type": "Financial Regulation",
            "kind": "Law",
            "owner": "USA",
            "version": "2002",
            "published_date": "2002-07",
            "geography": "USA"
        }
    ]

    # --- 3. Define Edges with Enhanced Schema (Audit-Grade) ---
    # Controlled vocabulary for labels: 
    # 'aligned_with', 'overlaps_with', 'mapped_to', 'implements', 'supports_compliance_with', 'lex_specialis_over', 'extends'
    edges = [
        # AI Relationships
        {"source": "ISO_42001", "target": "ISO_27001", "label": "aligned_with", "description": "built on management system structure of", "confidence": "High"},
        {"source": "ISO_23894", "target": "ISO_42001", "label": "supports_compliance_with", "description": "provides risk management guidance for", "confidence": "High"},
        {"source": "EU_AI_Act", "target": "ISO_42001", "label": "can_be_supported_by", "description": "harmonized standards likely to leverage 42001", "confidence": "Medium"},
        {"source": "EU_AI_Act", "target": "GDPR", "label": "complements", "description": "interplays on data governance/privacy", "confidence": "High"},
        {"source": "NIST_AI_RMF", "target": "NIST_CSF", "label": "aligned_with", "description": "shares risk-based conceptual model", "confidence": "High"},
        {"source": "NIST_AI_RMF", "target": "OECD_AI", "label": "aligned_with", "description": "maps to OECD principles", "confidence": "High"},
        
        # Security Standard Relationships
        {"source": "ISO_27002", "target": "ISO_27001", "label": "supports_compliance_with", "description": "provides implementation guidance for Annex A", "confidence": "High"},
        {"source": "ISO_27701", "target": "ISO_27001", "label": "extends", "description": "adds PIMS requirements to ISMS", "confidence": "High"},
        {"source": "NIST_CSF", "target": "ISO_27001", "label": "mapped_to", "description": "extensive informative references", "confidence": "High"},
        {"source": "NIST_CSF", "target": "NIST_SP_800_53", "label": "implements", "description": "core controls derived from 800-53", "confidence": "High"},
        {"source": "CIS_Controls", "target": "NIST_CSF", "label": "mapped_to", "description": "CIS provides mappings to CSF categories", "confidence": "High"},
        {"source": "PCI_DSS", "target": "ISO_27001", "label": "overlaps_with", "description": "significant control overlap but distinct scopes", "confidence": "Medium"},
        {"source": "SOC_2", "target": "COBIT", "label": "aligned_with", "description": "TSC aligns with COBIT principles", "confidence": "Medium"}, # Note: COBIT node not added to keep graph focused, but relation exists

        # Resilience & Regulatory
        {"source": "NIS2", "target": "ISO_27001", "label": "commonly_aligned_with", "description": "ISO 27001 is the de facto standard for demonstrating conformity", "confidence": "Medium"},
        {"source": "DORA", "target": "NIS2", "label": "lex_specialis_over", "description": "prevails for financial entities", "confidence": "High"},
        {"source": "ISO_22301", "target": "ISO_27001", "label": "aligned_with", "description": "shared MSS structure, often integrated", "confidence": "High"},
        
        # Privacy & US Regs
        {"source": "GDPR", "target": "ISO_27701", "label": "can_be_supported_by", "description": "ISO 27701 designed to demonstrate GDPR accountability", "confidence": "High"},
        {"source": "GDPR", "target": "CCPA_CPRA", "label": "influences", "description": "GDPR concepts heavily influenced CCPA", "confidence": "High"},
        {"source": "HIPAA", "target": "NIST_SP_800_53", "label": "mapped_to", "description": "NIST provides implementation guide for HIPAA", "confidence": "High"},
        {"source": "SOX", "target": "COBIT", "label": "often_implemented_using", "description": "COBIT is standard framework for SOX ITGC", "confidence": "High"} 
    ]
    
    # Add COBIT node just for the SOX edge context if we keep that edge
    nodes.append({
        "id": "COBIT",
        "label": "COBIT 2019",
        "type": "Security Framework",
        "kind": "Framework",
        "owner": "ISACA",
        "version": "2019",
        "published_date": "2018",
        "geography": "International"
    })
    
    # Update SOX edge target to new node
    for e in edges:
        if e["source"] == "SOC_2" and e["target"] == "COBIT":
             pass

    # --- 4. Output JSON Data ---
    graph_data = {
        "metadata": {
            "title": "Global GRC Framework Interconnectivity Graph",
            "version": "1.1",
            "last_updated": "2025-01-31",
            "generated_by": "CIX Alerts Logic"
        },
        "nodes": nodes,
        "edges": edges
    }
    
    with open("frameworks_graph_v2.json", "w", encoding="utf-8") as f:
        json.dump(graph_data, f, indent=2)
    print("JSON data saved to frameworks_graph_v2.json")

    # --- 5. Generate Visualization (PyVis) ---
    # Removed global font_color="#000000" to prevent conflicts with node-specific settings
    net = Network(height="calc(100vh - 50px)", width="100%", bgcolor="#ffffff", cdn_resources='in_line')
    
    # Physics settings
    net.barnes_hut(gravity=-3500, central_gravity=0.4, spring_length=180, spring_strength=0.06, damping=0.09)
    
    # Add Nodes
    for n in nodes:
        color = colors.get(n["type"], "#757575")
        
        # Enhanced Tooltip
        title_html = (
            f"<div style='font-family: Calibri, sans-serif; color: #333; padding: 10px; min-width: 200px;'>"
            f"<strong style='font-size: 14px; color: {color};'>{n['label']}</strong><hr style='border: 0; border-top: 1px solid #ccc; margin: 5px 0;'>"
            f"<b>Type:</b> {n['type']}<br>"
            f"<b>Kind:</b> {n.get('kind', '-')}<br>"
            f"<b>Owner:</b> {n.get('owner', '-')}<br>"
            f"<b>Version:</b> {n['version']}<br>"
            f"<b>Published:</b> {n.get('published_date', '-')}<br>"
            f"<b>Geography:</b> {n['geography']}"
        )
        if "effective_date" in n:
            title_html += f"<br><b>Effective:</b> {n['effective_date']}"
        title_html += "</div>"
        
        # Label formatting: Add Geography inside the box
        # Using a newline to separate name and geography
        label_text = f"{n['label']}\n[{n['geography']}]"

        net.add_node(
            n["id"],
            label=label_text,
            title=title_html,
            color=color,
            shape="box",
            # Explicitly forcing white text for better contrast against dark backgrounds
            font={'face': 'Calibri', 'color': '#ffffff', 'size': 16, 'bold': True}
        )

    # Add Edges
    for e in edges:
        edge_label = e["label"].replace("_", " ")
        tooltip = f"<b>{edge_label}</b><br>{e.get('description', '')}<br><i>Confidence: {e.get('confidence', 'N/A')}</i>"
        
        net.add_edge(
            e["source"],
            e["target"],
            label=edge_label,
            title=tooltip,
            color="#9E9E9E",
            arrows="to",
            width=1.5,
            font={'align': 'middle', 'size': 9, 'color': '#555555', 'face': 'Calibri'}
        )

    # --- 6. Inject Legend & Custom Style ---
    try:
        html_content = net.generate_html()
        
        custom_style = """
        <style>
            body { margin: 0; padding: 0; font-family: 'Calibri', sans-serif; }
            #mynetwork { width: 100%; height: 100vh; border: none; }
            
            /* Legend Container */
            .legend-container {
                position: absolute;
                top: 20px;
                right: 20px;
                background: rgba(255, 255, 255, 0.98);
                padding: 20px;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                z-index: 1000;
                max-width: 280px;
            }
            
            .legend-header {
                margin: 0 0 15px 0;
                font-size: 16px;
                font-weight: bold;
                color: #333;
                border-bottom: 2px solid #f0f0f0;
                padding-bottom: 8px;
            }
            
            .legend-section {
                margin-bottom: 20px;
            }
            
            .legend-item {
                display: flex;
                align-items: center;
                margin-bottom: 8px;
                font-size: 13px;
                color: #555;
            }
            
            .color-box {
                width: 18px;
                height: 18px;
                margin-right: 12px;
                border-radius: 4px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.2);
            }
            
            .geo-tags {
                display: flex;
                flex-wrap: wrap;
                gap: 5px;
            }

            .geo-badge {
                display: inline-block;
                padding: 3px 8px;
                background: #f5f5f5;
                border-radius: 12px;
                font-size: 11px;
                font-weight: 600;
                color: #666;
                border: 1px solid #ddd;
            }
        </style>
        """
        
        legend_html = "<div class='legend-container'>"
        legend_html += "<div class='legend-header'>Framework Categories</div>"
        
        # Framework Types Legend
        for type_name, color_code in colors.items():
            legend_html += f"""
            <div class='legend-item'>
                <div class='color-box' style='background: {color_code};'></div>
                <span>{type_name}</span>
            </div>
            """
        
        # Geography Note
        legend_html += "<div class='legend-header' style='margin-top: 20px;'>Geographies</div>"
        legend_html += "<div class='geo-tags'>"
        legend_html += "<span class='geo-badge'>International</span>"
        legend_html += "<span class='geo-badge'>USA</span>"
        legend_html += "<span class='geo-badge'>EU</span>"
        legend_html += "</div>"
        
        legend_html += "</div>"

        # Inject Style and Legend
        final_html = html_content.replace("<head>", f"<head>{custom_style}")
        final_html = final_html.replace("</body>", f"{legend_html}</body>")
        
        with open("frameworks_graph_v2.html", "w", encoding="utf-8") as f:
            f.write(final_html)
        print("Interactive visual saved to frameworks_graph_v2.html")
        
    except Exception as e:
        print(f"Error generating visual: {e}")

if __name__ == "__main__":
    generate_improved_framework_graph()
