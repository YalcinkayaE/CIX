import json
import argparse
import networkx as nx
from src.ingestion import RawParser
from src.models import GraphReadyAlert
from src.graph import GraphConstructor
from src.enrichment import EnrichmentAgent
from src.chaser import BraveChaser
from src.refiner import IntelligenceRefiner
from src.synthesis import GraphNarrator
from src.audit import ForensicLedger
from src.visualize import GraphVisualizer
from src.canon_registry import arv_evaluate, arv_phi, ARV_PHI_LIMIT
from src.kernel.kernel_gate import KernelGate
from src.ingest.dedup import compute_event_hash

def main():
    parser = argparse.ArgumentParser(description="CIX Alerts Graph-Lead Prototype")
    parser.add_argument("input_file", nargs="?", default="soc_alert_batch.json", help="Path to the input JSON file (default: soc_alert_batch.json)")
    parser.add_argument("--skip-kernel", action="store_true", help="Skip kernel gating (legacy flow)")
    parser.add_argument("--kernel-ledger", default="data/kernel_ledger.jsonl", help="Kernel ledger output path")
    args = parser.parse_args()

    print("--- CIX Alerts Graph-Lead Prototype (Phase 3: World Graph) Starting ---")
    
    # [ARV] Initialize Resilience State
    # Note: ARV state is global for the pipeline execution.
    arv_history = []
    arv_state = {
        "phi_prev": 12,          # Initial seed (Adjusted for 3-alert baseline)
        "d_plus": 0.0,
        "root_a": "init_A",     
        "root_b": "init_B"
    }     

    
    # 1. Ingestion (Batch)
    parser = RawParser()
    # Using 'soc_alert_batch.json' to test the new batch capability
    raw_alerts = parser.parse_file(args.input_file)
    print(f"[1] Batch Ingestion: Loaded {len(raw_alerts)} alerts from {args.input_file}.")

    # 2. Kernel Gate + Dedup (before graph build)
    admitted_alerts = raw_alerts
    if not args.skip_kernel:
        gate = KernelGate(ledger_path=args.kernel_ledger)
        gated_results = []
        halt_triggered = False
        for raw_alert in raw_alerts:
            result = gate.evaluate(raw_alert)
            if result.action_id == "ARV.HALT":
                gate.append_ledger(result)
                print(f"  [Kernel] HALT: {result.reason_codes}")
                halt_triggered = True
                break
            if result.action_id in {"ARV.ADMIT", "ARV.COMPRESS"}:
                gated_results.append(result)
            else:
                # Non-admitted events are not sent to graph
                gate.append_ledger(result)
        if halt_triggered:
            return
        deduped_results = []
        seen_hashes = set()
        duplicates_removed = 0
        for result in gated_results:
            event_hash = compute_event_hash(result.graph_raw)
            if event_hash in seen_hashes:
                duplicates_removed += 1
                continue
            seen_hashes.add(event_hash)
            deduped_results.append(result)
        if duplicates_removed:
            print(f"  [Kernel] Dedup removed {duplicates_removed} events before graph build.")
        admitted_alerts = [r.graph_raw for r in deduped_results]
        # Append ledger entries only for deduplicated, admitted events
        for result in deduped_results:
            gate.append_ledger(result)

    # 3. World Graph Construction
    world_graph = nx.DiGraph()
    constructor = GraphConstructor()
    
    for raw_alert in admitted_alerts:
        alert_model = GraphReadyAlert.from_raw_data(raw_alert)
        constructor.add_to_graph(world_graph, alert_model)
        print(f"  [+] Merged Alert: {alert_model.event_id}")
        
    print(f"[3] World Graph Built: {len(world_graph.nodes)} nodes, {len(world_graph.edges)} edges.")

    # [ARV] Gate 1: Post-Construction (Global Check)
    phi_curr = arv_phi(world_graph.nodes)
    decision = arv_evaluate(phi_curr, arv_state["phi_prev"], arv_state["d_plus"], 
                           arv_state["root_a"], arv_state["root_b"])
    print(f"  [ARV] Gate 1 (World Graph): {decision.action} ({decision.reason})")
    if decision.action != "EXECUTE":
        print("  [!] System HALT imposed by ARV.")
        return
    arv_state["phi_prev"] = phi_curr
    arv_state["d_plus"] = decision.metrics["d_plus"]

    # 3. EFI Deduplication & Internal Enrichment
    # EnrichmentAgent runs on the graph. Since NetworkX nodes are unique, 
    # redundant alerts sharing "Malware:X" only create one node. 
    # The agent visits each node exactly once. This IS EFI.
    print("[3] Running EFI-Deduplicated Internal Enrichment...")
    agent = EnrichmentAgent()
    agent.chase_leads(world_graph)
    print(f"  [+] Enrichment Complete: {len(world_graph.nodes)} nodes.")

    # [ARV] Gate 2: Post-Internal Enrichment
    phi_curr = arv_phi(world_graph.nodes)
    decision = arv_evaluate(phi_curr, arv_state["phi_prev"], arv_state["d_plus"], 
                           "agent_v1_out_A", "agent_v1_out_B")
    print(f"  [ARV] Gate 2: {decision.action} ({decision.reason})")
    if decision.action != "EXECUTE":
        print("  [!] System HALT imposed by ARV.")
        return
    arv_state["phi_prev"] = phi_curr
    arv_state["d_plus"] = decision.metrics["d_plus"]

    # 4. Automated Lead Chasing (External Search)
    print("[4] Executing Automated Lead Chasing (Unique Leads Only)...")
    chaser = BraveChaser()
    refiner = IntelligenceRefiner()
    
    leads_to_chase = [n for n, d in world_graph.nodes(data=True) if d.get("type") == "SearchLead"]
    # Because we operate on the World Graph, identical leads from different alerts are already merged.
    
    for lead_node in leads_to_chase:
        query = world_graph.nodes[lead_node].get("query")
        print(f"  --> Chasing: {query}")
        snippets = chaser.chase_lead(query)
        if snippets:
            intel = refiner.refine_artifacts(query, snippets)
            for artifact in intel.get("artifacts", []):
                val = artifact.get("value")
                a_type = artifact.get("type")
                artifact_node = f"Artifact:{val}"
                if artifact_node not in world_graph:
                    world_graph.add_node(artifact_node, type=a_type, value=val, 
                                         source=artifact.get("source_url"), confidence=artifact.get("confidence"))
                    world_graph.add_edge(lead_node, artifact_node, relationship="DISCOVERED_ARTIFACT")
                    print(f"    [+] Discovered: {a_type} - {val}")

    # [ARV] Gate 3: Post-Chasing
    phi_curr = arv_phi(world_graph.nodes)
    decision = arv_evaluate(phi_curr, arv_state["phi_prev"], arv_state["d_plus"], 
                           "chaser_out_A", "chaser_out_B")
    print(f"  [ARV] Gate 3: {decision.action} ({decision.reason})")
    if decision.action != "EXECUTE" and decision.action != "THROTTLE":
         print("  [!] System HALT imposed by ARV.")
         return
    arv_state["phi_prev"] = phi_curr
    arv_state["d_plus"] = decision.metrics.get("d_plus", arv_state["d_plus"])

    # 5. Campaign Identification (Connected Components)
    print("[5] Identifying Campaigns (Connected Components)...")
    # Convert to undirected to find weak components
    undirected = world_graph.to_undirected()
    components = list(nx.connected_components(undirected))
    print(f"  [+] Found {len(components)} Distinct Campaigns.")

    # 6. Reporting per Campaign
    narrator = GraphNarrator()
    ledger = ForensicLedger() # We'll just overwrite for now or use unique names
    visualizer = GraphVisualizer()

    for idx, comp_nodes in enumerate(components):
        print(f"\n--- Processing Campaign {idx+1} ---")
        # Extract subgraph for this campaign
        subgraph = world_graph.subgraph(comp_nodes).copy()
        
        # Synthesize
        summary = narrator.summarize(subgraph)
        print(summary)
        
        # Generate Human-Readable Assessment Report
        assessment_report = narrator.generate_assessment_report(subgraph)
        report_path = f"data/Forensic_Assessment_Campaign_{idx+1}.md"
        with open(report_path, "w") as f:
            f.write(assessment_report)
        print(f"  [+] Human-Readable Report generated: {report_path}")
        
        # Export Ledger (mocking separate files for prototype)
        # Note: In a real app we'd likely append to a master ledger or use unique IDs
        triples = []
        for u, v, data in subgraph.edges(data=True):
             triples.append({"source": u, "relationship": data.get("relationship"), "target": v})
        
        # Record specific audit trail for this campaign execution
        # (For prototype, reusing the global ARV history is acceptable as context)
        # Construct a localized history entry
        comp_arv = [{"gate": "Campaign_Isolation", "phi": len(comp_nodes)}]
        
        ledger_name = f"data/forensic_ledger_campaign_{idx+1}.json"
        ledger.file_path = ledger_name
        ledger.export(triples, summary, comp_arv)
        
        # Visualize
        viz_name = f"data/investigation_graph_campaign_{idx+1}.png"
        interactive_name = f"data/investigation_graph_campaign_{idx+1}.html"
        
        visualizer.generate_image(subgraph, output_path=viz_name)
        visualizer.generate_interactive_html(subgraph, output_path=interactive_name)
    
    print("--- Process Complete ---")

if __name__ == "__main__":
    main()
