import argparse

from src.ingestion import RawParser
from src.pipeline.graph_pipeline import run_graph_pipeline

def main():
    parser = argparse.ArgumentParser(description="CIX Alerts Graph-Lead Prototype")
    parser.add_argument("input_file", nargs="?", default="soc_alert_batch.json", help="Path to the input JSON file (default: soc_alert_batch.json)")
    parser.add_argument("--skip-kernel", action="store_true", help="Skip kernel gating (legacy flow)")
    parser.add_argument("--kernel-ledger", default="data/kernel_ledger.jsonl", help="Kernel ledger output path")
    parser.add_argument("--phi-limit", type=int, default=None, help="Override ARV phi limit for all gates (legacy)")
    parser.add_argument("--phi-limit-arv1", type=int, default=None, help="Override ARV Gate 1 phi limit (triage admission)")
    parser.add_argument("--phi-limit-arv2", type=int, default=None, help="Override ARV Gate 2/3 phi limit (post-enrichment)")
    parser.add_argument("--arv-beta", type=float, default=None, help="Override ARV beta (entropy budget)")
    parser.add_argument("--arv-tau", type=float, default=None, help="Override ARV tau (correlation threshold)")
    parser.add_argument("--triage-only", action="store_true", help="Stop after triage counts (no enrichment or reports)")
    parser.add_argument("--skip-enrichment", action="store_true", help="Skip enrichment/ARV2 (faster runs)")
    parser.add_argument("--verbose", action="store_true", help="Print ARV gate decisions")
    args = parser.parse_args()

    print("--- CIX Alerts Graph-Lead Prototype (Phase 3: World Graph) Starting ---")

    
    # 1. Ingestion (Batch)
    parser = RawParser()
    # Using 'soc_alert_batch.json' to test the new batch capability
    raw_alerts = parser.parse_file(args.input_file)
    print(f"[1] Batch Ingestion: Loaded {len(raw_alerts)} alerts from {args.input_file}.")
    artifacts = run_graph_pipeline(
        raw_alerts,
        output_dir="data",
        enable_kernel=not args.skip_kernel,
        kernel_ledger_path=args.kernel_ledger,
        arv_phi_limit=args.phi_limit,
        arv_phi_limit_gate1=args.phi_limit_arv1,
        arv_phi_limit_gate23=args.phi_limit_arv2,
        arv_beta=args.arv_beta,
        arv_tau=args.arv_tau,
        triage_only=args.triage_only,
        skip_enrichment=args.skip_enrichment,
        verbose=args.verbose,
    )

    if not artifacts["reports"]:
        print("  [!] Pipeline halted or produced no artifacts.")
        return

    for report in artifacts["reports"]:
        print(f"  [+] Report generated: {report}")

    print("--- Process Complete ---")

if __name__ == "__main__":
    main()
