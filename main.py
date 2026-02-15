import argparse
import hashlib
from pathlib import Path

from src.ingestion import RawParser
from src.canon_registry import profile_settings
from src.pipeline.graph_pipeline import run_graph_pipeline

def main():
    parser = argparse.ArgumentParser(description="CIX Alerts Graph-Lead Prototype")
    parser.add_argument("input_file", nargs="?", default="soc_alert_batch.json", help="Path to the input JSON file (default: soc_alert_batch.json)")
    parser.add_argument("--output-dir", default="data", help="Directory to write run artifacts (default: data)")
    parser.add_argument("--skip-kernel", action="store_true", help="Skip kernel gating (legacy flow)")
    parser.add_argument("--kernel-ledger", default=None, help="Kernel ledger output path (default: <output-dir>/kernel_ledger.jsonl)")
    parser.add_argument("--phi-limit", type=int, default=None, help="Override ARV phi limit for all gates (legacy)")
    parser.add_argument("--phi-limit-arv1", type=int, default=None, help="Override ARV Gate 1 phi limit (triage admission)")
    parser.add_argument("--phi-limit-arv2", type=int, default=None, help="Override ARV Gate 2 phi limit (post-enrichment)")
    parser.add_argument("--phi-limit-arv3", type=int, default=None, help="Override ARV Gate 3 phi limit (reporting)")
    parser.add_argument("--arv-beta", type=float, default=None, help="Override ARV beta (entropy budget)")
    parser.add_argument("--arv-tau", type=float, default=None, help="Override ARV tau (correlation threshold)")
    parser.add_argument("--profile-id", default=None, help="Override AxoDen profile_id (defaults to axoden-cix-1-v0.2.0)")
    parser.add_argument("--triage-only", action="store_true", help="Stop after triage counts (no enrichment or reports)")
    parser.add_argument("--skip-enrichment", action="store_true", help="Skip enrichment/ARV2 (faster runs)")
    parser.add_argument("--verbose", action="store_true", help="Print ARV gate decisions")
    parser.add_argument(
        "--max-campaigns",
        type=int,
        default=0,
        help="Maximum number of campaign components to emit as artifacts (default: 0 = all).",
    )
    args = parser.parse_args()

    print("--- CIX Alerts Graph-Lead Prototype (Phase 3: World Graph) Starting ---")

    
    # 1. Ingestion (Batch)
    parser = RawParser()
    # Using 'soc_alert_batch.json' to test the new batch capability
    raw_alerts = parser.parse_file(args.input_file)
    print(f"[1] Batch Ingestion: Loaded {len(raw_alerts)} alerts from {args.input_file}.")
    lineage_source = args.input_file
    try:
        input_path = Path(args.input_file)
        if input_path.exists():
            lineage_source = input_path.read_bytes()
    except Exception:
        lineage_source = args.input_file
    if isinstance(lineage_source, bytes):
        lineage_id = hashlib.sha256(lineage_source).hexdigest()
    else:
        lineage_id = hashlib.sha256(str(lineage_source).encode("utf-8")).hexdigest()
    profile = profile_settings(args.profile_id)
    kernel_ledger_path = args.kernel_ledger or str(Path(args.output_dir) / "kernel_ledger.jsonl")
    artifacts = run_graph_pipeline(
        raw_alerts,
        output_dir=args.output_dir,
        enable_kernel=not args.skip_kernel,
        kernel_ledger_path=kernel_ledger_path,
        arv_phi_limit=args.phi_limit,
        arv_phi_limit_gate1=args.phi_limit_arv1,
        arv_phi_limit_gate23=args.phi_limit_arv2,
        arv_phi_limit_gate3=args.phi_limit_arv3,
        arv_beta=args.arv_beta,
        arv_tau=args.arv_tau,
        profile_id=profile.get("profile_id") or args.profile_id,
        registry_commit=profile.get("registry_commit"),
        lineage_id=lineage_id,
        triage_only=args.triage_only,
        skip_enrichment=args.skip_enrichment,
        verbose=args.verbose,
        max_campaigns=None if args.max_campaigns == 0 else args.max_campaigns,
    )

    if not artifacts["reports"]:
        print("  [!] Pipeline halted or produced no artifacts.")
        return

    for report in artifacts["reports"]:
        print(f"  [+] Report generated: {report}")

    print("--- Process Complete ---")

if __name__ == "__main__":
    main()
