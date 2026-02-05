import json
from datetime import datetime

class ForensicLedger:
    """
    Mock append-only file that logs every graph edge created during the investigation.
    """
    def __init__(self, file_path: str = "data/forensic_ledger.json"):
        self.file_path = file_path

    def export(self, triples: list, summary: str, arv_history: list = None):
        """
        Saves the final graph as a forensic ledger, including AxoDen validation history.
        """
        ledger_entry = {
            "timestamp": datetime.now().isoformat(),
            "summary": summary,
            "validation_audit": arv_history or [],
            "ledger_entries": triples
        }
        
        with open(self.file_path, 'w') as f:
            json.dump(ledger_entry, f, indent=2)
        
        print(f"Forensic Ledger exported to {self.file_path}")
