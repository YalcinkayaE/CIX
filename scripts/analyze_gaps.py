from typing import Set, Dict, List
import re

# 1. Tags extracted from detection_triage/threat_assessment.py (Manual Extraction based on previous `cat` output)
# I am hardcoding the list I just derived to avoid complex AST parsing in this simple script step.
DETECTED_TAGS = {
    "credential_dumping", "credential_attack", "ingress_tool_transfer", "data_staging",
    "signed_binary_proxy", "persistence", "malicious_service", "remote_execution",
    "lateral_movement", "privilege_escalation", "group_modification", "account_modification",
    "sensitive_file_access", "archive_collection", "powershell_bypass", "execution",
    "bruteforce_external", "tor_egress", "exfiltration_channel", "persistence_registry",
    "dll_drop", "remote_services", "ssh", "rdp", "exfiltration", "discovery", "wmi"
}

# 2. Rules from grc/regulatory_map.py (mirrored in create_grc_worldgraph.py)
MAPPED_TAGS = {
    "bruteforce_external", "credential_dumping", "data_staging", "dll_drop",
    "exfiltration_channel", "group_modification", "ingress_tool_transfer",
    "lateral_movement", "malicious_service", "persistence", "persistence_registry",
    "powershell_bypass", "privilege_escalation", "remote_execution",
    "sensitive_file_access", "signed_binary_proxy", "tor_egress"
}

def analyze_coverage():
    print("--- GRC Coverage Gap Analysis ---\n")
    
    # 1. Unmapped Threats
    unmapped = sorted(list(DETECTED_TAGS - MAPPED_TAGS))
    print(f"Total Detected Threat Tags: {len(DETECTED_TAGS)}")
    print(f"Total Mapped Threat Tags:   {len(MAPPED_TAGS)}")
    print(f"\n[!] GAP: {len(unmapped)} Threat Tags have NO regulatory mapping:")
    for tag in unmapped:
        print(f"  - {tag}")

    # 2. Framework Frequency (from the rules we know)
    # Re-importing the rules structure from the local file to count frameworks
    try:
        from create_grc_worldgraph import _TAG_RULES, _DATA_CATEGORY_RULES
        
        framework_counts = {}
        for rules in [_TAG_RULES, _DATA_CATEGORY_RULES]:
            for tag, impacts in rules.items():
                for impact in impacts:
                    fw = impact.framework
                    framework_counts[fw] = framework_counts.get(fw, 0) + 1
        
        print("\n--- Framework Representation ---")
        for fw, count in sorted(framework_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {fw}: {count} rules")
            
        # 3. Specific Framework Gaps (Heuristic)
        print("\n--- Potential Framework Gaps (Heuristic) ---")
        
        # Check Bruteforce
        bf_rules = [i.framework for i in _TAG_RULES.get("bruteforce_external", [])]
        if "PCI DSS" not in bf_rules:
            print("[!] GAP: 'bruteforce_external' missing PCI DSS (Req 8.1.6)")
            
        # Check Credential Dumping
        cd_rules = [i.framework for i in _TAG_RULES.get("credential_dumping", [])]
        if "NIST CSF" not in cd_rules:
            print("[!] GAP: 'credential_dumping' missing NIST CSF (PR.AC)")

        # Check Lateral Movement
        lm_rules = [i.framework for i in _TAG_RULES.get("lateral_movement", [])]
        if "PCI DSS" not in lm_rules:
            print("[!] GAP: 'lateral_movement' missing PCI DSS (Segmentation checks)")
            
    except ImportError:
        print("\n[Error] Could not import rules from create_grc_worldgraph.py for deep analysis.")

if __name__ == "__main__":
    analyze_coverage()
