"""Audit this local machine (Windows) against BaselineGuard CIS hardening rules.

Executes read-only inspection commands (Registry, PowerShell, SecEdit, Firewall, Services),
normalizes the facts, evaluates them deterministically, and outputs the live results.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
from baselineguard_adapters.orchestrate import normalize_outputs
from baselineguard_adapters.windows.reader import WINDOWS_READERS, WindowsReader
from baselineguard_rule_engine.evaluator import evaluate_expression
from baselineguard_rule_engine.logic import Truth


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        
    print("=" * 75)
    print("  [+] BASELINEGUARD -- LIVE LOCAL MACHINE AUDIT")
    print("=" * 75)
    print("\n[1/3] Collecting read-only security evidence from local Windows OS...")
    
    reader = WindowsReader(timeout_seconds=20)
    try:
        raw_outputs = reader.collect(None, None, tuple(WINDOWS_READERS.keys()))
    except Exception as e:
        print(f"[-] Error collecting from local machine: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"  ✓ Executed {len(raw_outputs)} read-only inspection sets (Registry, SecEdit, Firewall, Services).")

    print("\n[2/3] Normalizing facts & calculating SHA-256 evidence digests...")
    results = [(out.reader_id, out) for out in raw_outputs]
    facts = normalize_outputs(results)
    facts_dict = {f.fact_id: f for f in facts}
    print(f"  ✓ Extracted {len(facts)} tamper-evident normalized facts.")
    
    os_ver = facts_dict.get("platform.version")
    os_build = facts_dict.get("platform.build")
    role = facts_dict.get("platform.role")
    print(f"  → Host: Windows {os_ver.value if os_ver else 'Unknown'} (Build {os_build.value if os_build else 'Unknown'}, Role: {role.value if role else 'workstation'})")

    print("\n[3/3] Evaluating against CIS Windows Baseline Controls...")
    rule_pack_path = Path(__file__).resolve().parents[1] / "content" / "original" / "windows-server-2019.yaml"
    remediation_path = Path(__file__).resolve().parents[1] / "content" / "remediation" / "windows-server-2019.json"
    
    pack_data = yaml.safe_load(rule_pack_path.read_text(encoding="utf-8"))
    remed_data = json.loads(remediation_path.read_text(encoding="utf-8")) if remediation_path.exists() else {}
    templates = remed_data.get("templates", {})

    passed = []
    failed = []
    unresolved = []

    for ctrl in pack_data["controls"]:
        res = evaluate_expression(ctrl["assertion"], facts_dict)
        cid = ctrl["id"]
        title = ctrl["title"]
        expected_fact = ctrl.get("expected", {}).get("fact", "")
        expected_val = ctrl.get("expected", {}).get("value", "")
        op = ctrl.get("expected", {}).get("operator", "==")
        
        # Get actual value from normalized facts
        actual_obj = facts_dict.get(expected_fact)
        actual_val = actual_obj.value if actual_obj and actual_obj.state is not None and str(actual_obj.state).lower().endswith("present") else "UNAVAILABLE"

        tpl_id = ctrl.get("remediation_template", "")
        tpl = templates.get(tpl_id, {})
        remedy_summary = tpl.get("summary", "Review security setting in Local Security Policy or Registry.")

        if res is Truth.TRUE:
            passed.append((cid, title, expected_fact, actual_val))
        elif res is Truth.FALSE:
            failed.append((cid, title, expected_fact, op, expected_val, actual_val, remedy_summary))
        else:
            unresolved.append((cid, title, expected_fact))

    print("\n" + "=" * 75)
    print("  AUDIT SUMMARY")
    print("=" * 75)
    print(f"  Controls Evaluated:  {len(pack_data['controls'])}")
    print(f"  [PASS] Compliant:    {len(passed)}")
    print(f"  [FAIL] Deviating:    {len(failed)}")
    print(f"  [?]    Unresolved:   {len(unresolved)} (requires Admin elevation or Active Directory)")

    print("\n" + "-" * 75)
    print("  [PASS] COMPLIANT CONTROLS")
    print("-" * 75)
    for cid, title, fact_k, actual_val in passed:
        print(f"  * {cid}: {title}")
        print(f"    Fact: {fact_k} = {actual_val}\n")

    if failed:
        print("-" * 75)
        print("  [FAIL] DEVIATING CONTROLS (ACTION REQUIRED)")
        print("-" * 75)
        for cid, title, fact_k, op, expected_val, actual_val, remedy in failed:
            print(f"  * {cid}: {title}")
            print(f"    Fact:        {fact_k}")
            print(f"    Expected:    {op} {expected_val}")
            print(f"    Actual:      {actual_val}")
            print(f"    Remediation: {remedy}\n")

    print("=" * 75)
    print("  All evaluations are 100% deterministic with zero AI/ML inference.")
    print("=" * 75)

if __name__ == "__main__":
    main()
