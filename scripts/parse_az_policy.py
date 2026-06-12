#!/usr/bin/env python3
"""
Parse Azure Policy JSON export → MCSB control coverage map.

Inputs:  data/inputs/az_policy.json
Outputs: data/outputs/az_policy_coverage.csv

Azure Policy JSON (exported from portal or az cli) structure varies.
Script handles two common formats:
  Format A: policyAssignments[] (from az policy assignment list)
  Format B: value[] (from REST API response)
"""

import json
import sys
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).parent.parent
INPUT_FILE = ROOT / "data" / "inputs" / "az_policy.json"
OUTPUT_FILE = ROOT / "data" / "outputs" / "az_policy_coverage.csv"

# Keywords that suggest a policy maps to an MCSB control
# Format: "keyword_in_policy_name" -> "likely_domain_code"
POLICY_DOMAIN_HINTS: dict[str, str] = {
    "network": "NS",
    "firewall": "NS",
    "private endpoint": "NS",
    "tls": "NS",
    "https": "NS",
    "nsg": "NS",
    "identity": "IM",
    "managed identity": "IM",
    "authentication": "IM",
    "mfa": "IM",
    "privileged": "PA",
    "pim": "PA",
    "encryption": "DP",
    "key vault": "DP",
    "cmk": "DP",
    "customer-managed": "DP",
    "tde": "DP",
    "audit log": "LT",
    "diagnostic": "LT",
    "log analytics": "LT",
    "monitoring": "LT",
    "vulnerability": "PV",
    "defender": "PV",
    "secure score": "PV",
    "patch": "PV",
    "antimalware": "ES",
    "endpoint protection": "ES",
    "backup": "BR",
    "inventory": "AM",
    "tagging": "AM",
    "tag": "AM",
    "governance": "GS",
    "compliance": "GS",
    "incident": "IR",
}

# Enforcement mode normalization
ENFORCEMENT_MAP = {
    "default": "Enforced",
    "doenforce": "Enforced",
    "enforce": "Enforced",
    "donotenforce": "Audit",
    "audit": "Audit",
    "disabled": "Not Configured",
    "": "Unknown",
}


def normalize_enforcement(mode: str) -> str:
    return ENFORCEMENT_MAP.get(str(mode).lower().strip(), "Unknown")


def map_policy_to_domain(display_name: str, policy_def_id: str) -> str:
    """Guess MCSB domain from policy name or definition ID."""
    search_text = f"{display_name} {policy_def_id}".lower()

    # Check for explicit MCSB reference in policy ID (e.g., /azure-security-benchmark/)
    if "security-benchmark" in search_text or "mcsb" in search_text:
        for keyword, domain in POLICY_DOMAIN_HINTS.items():
            if keyword in search_text:
                return domain

    # Keyword match on display name
    for keyword, domain in POLICY_DOMAIN_HINTS.items():
        if keyword in search_text:
            return domain

    return "UNKNOWN"


def extract_assignments_format_a(data: list) -> list[dict]:
    """Format A: list of assignment objects (az policy assignment list output)."""
    rows = []
    for item in data:
        if not isinstance(item, dict):
            continue
        props = item.get("properties", item)
        rows.append({
            "policy_assignment_id": item.get("id", item.get("name", "")),
            "policy_name": item.get("name", ""),
            "policy_display_name": props.get("displayName", item.get("displayName", "")),
            "policy_definition_id": props.get("policyDefinitionId", ""),
            "enforcement_mode": props.get("enforcementMode", ""),
            "compliance_state": props.get("complianceState", "Unknown"),
            "scope": props.get("scope", item.get("scope", "")),
        })
    return rows


def extract_assignments_format_b(data: dict) -> list[dict]:
    """Format B: REST API response with value[]."""
    rows = []
    for item in data.get("value", []):
        props = item.get("properties", {})
        rows.append({
            "policy_assignment_id": item.get("id", ""),
            "policy_name": item.get("name", ""),
            "policy_display_name": props.get("displayName", ""),
            "policy_definition_id": props.get("policyDefinitionId", ""),
            "enforcement_mode": props.get("enforcementMode", ""),
            "compliance_state": props.get("complianceState", "Unknown"),
            "scope": props.get("scope", ""),
        })
    return rows


def main():
    if not INPUT_FILE.exists():
        print(f"ERROR: Input file not found: {INPUT_FILE}", file=sys.stderr)
        print(f"Export from Azure portal or run:", file=sys.stderr)
        print(f"  az policy assignment list --output json > {INPUT_FILE}", file=sys.stderr)
        sys.exit(1)

    (ROOT / "data" / "outputs").mkdir(parents=True, exist_ok=True)

    with open(INPUT_FILE) as f:
        data = json.load(f)

    # Detect format
    if isinstance(data, list):
        print("Detected format: list (az cli output)")
        raw_rows = extract_assignments_format_a(data)
    elif isinstance(data, dict) and "value" in data:
        print("Detected format: REST API response")
        raw_rows = extract_assignments_format_b(data)
    else:
        print("ERROR: Unrecognized JSON format", file=sys.stderr)
        print("Expected: list[] or {value: []}", file=sys.stderr)
        sys.exit(1)

    print(f"Extracted {len(raw_rows)} policy assignments")

    output_rows = []
    for row in raw_rows:
        domain = map_policy_to_domain(
            row["policy_display_name"],
            row["policy_definition_id"],
        )
        enforcement = normalize_enforcement(row["enforcement_mode"])
        coverage = "Enforced" if enforcement == "Enforced" else \
                   "Audit" if enforcement == "Audit" else "Not Configured"

        output_rows.append({
            **row,
            "guessed_domain": domain,
            "enforcement_normalized": enforcement,
            "az_policy_covered": coverage,
        })

    df_out = pd.DataFrame(output_rows)
    df_out.to_csv(OUTPUT_FILE, index=False)

    print(f"\nWrote {len(df_out)} records to {OUTPUT_FILE}")
    print(f"\nEnforcement distribution:\n{df_out['enforcement_normalized'].value_counts().to_string()}")
    print(f"\nDomain guesses (top 15):\n{df_out['guessed_domain'].value_counts().head(15).to_string()}")

    unknown_count = len(df_out[df_out["guessed_domain"] == "UNKNOWN"])
    if unknown_count > 0:
        print(f"\nWARNING: {unknown_count} policies could not be mapped to a domain.")
        print("These will be joined by scope in build_gap_matrix.py (best-effort).")


if __name__ == "__main__":
    main()
