#!/usr/bin/env python3
"""
Parse Azure Defender for Cloud JSON export → MCSB control coverage map.

Inputs:  data/inputs/az_defender.json
Outputs: data/outputs/az_defender_coverage.csv

Defender JSON formats supported:
  Format A: securityAssessments[] (from REST API / az security assessment list)
  Format B: recommendations[] (from Defender for Cloud export)
  Format C: value[] wrapper (REST API)
"""

import json
import sys
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).parent.parent
INPUT_FILE = ROOT / "data" / "inputs" / "az_defender.json"
OUTPUT_FILE = ROOT / "data" / "outputs" / "az_defender_coverage.csv"

# Defender recommendation category → MCSB domain
CATEGORY_DOMAIN_MAP: dict[str, str] = {
    "networking": "NS",
    "network": "NS",
    "identity": "IM",
    "identityandaccess": "IM",
    "identity and access": "IM",
    "privilegedaccess": "PA",
    "data": "DP",
    "datasecurity": "DP",
    "encryption": "DP",
    "compute": "PV",
    "computeandapps": "PV",
    "computeandapplications": "PV",
    "container": "PV",
    "appservices": "PV",
    "applicationandapi": "PV",
    "monitoring": "LT",
    "loggingandmonitoring": "LT",
    "logging": "LT",
    "endpoint": "ES",
    "antimalware": "ES",
    "backup": "BR",
    "devops": "DS",
    "governance": "GS",
    "iotsecurity": "ES",
}

STATUS_NORMALIZATION = {
    "healthy": "Covered",
    "notapplicable": "Not Applicable",
    "not applicable": "Not Applicable",
    "low": "Not Covered",
    "medium": "Not Covered",
    "high": "Not Covered",
    "unhealthy": "Not Covered",
}


def map_category_to_domain(category: str) -> str:
    key = category.lower().replace(" ", "").replace("-", "")
    return CATEGORY_DOMAIN_MAP.get(key, CATEGORY_DOMAIN_MAP.get(category.lower(), "UNKNOWN"))


def normalize_status(status_code: str, status_cause: str = "") -> str:
    key = str(status_code).lower().strip()
    return STATUS_NORMALIZATION.get(key, "Unknown")


def extract_recommendations(items: list) -> list[dict]:
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue

        props = item.get("properties", item)
        metadata = props.get("metadata", {})
        status = props.get("status", {})

        # Try multiple field paths for display name
        display_name = (
            props.get("displayName")
            or metadata.get("displayName")
            or item.get("displayName")
            or item.get("name", "")
        )

        # Category / control mapping
        category = (
            metadata.get("category", [])
            or metadata.get("categories", [])
        )
        if isinstance(category, list):
            category_str = category[0] if category else ""
        else:
            category_str = str(category)

        # MCSB control reference (some recommendations have direct mapping)
        mcsb_ref = (
            metadata.get("azureSecurityBenchmark", {}).get("v2", "")
            or metadata.get("benchmarks", {}).get("azureSecurityBenchmark", {}).get("v2", "")
            or ""
        )

        severity = metadata.get("severity", props.get("severity", "Unknown"))
        status_code = status.get("code", props.get("statusCode", "Unknown"))
        status_cause = status.get("cause", "")

        domain = "UNKNOWN"
        if mcsb_ref:
            # Extract domain code from MCSB reference like "NS-1" or "IM-3"
            domain = mcsb_ref.split("-")[0] if "-" in str(mcsb_ref) else "UNKNOWN"
        if domain == "UNKNOWN" and category_str:
            domain = map_category_to_domain(category_str)

        rows.append({
            "recommendation_name": display_name,
            "category": category_str,
            "severity": severity,
            "status_code": status_code,
            "mcsb_control_ref": mcsb_ref,
            "guessed_domain": domain,
            "defender_covered": normalize_status(status_code, status_cause),
            "resource_id": item.get("id", ""),
        })
    return rows


def main():
    if not INPUT_FILE.exists():
        print(f"ERROR: Input file not found: {INPUT_FILE}", file=sys.stderr)
        print(f"Export from Azure portal or run:", file=sys.stderr)
        print(f"  az security assessment list --output json > {INPUT_FILE}", file=sys.stderr)
        sys.exit(1)

    (ROOT / "data" / "outputs").mkdir(parents=True, exist_ok=True)

    with open(INPUT_FILE) as f:
        data = json.load(f)

    # Detect format and extract items
    if isinstance(data, list):
        print("Detected format: list")
        items = data
    elif isinstance(data, dict) and "value" in data:
        print("Detected format: REST API {value: []}")
        items = data["value"]
    elif isinstance(data, dict) and "securityAssessments" in data:
        print("Detected format: {securityAssessments: []}")
        items = data["securityAssessments"]
    elif isinstance(data, dict) and "recommendations" in data:
        print("Detected format: {recommendations: []}")
        items = data["recommendations"]
    else:
        print("WARNING: Unrecognized format, attempting to parse as list of recommendations")
        items = list(data.values())[0] if isinstance(data, dict) else []

    print(f"Processing {len(items)} recommendations...")

    rows = extract_recommendations(items)
    df_out = pd.DataFrame(rows)

    if df_out.empty:
        print("WARNING: No recommendations extracted. Check input JSON structure.")
        df_out = pd.DataFrame(columns=[
            "recommendation_name", "category", "severity", "status_code",
            "mcsb_control_ref", "guessed_domain", "defender_covered", "resource_id"
        ])

    df_out.to_csv(OUTPUT_FILE, index=False)

    print(f"\nWrote {len(df_out)} recommendations to {OUTPUT_FILE}")
    print(f"\nCoverage:\n{df_out['defender_covered'].value_counts().to_string()}")
    print(f"\nDomain distribution:\n{df_out['guessed_domain'].value_counts().to_string()}")

    with_mcsb = len(df_out[df_out["mcsb_control_ref"].astype(str).str.len() > 2])
    print(f"\nRecommendations with direct MCSB reference: {with_mcsb}/{len(df_out)}")


if __name__ == "__main__":
    main()
