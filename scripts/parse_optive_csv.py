#!/usr/bin/env python3
"""
Parse Optive gap assessment CSV (pre-processed via docling → MCSB v3 format).

Inputs:  data/inputs/optive_parsed.csv
Outputs: data/outputs/optive_coverage.csv

Expected columns (MCSB v3 format from docling parse):
  Control ID, Azure Service, Control Title, Status, Notes, Remediation
  (column names may vary — script auto-detects)
"""

import sys
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).parent.parent
INPUT_FILE = ROOT / "data" / "inputs" / "optive_parsed.csv"
OUTPUT_FILE = ROOT / "data" / "outputs" / "optive_coverage.csv"

STATUS_NORMALIZATION = {
    # Covered variants
    "covered": "Covered",
    "pass": "Covered",
    "passed": "Covered",
    "compliant": "Covered",
    "implemented": "Covered",
    "yes": "Covered",
    "met": "Covered",
    "complete": "Covered",
    "done": "Covered",
    # Partial variants
    "partial": "Partial",
    "partially covered": "Partial",
    "partially implemented": "Partial",
    "in progress": "Partial",
    "in-progress": "Partial",
    "planned": "Partial",
    # Not covered variants
    "not covered": "Not Covered",
    "fail": "Not Covered",
    "failed": "Not Covered",
    "non-compliant": "Not Covered",
    "no": "Not Covered",
    "not implemented": "Not Covered",
    "not met": "Not Covered",
    "missing": "Not Covered",
    "gap": "Not Covered",
    # Not assessed
    "n/a": "Not Assessed",
    "not applicable": "Not Assessed",
    "na": "Not Assessed",
    "out of scope": "Not Assessed",
    "not assessed": "Not Assessed",
    "not evaluated": "Not Assessed",
    "": "Unknown",
}

COLUMN_CANDIDATES = {
    "v3_control_id": ["control id", "id", "control_id", "mcsb id", "benchmark id"],
    "azure_resource": ["azure service", "service", "resource", "azure resource"],
    "v3_control_title": ["control title", "control name", "title", "control"],
    "optive_status": ["status", "coverage status", "result", "compliance status", "finding"],
    "optive_notes": ["notes", "comments", "remarks", "observation", "finding detail"],
    "remediation": ["remediation", "recommendation", "action", "remediation steps"],
}


def detect_column(df: pd.DataFrame, candidates: list[str]) -> str | None:
    cols_lower = {c.lower().strip(): c for c in df.columns}
    for candidate in candidates:
        if candidate in cols_lower:
            return cols_lower[candidate]
    return None


def normalize_status(raw: str) -> str:
    if not isinstance(raw, str):
        return "Unknown"
    key = raw.strip().lower()
    return STATUS_NORMALIZATION.get(key, "Unknown")


def main():
    if not INPUT_FILE.exists():
        print(f"ERROR: Input file not found: {INPUT_FILE}", file=sys.stderr)
        print(f"Place Optive parsed CSV at: {INPUT_FILE}", file=sys.stderr)
        sys.exit(1)

    (ROOT / "data" / "outputs").mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(INPUT_FILE, encoding="utf-8-sig")
    print(f"Loaded {len(df)} rows")
    print(f"Columns: {list(df.columns)}")

    # Auto-detect columns
    col_map = {}
    for canonical, candidates in COLUMN_CANDIDATES.items():
        found = detect_column(df, candidates)
        col_map[canonical] = found
        status = "found" if found else "NOT FOUND"
        print(f"  {canonical}: {found or '—'} [{status}]")

    # Build output
    output_rows = []
    for _, row in df.iterrows():
        v3_id = str(row[col_map["v3_control_id"]]).strip() if col_map["v3_control_id"] else ""
        resource = str(row[col_map["azure_resource"]]).strip() if col_map["azure_resource"] else ""
        title = str(row[col_map["v3_control_title"]]).strip() if col_map["v3_control_title"] else ""
        raw_status = str(row[col_map["optive_status"]]).strip() if col_map["optive_status"] else ""
        notes = str(row[col_map["optive_notes"]]).strip() if col_map["optive_notes"] else ""

        if not v3_id and not title:
            continue

        output_rows.append({
            "v3_control_id": v3_id,
            "azure_resource": resource,
            "v3_control_title": title,
            "optive_status": normalize_status(raw_status),
            "optive_status_raw": raw_status,
            "optive_notes": notes[:300] if notes and notes != "nan" else "",
        })

    df_out = pd.DataFrame(output_rows)
    df_out.to_csv(OUTPUT_FILE, index=False)

    status_dist = df_out["optive_status"].value_counts()
    print(f"\nWrote {len(df_out)} records to {OUTPUT_FILE}")
    print(f"\nCoverage distribution:\n{status_dist.to_string()}")


if __name__ == "__main__":
    main()
