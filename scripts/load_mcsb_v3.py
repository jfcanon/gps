#!/usr/bin/env python3
"""
Load MCSB v3 GitHub Excel (118 controls, per-resource).

Inputs:  data/inputs/mcsb_v3.xlsx
         (download from https://github.com/MicrosoftDocs/SecurityBenchmarks)
Outputs: data/outputs/mcsb_v3_raw.csv
"""

import sys
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).parent.parent
INPUT_FILE = ROOT / "data" / "inputs" / "mcsb_v3.xlsx"
OUTPUT_FILE = ROOT / "data" / "outputs" / "mcsb_v3_raw.csv"

# Known v3 column name variants → canonical
COLUMN_MAP = {
    "id": "v3_control_id",
    "control id": "v3_control_id",
    "azure service": "azure_resource",
    "service": "azure_resource",
    "resource": "azure_resource",
    "control title": "v3_control_title",
    "control name": "v3_control_title",
    "title": "v3_control_title",
    "description": "v3_description",
    "guidance": "v3_guidance",
    "responsibility": "responsibility",
    "feature": "feature",
    "policy / implementation": "policy_implementation",
    "policy/implementation": "policy_implementation",
}


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    renamed = {}
    for col in df.columns:
        key = col.strip().lower()
        if key in COLUMN_MAP:
            renamed[col] = COLUMN_MAP[key]
    df = df.rename(columns=renamed)
    return df


def infer_v3_id(row: pd.Series, azure_resource: str, seq: int) -> str:
    if "v3_control_id" in row.index:
        cid = str(row["v3_control_id"]).strip()
        if cid and cid != "nan":
            return cid
    # Synthetic ID from resource abbreviation
    abbrev = "".join(w[0].upper() for w in azure_resource.split()[:3]) if azure_resource else "XX"
    return f"{abbrev}-{seq:03d}"


def main():
    if not INPUT_FILE.exists():
        print(f"ERROR: Input file not found: {INPUT_FILE}", file=sys.stderr)
        print("Download MCSB v3 Excel from:", file=sys.stderr)
        print("  https://github.com/MicrosoftDocs/SecurityBenchmarks/tree/master/Azure%20Security%20Benchmark", file=sys.stderr)
        print(f"Place at: {INPUT_FILE}", file=sys.stderr)
        sys.exit(1)

    (ROOT / "data" / "outputs").mkdir(parents=True, exist_ok=True)

    df = pd.read_excel(INPUT_FILE, engine="openpyxl")
    print(f"Loaded {len(df)} rows, {len(df.columns)} columns")
    print(f"Columns: {list(df.columns)}")

    df = normalize_columns(df)

    # Ensure required columns exist
    for col in ["azure_resource", "v3_control_title"]:
        if col not in df.columns:
            print(f"WARNING: Column '{col}' not found. Available: {list(df.columns)}")

    # Build output with synthetic IDs if needed
    output_rows = []
    resource_seq: dict[str, int] = {}

    for _, row in df.iterrows():
        resource = str(row.get("azure_resource", "Unknown")).strip()
        if not resource or resource == "nan":
            continue

        resource_seq[resource] = resource_seq.get(resource, 0) + 1
        v3_id = infer_v3_id(row, resource, resource_seq[resource])

        output_rows.append({
            "v3_control_id": v3_id,
            "azure_resource": resource,
            "v3_control_title": str(row.get("v3_control_title", "")).strip(),
            "v3_description": str(row.get("v3_description", row.get("v3_guidance", ""))).strip()[:500],
            "responsibility": str(row.get("responsibility", "")).strip(),
            "feature": str(row.get("feature", "")).strip(),
            "source": "v3",
        })

    df_out = pd.DataFrame(output_rows)
    df_out.to_csv(OUTPUT_FILE, index=False)

    print(f"\nWrote {len(df_out)} v3 controls to {OUTPUT_FILE}")
    print(f"Azure resources covered:\n{df_out['azure_resource'].value_counts().head(20).to_string()}")


if __name__ == "__main__":
    main()
