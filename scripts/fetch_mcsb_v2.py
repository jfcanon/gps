#!/usr/bin/env python3
"""
Fetch MCSB v2 (preview) controls from Microsoft GitHub.

Outputs: data/outputs/mcsb_v2_raw.csv

MCSB v2 GitHub: https://github.com/MicrosoftDocs/SecurityBenchmarks
Expected columns vary by Excel version. Script normalizes to standard schema.
"""

import sys
import io
import requests
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).parent.parent
OUTPUT_DIR = ROOT / "data" / "outputs"
OUTPUT_FILE = OUTPUT_DIR / "mcsb_v2_raw.csv"
INPUT_FALLBACK = ROOT / "data" / "inputs" / "mcsb_v2.xlsx"

# Candidate URLs — try in order, first success wins
GITHUB_URLS = [
    "https://raw.githubusercontent.com/MicrosoftDocs/SecurityBenchmarks/master/Azure%20Security%20Benchmark/3.0/azure-security-benchmark-v3-latest.xlsx",
    "https://raw.githubusercontent.com/MicrosoftDocs/SecurityBenchmarks/master/Azure%20Security%20Benchmark/2.0/azure-security-benchmark-v2-latest.xlsx",
]

# Normalized column map: (actual column name variants) -> canonical name
COLUMN_MAP = {
    "id": "control_id",
    "control id": "control_id",
    "benchmark control": "control_id",
    "control": "control_title",
    "control name": "control_title",
    "title": "control_title",
    "description": "control_description",
    "guidance": "guidance",
    "azure security benchmark v2": "control_id",
    "security function": "security_function",
    "category": "domain_name",
    "security domain": "domain_name",
}

DOMAIN_CODE_MAP = {
    "network security": "NS",
    "identity management": "IM",
    "privileged access": "PA",
    "data protection": "DP",
    "asset management": "AM",
    "logging and threat detection": "LT",
    "incident response": "IR",
    "posture and vulnerability management": "PV",
    "endpoint security": "ES",
    "backup and recovery": "BR",
    "devops security": "DS",
    "governance and strategy": "GS",
}


def fetch_excel(url: str) -> bytes | None:
    print(f"  Trying: {url}")
    try:
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            print(f"  Success ({len(resp.content):,} bytes)")
            return resp.content
    except requests.RequestException as e:
        print(f"  Failed: {e}")
    return None


def load_excel_bytes(data: bytes) -> pd.DataFrame:
    return pd.read_excel(io.BytesIO(data), engine="openpyxl")


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    renamed = {}
    for col in df.columns:
        normalized = col.strip().lower()
        if normalized in COLUMN_MAP:
            renamed[col] = COLUMN_MAP[normalized]
    return df.rename(columns=renamed)


def extract_domain_code(domain_name: str) -> str:
    if not isinstance(domain_name, str):
        return "UNKNOWN"
    key = domain_name.strip().lower()
    for domain, code in DOMAIN_CODE_MAP.items():
        if domain in key:
            return code
    # Try prefix match (e.g., "NS. Network Security")
    prefix = key.split(".")[0].strip()
    if prefix in [c.lower() for c in DOMAIN_CODE_MAP.values()]:
        return prefix.upper()
    return "UNKNOWN"


def infer_control_id(row: pd.Series, idx: int) -> str:
    """Extract or infer control ID like NS-1, IM-3 from row data."""
    if "control_id" in row and isinstance(row["control_id"], str):
        cid = row["control_id"].strip()
        if cid and cid != "nan":
            return cid
    domain_code = row.get("domain_code", "XX")
    return f"{domain_code}-{idx}"


def build_output(df: pd.DataFrame) -> pd.DataFrame:
    output_rows = []
    seq_counters: dict[str, int] = {}

    for _, row in df.iterrows():
        domain_name = str(row.get("domain_name", "")).strip()
        if not domain_name or domain_name == "nan":
            continue

        domain_code = extract_domain_code(domain_name)
        seq_counters[domain_code] = seq_counters.get(domain_code, 0) + 1

        control_id = infer_control_id(row, seq_counters[domain_code])
        control_title = str(row.get("control_title", "")).strip()
        description = str(row.get("control_description", row.get("guidance", ""))).strip()

        output_rows.append({
            "control_id": control_id,
            "domain_code": domain_code,
            "domain_name": domain_name,
            "control_title": control_title,
            "control_description": description[:500] if description else "",
            "source": "v2",
        })

    return pd.DataFrame(output_rows)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    df_raw = None

    # Try remote fetch first
    for url in GITHUB_URLS:
        data = fetch_excel(url)
        if data:
            df_raw = load_excel_bytes(data)
            break

    # Fallback to local file
    if df_raw is None and INPUT_FALLBACK.exists():
        print(f"Using local fallback: {INPUT_FALLBACK}")
        df_raw = pd.read_excel(INPUT_FALLBACK, engine="openpyxl")

    if df_raw is None:
        print("ERROR: Could not fetch MCSB v2 data.", file=sys.stderr)
        print(f"Download manually from GitHub and place at: {INPUT_FALLBACK}", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(df_raw)} rows, {len(df_raw.columns)} columns")
    print(f"Columns: {list(df_raw.columns)}")

    df_normalized = normalize_columns(df_raw)
    df_output = build_output(df_normalized)

    df_output.to_csv(OUTPUT_FILE, index=False)
    print(f"\nWrote {len(df_output)} controls to {OUTPUT_FILE}")
    print(f"Domain distribution:\n{df_output['domain_code'].value_counts().to_string()}")


if __name__ == "__main__":
    main()
