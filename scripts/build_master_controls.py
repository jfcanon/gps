#!/usr/bin/env python3
"""
Merge MCSB v2 controls + mapped v3 controls into unified master control list.

Inputs:
  data/outputs/mcsb_v2_raw.csv
  data/outputs/mcsb_v3_mapped.csv

Outputs:
  data/outputs/master_controls.csv  (~162 rows)

Merge strategy:
  1. Start with all v2 controls (authoritative structure)
  2. For each v3 control, find best-match v2 control in same domain (title similarity)
  3. If similarity >= 0.80: merge into v2 row (source = v2+v3)
  4. If similarity < 0.80: add as standalone row (source = v3, synthetic unified_id)
"""

import re
import pandas as pd
from pathlib import Path
from rapidfuzz import fuzz

ROOT = Path(__file__).parent.parent
V2_FILE = ROOT / "data" / "outputs" / "mcsb_v2_raw.csv"
V3_FILE = ROOT / "data" / "outputs" / "mcsb_v3_mapped.csv"
OUTPUT_FILE = ROOT / "data" / "outputs" / "master_controls.csv"

MERGE_THRESHOLD = 80  # rapidfuzz token_sort_ratio score

SEVERITY_DEFAULTS: dict[str, str] = {
    "NS": "High", "IM": "High", "PA": "High",
    "DP": "High", "AM": "Medium", "LT": "High",
    "IR": "Medium", "PV": "High", "ES": "Medium",
    "BR": "Medium", "DS": "Medium", "GS": "Medium",
}

IMPLEMENTATION_TYPE_KEYWORDS = {
    "Automated": ["policy", "defender", "diagnostic", "azure monitor", "automatic", "enable"],
    "Manual": ["document", "define", "establish", "train", "review", "approve", "strategy"],
}


def infer_implementation_type(text: str) -> str:
    text_lower = text.lower()
    for impl_type, keywords in IMPLEMENTATION_TYPE_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            return impl_type
    return "Hybrid"


def similarity(a: str, b: str) -> float:
    return fuzz.token_sort_ratio(a.lower().strip(), b.lower().strip())


def assign_unified_id(control_id: str, domain_code: str, seq: int, source: str) -> str:
    if source in ("v2", "v2+v3") and control_id and control_id != "nan":
        return control_id
    return f"{domain_code}-v3-{seq:03d}"


def main():
    if not V2_FILE.exists():
        print(f"ERROR: Run fetch_mcsb_v2.py first. Missing: {V2_FILE}")
        raise SystemExit(1)

    if not V3_FILE.exists():
        print(f"ERROR: Run map_v3_to_v2_domains.py first. Missing: {V3_FILE}")
        raise SystemExit(1)

    (ROOT / "data" / "outputs").mkdir(parents=True, exist_ok=True)

    df_v2 = pd.read_csv(V2_FILE)
    df_v3 = pd.read_csv(V3_FILE)

    print(f"v2 controls: {len(df_v2)}")
    print(f"v3 controls: {len(df_v3)}")

    # Track which v3 controls get merged into a v2 row
    v3_merged_ids: set[str] = set()

    # Build v2 rows (primary structure)
    output_rows = []
    for _, v2_row in df_v2.iterrows():
        domain = str(v2_row.get("domain_code", "")).strip()
        v2_title = str(v2_row.get("control_title", "")).strip()
        v2_id = str(v2_row.get("control_id", "")).strip()

        # Find v3 controls in same domain with similar title
        same_domain_v3 = df_v3[df_v3["domain_code"] == domain]
        best_match_id = None
        best_score = 0.0

        for _, v3_row in same_domain_v3.iterrows():
            v3_title = str(v3_row.get("v3_control_title", "")).strip()
            score = similarity(v2_title, v3_title)
            if score > best_score and score >= MERGE_THRESHOLD:
                best_score = score
                best_match_id = str(v3_row.get("v3_control_id", ""))

        source = "v2"
        v3_control_id = ""
        v3_resource = ""
        v3_title = ""
        merge_notes = ""

        if best_match_id:
            v3_matched = df_v3[df_v3["v3_control_id"] == best_match_id].iloc[0]
            source = "v2+v3"
            v3_control_id = best_match_id
            v3_resource = str(v3_matched.get("azure_resource", "")).strip()
            v3_title = str(v3_matched.get("v3_control_title", "")).strip()
            merge_notes = f"Auto-merged (score={best_score:.0f})"
            v3_merged_ids.add(best_match_id)

        all_text = f"{v2_title} {str(v2_row.get('control_description', ''))}"
        output_rows.append({
            "unified_id": v2_id,
            "domain_code": domain,
            "domain_name": str(v2_row.get("domain_name", "")).strip(),
            "control_title": v2_title,
            "source": source,
            "v2_control_id": v2_id,
            "v2_control_title": v2_title,
            "v3_control_id": v3_control_id,
            "v3_resource": v3_resource,
            "v3_control_title": v3_title,
            "severity": SEVERITY_DEFAULTS.get(domain, "Medium"),
            "implementation_type": infer_implementation_type(all_text),
            "notes": merge_notes,
        })

    # Add unmerged v3 controls as standalone rows
    domain_v3_seq: dict[str, int] = {}

    for _, v3_row in df_v3.iterrows():
        v3_id = str(v3_row.get("v3_control_id", "")).strip()
        if v3_id in v3_merged_ids:
            continue

        # Skip Low-confidence unmapped controls
        if v3_row.get("domain_code", "UNKNOWN") == "UNKNOWN":
            continue

        domain = str(v3_row.get("domain_code", "")).strip()
        domain_v3_seq[domain] = domain_v3_seq.get(domain, 0) + 1
        unified_id = f"{domain}-v3-{domain_v3_seq[domain]:03d}"

        v3_title = str(v3_row.get("v3_control_title", "")).strip()
        all_text = f"{v3_title} {str(v3_row.get('v3_description', ''))}"

        output_rows.append({
            "unified_id": unified_id,
            "domain_code": domain,
            "domain_name": str(v3_row.get("domain_name", "")).strip(),
            "control_title": v3_title,
            "source": "v3",
            "v2_control_id": "",
            "v2_control_title": "",
            "v3_control_id": v3_id,
            "v3_resource": str(v3_row.get("azure_resource", "")).strip(),
            "v3_control_title": v3_title,
            "severity": SEVERITY_DEFAULTS.get(domain, "Medium"),
            "implementation_type": infer_implementation_type(all_text),
            "notes": f"v3 control mapped to {domain} domain (confidence: {v3_row.get('mapping_confidence', '?')})",
        })

    df_out = pd.DataFrame(output_rows)

    # Sort by domain_code, then v2 controls first, then v3
    source_order = {"v2": 0, "v2+v3": 1, "v3": 2}
    df_out["_sort_source"] = df_out["source"].map(source_order)
    df_out = df_out.sort_values(["domain_code", "_sort_source"]).drop(columns=["_sort_source"])

    df_out.to_csv(OUTPUT_FILE, index=False)

    merged_count = len(df_out[df_out["source"] == "v2+v3"])
    v2_only = len(df_out[df_out["source"] == "v2"])
    v3_only = len(df_out[df_out["source"] == "v3"])

    print(f"\nMaster control list: {len(df_out)} total controls")
    print(f"  v2 only:  {v2_only}")
    print(f"  v2+v3:    {merged_count} (merged)")
    print(f"  v3 only:  {v3_only}")
    print(f"\nWrote: {OUTPUT_FILE}")
    print(f"\nDomain breakdown:\n{df_out.groupby('domain_code').size().to_string()}")


if __name__ == "__main__":
    main()
