#!/usr/bin/env python3
"""
Parse ADO (Azure DevOps) export and fuzzy-match against MCSB controls.

Inputs:
  data/inputs/ado_export.json (or .csv)
  data/outputs/master_controls.csv

Outputs:
  data/outputs/ado_coverage.csv

Fuzzy match thresholds:
  score >= 90 → High confidence → mark Covered
  score 75-89 → Medium confidence → mark Likely (needs human review)
  score < 75  → No match
"""

import json
import sys
import pandas as pd
from pathlib import Path
from rapidfuzz import process, fuzz

ROOT = Path(__file__).parent.parent
MASTER_CONTROLS_FILE = ROOT / "data" / "outputs" / "master_controls.csv"
OUTPUT_FILE = ROOT / "data" / "outputs" / "ado_coverage.csv"

ADO_EXPORT_JSON = ROOT / "data" / "inputs" / "ado_export.json"
ADO_EXPORT_CSV = ROOT / "data" / "inputs" / "ado_export.csv"

HIGH_CONFIDENCE_THRESHOLD = 90
MEDIUM_CONFIDENCE_THRESHOLD = 75

# ADO tag prefixes that suggest MCSB domain coverage
DOMAIN_TAG_HINTS = {
    "ns": "NS", "network": "NS",
    "im": "IM", "identity": "IM",
    "pa": "PA", "privileged": "PA",
    "dp": "DP", "data-protection": "DP",
    "am": "AM", "asset": "AM",
    "lt": "LT", "logging": "LT",
    "ir": "IR", "incident": "IR",
    "pv": "PV", "vulnerability": "PV",
    "es": "ES", "endpoint": "ES",
    "br": "BR", "backup": "BR",
    "ds": "DS", "devops": "DS",
    "gs": "GS", "governance": "GS",
    "mcsb": "MCSB", "security-gap": "MCSB",
    "mcsb-v2": "MCSB",
}


def load_ado_json(path: Path) -> list[dict]:
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    # ADO API export format
    if isinstance(data, dict) and "value" in data:
        return data["value"]
    if isinstance(data, dict) and "workItems" in data:
        return data["workItems"]
    return []


def load_ado_csv(path: Path) -> list[dict]:
    df = pd.read_csv(path, encoding="utf-8-sig")
    return df.to_dict(orient="records")


def extract_ado_fields(item: dict) -> dict:
    # Handle both raw API format and CSV export format
    fields = item.get("fields", item)

    def get_field(*keys: str) -> str:
        for key in keys:
            val = fields.get(key, "")
            if val and str(val) != "nan":
                return str(val).strip()
        return ""

    return {
        "ado_item_id": str(item.get("id", get_field("System.Id", "ID", "Id"))),
        "ado_title": get_field("System.Title", "Title", "title"),
        "ado_state": get_field("System.State", "State", "state"),
        "ado_type": get_field("System.WorkItemType", "Work Item Type", "type"),
        "ado_tags": get_field("System.Tags", "Tags", "tags"),
        "ado_description": get_field("System.Description", "Description", "description"),
        "ado_area_path": get_field("System.AreaPath", "Area Path", "areaPath"),
        "ado_iteration": get_field("System.IterationPath", "Iteration Path", "iterationPath"),
    }


def check_tag_domain_hint(tags: str) -> str | None:
    """Check if ADO tags contain MCSB domain references."""
    if not tags:
        return None
    tags_lower = tags.lower().replace(" ", "")
    for hint, domain in DOMAIN_TAG_HINTS.items():
        if hint in tags_lower:
            return domain
    return None


def fuzzy_match_control(
    ado_title: str,
    control_titles: list[str],
    control_ids: list[str],
) -> tuple[str, float, str]:
    """
    Returns (unified_id, score, matched_title).
    Uses token_sort_ratio to handle word-order differences.
    """
    if not ado_title or not control_titles:
        return "", 0.0, ""

    result = process.extractOne(
        ado_title,
        control_titles,
        scorer=fuzz.token_sort_ratio,
    )
    if result is None:
        return "", 0.0, ""

    matched_title, score, idx = result
    return control_ids[idx], float(score), matched_title


def classify_coverage(state: str, score: float) -> tuple[str, str]:
    """Returns (ado_covered, match_confidence)."""
    closed_states = {"closed", "done", "resolved", "completed", "removed"}
    is_closed = state.lower().strip() in closed_states

    if score >= HIGH_CONFIDENCE_THRESHOLD:
        coverage = "Covered" if is_closed else "In Progress"
        confidence = "High"
    elif score >= MEDIUM_CONFIDENCE_THRESHOLD:
        coverage = "Likely"
        confidence = "Medium"
    else:
        coverage = "Not Found"
        confidence = "None"

    return coverage, confidence


def main():
    if not MASTER_CONTROLS_FILE.exists():
        print(f"ERROR: Run build_master_controls.py first. Missing: {MASTER_CONTROLS_FILE}")
        sys.exit(1)

    # Detect ADO input format
    if ADO_EXPORT_JSON.exists():
        print(f"Loading ADO export: {ADO_EXPORT_JSON}")
        raw_items = load_ado_json(ADO_EXPORT_JSON)
    elif ADO_EXPORT_CSV.exists():
        print(f"Loading ADO export: {ADO_EXPORT_CSV}")
        raw_items = load_ado_csv(ADO_EXPORT_CSV)
    else:
        print(f"ERROR: No ADO export found.", file=sys.stderr)
        print(f"Place export at {ADO_EXPORT_JSON} or {ADO_EXPORT_CSV}", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(raw_items)} ADO items")

    (ROOT / "data" / "outputs").mkdir(parents=True, exist_ok=True)

    df_controls = pd.read_csv(MASTER_CONTROLS_FILE)
    control_titles = df_controls["control_title"].tolist()
    control_ids = df_controls["unified_id"].tolist()

    output_rows = []
    for raw_item in raw_items:
        item = extract_ado_fields(raw_item)

        if not item["ado_title"]:
            continue

        unified_id, score, matched_title = fuzzy_match_control(
            item["ado_title"], control_titles, control_ids
        )
        coverage, confidence = classify_coverage(item["ado_state"], score)
        tag_domain = check_tag_domain_hint(item["ado_tags"])

        output_rows.append({
            **item,
            "matched_unified_id": unified_id,
            "match_score": round(score, 1),
            "matched_control_title": matched_title,
            "ado_covered": coverage,
            "match_confidence": confidence,
            "tag_domain_hint": tag_domain or "",
        })

    df_out = pd.DataFrame(output_rows)
    df_out.to_csv(OUTPUT_FILE, index=False)

    high = len(df_out[df_out["match_confidence"] == "High"])
    medium = len(df_out[df_out["match_confidence"] == "Medium"])
    none = len(df_out[df_out["match_confidence"] == "None"])

    print(f"\nWrote {len(df_out)} ADO items to {OUTPUT_FILE}")
    print(f"\nMatch confidence:")
    print(f"  High   (≥90, auto-match): {high}")
    print(f"  Medium (75-89, review):   {medium}")
    print(f"  None   (<75, no match):   {none}")
    print(f"\nCoverage distribution:\n{df_out['ado_covered'].value_counts().to_string()}")

    if medium > 0:
        print(f"\nReview Medium-confidence matches in: {OUTPUT_FILE}")
        print("Column 'match_score' shows similarity. Adjust matched_unified_id if wrong.")


if __name__ == "__main__":
    main()
