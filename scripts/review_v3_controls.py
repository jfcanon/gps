"""
review_v3_controls.py
---------------------
Phase 35: Classify applicability and automation feasibility for each v3
per-service control row.

Input:  data/outputs/v3_service_controls_raw.csv
Output: data/outputs/v3_service_controls_reviewed.csv

Added columns:
  applicability      — customer | not_applicable | microsoft_managed | shared | unknown
  newly_applicable   — True if was N/A but Feature Supported is now available
  automation_class   — script_simple | script_medium | manual_only | not_applicable

Usage:
  python3 review_v3_controls.py [--raw PATH] [--out PATH]
"""

import csv
import argparse
from pathlib import Path
from collections import Counter

ROOT     = Path(__file__).parent.parent
RAW_CSV  = ROOT / "data" / "outputs" / "v3_service_controls_raw.csv"
OUT_CSV  = ROOT / "data" / "outputs" / "v3_service_controls_reviewed.csv"


# ---------------------------------------------------------------------------
# Classifiers
# ---------------------------------------------------------------------------

def classify_applicability(responsibility: str) -> str:
    r = responsibility.strip().lower()
    if "not applicable" in r or r == "n/a":
        return "not_applicable"
    if r == "microsoft":
        return "microsoft_managed"
    if "shared" in r:
        return "shared"
    if "customer" in r:
        return "customer"
    if r == "":
        return "unknown"
    return "customer"   # default: anything else is customer responsibility


def is_newly_applicable(responsibility: str, feature_supported: str) -> bool:
    """
    Flag controls that were marked N/A in Responsibility but now have
    Feature Supported = True, indicating the Azure service added support.
    """
    was_na   = "not applicable" in responsibility.lower()
    now_supp = feature_supported.strip().lower() not in ("not applicable", "false", "no", "")
    return was_na and now_supp


def classify_automation(feature_supported: str, feature_enabled_by_default: str) -> str:
    """
    Determine how automatable a control check is based on Feature Summary fields.

    script_simple  — Feature exists AND is on by default (just verify compliance state)
    script_medium  — Feature exists BUT must be enabled (check + remediation script needed)
    manual_only    — Feature not supported (manual config review required)
    not_applicable — Feature explicitly marked N/A for this service
    """
    sup = feature_supported.strip().lower()
    ena = feature_enabled_by_default.strip().lower()

    if sup == "not applicable":
        return "not_applicable"
    if sup in ("false", "no"):
        return "manual_only"
    if sup in ("true", "yes"):
        if ena in ("true", "yes"):
            return "script_simple"
        return "script_medium"
    # Unexpected value → treat as manual
    return "manual_only"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(raw_path: str, out_path: str) -> None:
    raw = Path(raw_path)
    if not raw.exists():
        print(f"[ERROR] Raw CSV not found: {raw}")
        print("        Run download_v3_baselines.py first.")
        return

    with open(raw, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    reviewed = []
    for row in rows:
        resp          = row.get("responsibility", "")
        feat_supp     = row.get("feature_supported", "")
        feat_ena      = row.get("feature_enabled_by_default", "")

        row["applicability"]    = classify_applicability(resp)
        row["newly_applicable"] = str(is_newly_applicable(resp, feat_supp))
        row["automation_class"] = classify_automation(feat_supp, feat_ena)
        reviewed.append(row)

    # Write output
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(reviewed[0].keys()) if reviewed else []
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(reviewed)

    # Summary
    appl_counts  = Counter(r["applicability"]    for r in reviewed)
    auto_counts  = Counter(r["automation_class"] for r in reviewed)
    newly        = sum(1 for r in reviewed if r["newly_applicable"] == "True")
    customer_rows = [r for r in reviewed if r["applicability"] == "customer"]

    print(f"Reviewed {len(reviewed)} rows → {out}")
    print(f"\nApplicability breakdown:")
    for k, v in sorted(appl_counts.items(), key=lambda x: -x[1]):
        print(f"  {k:<20} {v:>5}")

    print(f"\nAutomation class (all rows):")
    for k, v in sorted(auto_counts.items(), key=lambda x: -x[1]):
        print(f"  {k:<20} {v:>5}")

    print(f"\nCustomer-applicable rows: {len(customer_rows)}")
    customer_auto = Counter(r["automation_class"] for r in customer_rows)
    for k, v in sorted(customer_auto.items(), key=lambda x: -x[1]):
        print(f"  {k:<20} {v:>5}")

    print(f"\nNewly applicable (was N/A, now supported): {newly}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Classify v3 control applicability + automation feasibility")
    parser.add_argument("--raw", default=str(RAW_CSV), help="Input raw CSV")
    parser.add_argument("--out", default=str(OUT_CSV), help="Output reviewed CSV")
    args = parser.parse_args()
    main(args.raw, args.out)
