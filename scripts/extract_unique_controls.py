"""
extract_unique_controls.py
--------------------------
Phase 37 (step 1): Extract unique ASB control IDs from v3_service_controls_reviewed.csv
for Qwen3 reclassification batch.

Input:  data/outputs/v3_service_controls_reviewed.csv
Output: data/outputs/v3_unique_controls.csv

Per unique asb_control_id:
  - asb_control_id, asb_control_title, control_domain
  - guidance: longest non-empty guidance string across all service rows
  - service_count: number of distinct services with this control
  - current_auto_class_distribution: JSON string of automation_class counts
"""

import csv
import json
import argparse
from pathlib import Path
from collections import defaultdict, Counter

ROOT     = Path(__file__).parent.parent
IN_CSV   = ROOT / "data" / "outputs" / "v3_service_controls_reviewed.csv"
OUT_CSV  = ROOT / "data" / "outputs" / "v3_unique_controls.csv"


def main(in_path: str, out_path: str) -> None:
    with open(in_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    # Group by control ID
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        cid = row.get("asb_control_id", "").strip()
        if cid:
            groups[cid].append(row)

    unique = []
    for cid, grp in groups.items():
        # Longest non-empty guidance
        guidance = max(
            (r.get("guidance", "") or "" for r in grp),
            key=len,
            default="",
        )
        # First row for title + domain (consistent across group)
        first = grp[0]
        service_count = len({r.get("service_name", "") for r in grp})
        auto_dist = dict(Counter(r.get("automation_class", "") for r in grp))

        unique.append({
            "asb_control_id":                 cid,
            "asb_control_title":              first.get("asb_control_title", ""),
            "control_domain":                 first.get("control_domain", ""),
            "guidance":                       guidance[:2000],  # cap for prompt length
            "service_count":                  service_count,
            "current_auto_class_distribution": json.dumps(auto_dist),
        })

    # Sort by domain then control ID
    unique.sort(key=lambda r: (r["control_domain"], r["asb_control_id"]))

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(unique[0].keys()) if unique else []
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(unique)

    print(f"Unique control IDs: {len(unique)}")
    print(f"Total input rows:   {len(rows)}")
    print(f"→ {out}")

    # Sample
    print("\nSample (first 5):")
    for r in unique[:5]:
        print(f"  {r['asb_control_id']:<8} {r['control_domain']:<30} services={r['service_count']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--in",  dest="in_path",  default=str(IN_CSV))
    parser.add_argument("--out", dest="out_path", default=str(OUT_CSV))
    args = parser.parse_args()
    main(args.in_path, args.out_path)
