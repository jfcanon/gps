"""
audit_policy_coverage.py
------------------------
Phase 29: Classify Azure Policy built-in coverage for each user story.

Reads:  ado_stories.csv
Writes: ado_stories.csv (adds policy_status column)
        data/outputs/policy_coverage_summary.csv

policy_status values:
  confirmed  — learn.microsoft.com link present, no ⚠️ in policy section
  uncertain  — ⚠️ flag with a quoted policy name (training data, unverified)
  none       — explicit "No confirmed built-ins" or assessment relies on manual audit only

Usage:
  python3 audit_policy_coverage.py [--csv PATH]
"""

import csv
import argparse
from pathlib import Path
from collections import Counter


def classify_policy_status(description: str) -> str:
    """
    Classify Azure Policy built-in coverage from story description text.

    Signal priority:
      1. "No confirmed Azure Policy built-ins" → none
      2. learn.microsoft.com link + ⚠️ in policy section → uncertain
      3. learn.microsoft.com link, no ⚠️ in policy section → confirmed
      4. ⚠️ with quoted policy name (azadvertizer) → uncertain
      5. Default → none
    """
    desc_lower = description.lower()

    # Explicit no-built-in signal
    if "no confirmed azure policy built-in" in desc_lower:
        return "none"

    # Extract policy section (everything after the sentinel phrase)
    sentinel = "key azure policy built-ins applicable:"
    if sentinel in desc_lower:
        idx = desc_lower.index(sentinel) + len(sentinel)
        policy_section = description[idx:]
    else:
        policy_section = description

    has_confirmed_link = "learn.microsoft.com" in policy_section
    has_warn_flag      = "⚠️" in policy_section

    if has_confirmed_link and not has_warn_flag:
        return "confirmed"

    if has_confirmed_link and has_warn_flag:
        # ⚠️ means training data — not fully verified
        return "uncertain"

    if has_warn_flag and ('"' in policy_section or "azadvertizer" in policy_section):
        return "uncertain"

    return "none"


def main(csv_path: str) -> None:
    input_path = Path(csv_path)
    if not input_path.exists():
        print(f"[ERROR] CSV not found: {input_path}")
        print("        Run parse_stories.py first.")
        return

    with open(input_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    # Add policy_status to each row
    for row in rows:
        row["policy_status"] = classify_policy_status(row["description"])

    # Rewrite CSV with new column
    fieldnames = list(rows[0].keys())
    with open(input_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Updated {input_path} — added policy_status column")

    # Summary by domain
    print("\n── Policy Coverage by Domain ─────────────────────────────────")
    print(f"{'Domain':<6} {'confirmed':>10} {'uncertain':>10} {'none':>6} {'total':>6}")
    print("-" * 42)

    domains = sorted({r["domain"] for r in rows})
    grand = Counter()
    for domain in domains:
        domain_rows = [r for r in rows if r["domain"] == domain]
        counts = Counter(r["policy_status"] for r in domain_rows)
        grand.update(counts)
        print(f"{domain:<6} {counts['confirmed']:>10} {counts['uncertain']:>10} {counts['none']:>6} {len(domain_rows):>6}")

    print("-" * 42)
    print(f"{'TOTAL':<6} {grand['confirmed']:>10} {grand['uncertain']:>10} {grand['none']:>6} {len(rows):>6}")

    # Write summary CSV
    summary_dir = input_path.parent.parent / "data" / "outputs"
    summary_dir.mkdir(parents=True, exist_ok=True)
    summary_path = summary_dir / "policy_coverage_summary.csv"

    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "confirmed", "uncertain", "none", "total"])
        writer.writeheader()
        for domain in domains:
            domain_rows = [r for r in rows if r["domain"] == domain]
            counts = Counter(r["policy_status"] for r in domain_rows)
            writer.writerow({
                "domain":    domain,
                "confirmed": counts["confirmed"],
                "uncertain": counts["uncertain"],
                "none":      counts["none"],
                "total":     len(domain_rows),
            })

    print(f"\nSummary → {summary_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit Azure Policy built-in coverage per user story")
    parser.add_argument("--csv", default="ado_stories.csv", help="Path to ado_stories.csv")
    args = parser.parse_args()
    main(args.csv)
