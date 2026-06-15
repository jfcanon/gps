"""
estimate_effort_v3.py
---------------------
Phase 36: Produce revised effort estimates for v3-combined user stories,
matched against per-service control data from Phase 35.

Inputs:
  scripts/ado_stories.csv                       (has policy_status, is_combined, resource)
  data/outputs/v3_service_controls_reviewed.csv (has automation_class, applicability)

Output:
  data/outputs/effort_estimates_v3.csv

Matching:
  story.resource (e.g. "Bot Service") ↔ reviewed.service_name (e.g. "azure-bot-service")
  Uses rapidfuzz for fuzzy name matching (threshold 60).
  Stories with no match fall back to Phase 32 formula.

Scope:
  Only is_combined=True stories are processed here.
  Pure v2 stories with policy_status=confirmed are excluded (already handled).
  All others use the v3 formula or Phase 32 fallback.

Effort table (industry-calibrated, from Phase 33 benchmark):
  script_simple  + confirmed → 2h
  script_simple  + uncertain → 3h
  script_simple  + none      → 3h
  script_medium  + any       → 4h
  manual_only    + any       → 7h
  not_applicable + any       → 0.5h

Usage:
  python3 estimate_effort_v3.py [--stories PATH] [--reviewed PATH] [--out PATH]
"""

import csv
import argparse
from pathlib import Path
from collections import Counter, defaultdict

ROOT          = Path(__file__).parent.parent
STORIES_CSV   = Path(__file__).parent / "ado_stories.csv"
REVIEWED_CSV  = ROOT / "data" / "outputs" / "v3_service_controls_reviewed.csv"
OUT_CSV       = ROOT / "data" / "outputs" / "effort_estimates_v3.csv"

# Effort table: (automation_class, policy_status) → hours
EFFORT = {
    ("script_simple",  "confirmed"): 2.0,
    ("script_simple",  "uncertain"): 3.0,
    ("script_simple",  "none"):      3.0,
    ("script_medium",  "confirmed"): 3.0,
    ("script_medium",  "uncertain"): 4.0,
    ("script_medium",  "none"):      4.0,
    ("manual_only",    "confirmed"): 4.0,
    ("manual_only",    "uncertain"): 5.0,
    ("manual_only",    "none"):      7.0,
    ("not_applicable", "confirmed"): 0.5,
    ("not_applicable", "uncertain"): 0.5,
    ("not_applicable", "none"):      0.5,
}

# Phase 32 fallback table (when no v3 row match found)
PHASE32_FALLBACK = {
    ("none",      "manual_only"):    7.0,
    ("none",      "script_complex"): 5.0,
    ("none",      "script_simple"):  4.0,
    ("uncertain", "manual_only"):    5.0,
    ("uncertain", "script_complex"): 4.0,
    ("uncertain", "script_simple"):  3.0,
    ("confirmed", "manual_only"):    4.0,
    ("confirmed", "script_complex"): 3.0,
    ("confirmed", "script_simple"):  2.0,
}


def _normalise(name: str) -> str:
    """Lower, strip, remove common noise words for fuzzy matching."""
    noise = ["azure", "microsoft", "service", "services", "for", "the", "-"]
    n = name.lower().strip()
    for w in noise:
        n = n.replace(w, " ")
    return " ".join(n.split())


def fuzzy_match(resource: str, service_names: list[str], threshold: int = 60) -> str | None:
    """Return best-matching service_name or None."""
    try:
        from rapidfuzz import process, fuzz
        norm_resource = _normalise(resource)
        norm_services = {s: _normalise(s) for s in service_names}
        result = process.extractOne(
            norm_resource,
            list(norm_services.values()),
            scorer=fuzz.token_sort_ratio,
            score_cutoff=threshold,
        )
        if result:
            matched_norm = result[0]
            for orig, norm in norm_services.items():
                if norm == matched_norm:
                    return orig
    except ImportError:
        pass
    return None


def dominant_automation_class(rows: list[dict]) -> str:
    """Return most common automation_class among customer-applicable rows."""
    customer = [r for r in rows if r.get("applicability") == "customer"]
    if not customer:
        return "manual_only"
    counts = Counter(r["automation_class"] for r in customer)
    return counts.most_common(1)[0][0]


def main(stories_path: str, reviewed_path: str, out_path: str) -> None:
    # Load inputs
    if not Path(stories_path).exists():
        print(f"[ERROR] {stories_path} not found. Run parse_stories.py + audit_policy_coverage.py first.")
        return
    if not Path(reviewed_path).exists():
        print(f"[ERROR] {reviewed_path} not found. Run review_v3_controls.py first.")
        return

    with open(stories_path, newline="", encoding="utf-8") as f:
        stories = list(csv.DictReader(f))
    with open(reviewed_path, newline="", encoding="utf-8") as f:
        reviewed = list(csv.DictReader(f))

    # Build lookup: service_name → list of rows
    service_rows: dict[str, list[dict]] = defaultdict(list)
    for row in reviewed:
        service_rows[row["service_name"]].append(row)
    all_services = list(service_rows.keys())

    estimates = []
    match_count = 0
    fallback_count = 0

    for story in stories:
        is_combined    = story.get("is_combined", "False") == "True"
        policy_status  = story.get("policy_status", "none")
        resource       = story.get("resource", "")

        # Skip pure v2 confirmed stories (already handled by Azure Policy built-ins)
        if not is_combined and policy_status == "confirmed":
            continue

        matched_service = None
        auto_class      = None
        source          = "phase32_fallback"
        hours           = None

        # Try to match resource → v3 service
        if resource and is_combined:
            matched_service = fuzzy_match(resource, all_services)
            if matched_service:
                rows = service_rows[matched_service]
                auto_class = dominant_automation_class(rows)
                hours = EFFORT.get((auto_class, policy_status), 4.0)
                source = "v3_matched"
                match_count += 1

        # Fallback to Phase 32 formula
        if hours is None:
            auto_class = "manual_only" if not is_combined else "script_medium"
            hours = PHASE32_FALLBACK.get((policy_status, auto_class), 4.0)
            source = "phase32_fallback"
            fallback_count += 1

        estimates.append({
            "domain":           story.get("domain", ""),
            "story_id":         story.get("story_id", ""),
            "story_title":      story.get("story_title", "")[:60],
            "resource":         resource,
            "matched_service":  matched_service or "",
            "is_combined":      story.get("is_combined", "False"),
            "policy_status":    policy_status,
            "automation_class": auto_class,
            "estimated_hours":  hours,
            "source":           source,
        })

    # Write output
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(estimates[0].keys()) if estimates else [])
        writer.writeheader()
        writer.writerows(estimates)

    total_hours = sum(e["estimated_hours"] for e in estimates)

    # Domain summary
    domain_hours: dict[str, float] = defaultdict(float)
    domain_count: dict[str, int]   = defaultdict(int)
    for e in estimates:
        domain_hours[e["domain"]] += e["estimated_hours"]
        domain_count[e["domain"]] += 1

    print(f"Processed {len(estimates)} stories ({match_count} v3-matched, {fallback_count} fallback)")
    print(f"\n── Effort Summary by Domain (v3-revised) ─────────────────────")
    print(f"{'Domain':<6} {'Stories':>8} {'Hours':>8} {'Days(8h)':>10}")
    print("-" * 36)
    for domain in sorted(domain_hours):
        h = domain_hours[domain]
        print(f"{domain:<6} {domain_count[domain]:>8} {h:>8.1f} {h/8:>10.1f}")
    print("-" * 36)
    print(f"{'TOTAL':<6} {len(estimates):>8} {total_hours:>8.1f} {total_hours/8:>10.1f}")
    print(f"\n→ {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Revised effort estimates using v3 per-service data")
    parser.add_argument("--stories",  default=str(STORIES_CSV),  help="ado_stories.csv path")
    parser.add_argument("--reviewed", default=str(REVIEWED_CSV), help="v3_service_controls_reviewed.csv path")
    parser.add_argument("--out",      default=str(OUT_CSV),      help="Output CSV path")
    args = parser.parse_args()
    main(args.stories, args.reviewed, args.out)
