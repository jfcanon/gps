"""
estimate_effort_ns_filtered.py
-------------------------------
Phase 39: Re-estimate NS domain effort, excluding services not in active infrastructure.

Inputs:
  scripts/ado_stories.csv                              (domain, resource, policy_status, is_combined)
  data/outputs/v3_service_controls_reclassified.csv    (service_name, control_domain, applicability,
                                                         automation_class — Phase 37 output)

Output:
  data/outputs/effort_estimates_ns_filtered.csv

Excluded services (infra-confirmed absent):
  Batch, Communication Services, Communications Gateway, Container Apps,
  Digital Twins, HPC Cache, Machine Learning Service, Managed Lustre,
  Nutanix on Azure, Remote Rendering, SignalR Service, Spring Apps,
  Stack Edge, VMware Solution, Web PubSub
  + azure-netapp-files (no NS story; excluded from CSV match pool)

Effort table (Phase 37 calibrated):
  script_simple  + confirmed → 2h
  script_simple  + uncertain/none → 3h
  script_medium  + confirmed → 3h
  script_medium  + uncertain/none → 4h
  manual_only    + confirmed → 4h
  manual_only    + uncertain → 5h
  manual_only    + none → 7h
  not_applicable + any → 0.5h

Matching: story.resource → reclassified.service_name via rapidfuzz token_sort_ratio (threshold 60).
Zero-match fallback: script_medium + policy_status.

Usage:
  python3 scripts/estimate_effort_ns_filtered.py [--stories PATH] [--reclassified PATH] [--out PATH]
"""

import csv
import argparse
from pathlib import Path
from collections import Counter, defaultdict

ROOT             = Path(__file__).parent.parent
STORIES_CSV      = Path(__file__).parent / "ado_stories.csv"
RECLASSIFIED_CSV = ROOT / "data" / "outputs" / "v3_service_controls_reclassified.csv"
OUT_CSV          = ROOT / "data" / "outputs" / "effort_estimates_ns_filtered.csv"

# Services confirmed absent from infrastructure — skip these stories
EXCLUDED_RESOURCES = {
    "Batch",
    "Communication Services",
    "Communications Gateway",
    "Container Apps",
    "Digital Twins",
    "HPC Cache",
    "Machine Learning Service",
    "Managed Lustre",
    "Nutanix on Azure",
    "Remote Rendering",
    "SignalR Service",
    "Spring Apps",
    "Stack Edge",
    "VMware Solution",
    "Web PubSub",
}

# CSV service names to exclude from the match pool (no NS story or infra-absent)
EXCLUDED_CSV_SERVICES = {"azure-netapp-files"}

# Effort table (Phase 37 calibrated — refined from Phase 36)
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

TIEBREAK = ["script_medium", "script_simple", "manual_only", "not_applicable"]


def _normalise(name: str) -> str:
    noise = ["azure", "microsoft", "service", "services", "for", "the", "-"]
    n = name.lower().strip()
    for w in noise:
        n = n.replace(w, " ")
    return " ".join(n.split())


def fuzzy_match(resource: str, service_names: list[str], threshold: int = 60) -> str | None:
    try:
        from rapidfuzz import process, fuzz
    except ImportError:
        print("[WARN] rapidfuzz not installed — no fuzzy matching. Run: pip install rapidfuzz")
        return None
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
    return None


def dominant_automation_class(rows: list[dict]) -> str:
    """Majority automation_class among customer+shared rows; tie-break by TIEBREAK priority."""
    active = [r for r in rows if r.get("applicability") in ("customer", "shared")]
    if not active:
        return "manual_only"
    counts = Counter(r["automation_class"] for r in active)
    max_count = max(counts.values())
    top = [cls for cls, c in counts.items() if c == max_count]
    if len(top) == 1:
        return top[0]
    for cls in TIEBREAK:
        if cls in top:
            return cls
    return top[0]


def main(stories_path: str, reclassified_path: str, out_path: str) -> None:
    if not Path(stories_path).exists():
        print(f"[ERROR] {stories_path} not found. Run parse_stories.py first.")
        return
    if not Path(reclassified_path).exists():
        print(f"[ERROR] {reclassified_path} not found. Run reclassify_v3_controls.py first.")
        return

    with open(stories_path, newline="", encoding="utf-8") as f:
        all_stories = list(csv.DictReader(f))
    with open(reclassified_path, newline="", encoding="utf-8") as f:
        reclassified = list(csv.DictReader(f))

    # NS domain rows only, excluding known-absent services from match pool
    ns_rows = [
        r for r in reclassified
        if r.get("control_domain") == "Network Security"
        and r.get("service_name") not in EXCLUDED_CSV_SERVICES
    ]

    service_rows: dict[str, list[dict]] = defaultdict(list)
    for row in ns_rows:
        service_rows[row["service_name"]].append(row)
    ns_services = list(service_rows.keys())

    # NS stories only
    ns_stories = [s for s in all_stories if s.get("domain") == "NS"]

    estimates = []
    match_count   = 0
    fallback_count = 0
    excluded_count = 0

    for story in ns_stories:
        resource      = story.get("resource", "").strip()
        policy_status = story.get("policy_status", "none")
        is_combined   = story.get("is_combined", "False") == "True"
        story_id      = story.get("story_id", "")
        story_title   = story.get("story_title", "")

        # Extract control number from story_id (e.g. "NS-1" → "NS-1")
        # story_id format varies; try to derive from title prefix
        control_num = ""
        for part in story_id.split("-")[:2]:
            pass
        # Derive NS-N from story_id field directly
        sid_parts = story_id.upper().replace("[SEC-", "").replace("]", "").split()
        if sid_parts:
            control_num = sid_parts[0] if sid_parts[0].startswith("NS") else story_id

        excluded = resource in EXCLUDED_RESOURCES

        if excluded:
            excluded_count += 1
            estimates.append({
                "story_id":        story_id,
                "control_num":     control_num,
                "resource":        resource,
                "excluded":        "True",
                "matched_service": "",
                "automation_class": "",
                "policy_status":   policy_status,
                "hours":           0.0,
                "notes":           "excluded — not in active infrastructure",
            })
            continue

        # Match resource → NS service
        matched_service = fuzzy_match(resource, ns_services)
        auto_class      = None
        source          = ""

        if matched_service:
            rows       = service_rows[matched_service]
            auto_class = dominant_automation_class(rows)
            hours      = EFFORT.get((auto_class, policy_status), 4.0)
            source     = "v3_matched"
            match_count += 1
        else:
            auto_class = "script_medium"
            hours      = EFFORT.get((auto_class, policy_status), 4.0)
            source     = "fallback"
            fallback_count += 1

        estimates.append({
            "story_id":         story_id,
            "control_num":      control_num,
            "resource":         resource,
            "excluded":         "False",
            "matched_service":  matched_service or "",
            "automation_class": auto_class,
            "policy_status":    policy_status,
            "hours":            hours,
            "notes":            source,
        })

    # Write CSV
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(estimates[0].keys()) if estimates else [])
        writer.writeheader()
        writer.writerows(estimates)

    active    = [e for e in estimates if e["excluded"] == "False"]
    total_h   = sum(e["hours"] for e in active)

    # Per NS-N control breakdown using story_id prefix
    control_hours: dict[str, float] = defaultdict(float)
    control_count: dict[str, int]   = defaultdict(int)
    for e in active:
        sid = e["story_id"]
        # story_id like "NS-1" or "[SEC-1]..." — extract NS-N
        ckey = sid.split("]")[0].strip("[").strip() if "]" in sid else sid.split("-")[0] + "-" + sid.split("-")[1] if "-" in sid else sid
        control_hours[ckey] += e["hours"]
        control_count[ckey] += 1

    print(f"\n── Phase 39: NS Filtered Effort Estimate ─────────────────────")
    print(f"  Total NS stories   : {len(ns_stories)}")
    print(f"  Excluded (absent)  : {excluded_count} — {sorted(EXCLUDED_RESOURCES)}")
    print(f"  Active stories     : {len(active)}")
    print(f"  v3-matched         : {match_count}")
    print(f"  Fallback           : {fallback_count}")
    print(f"\n── Per-Control Breakdown ──────────────────────────────────────")
    print(f"{'Control':<10} {'Stories':>8} {'Hours':>8} {'Days':>8}")
    print("-" * 38)
    for ctrl in sorted(control_hours):
        h = control_hours[ctrl]
        print(f"{ctrl:<10} {control_count[ctrl]:>8} {h:>8.1f} {h/8:>8.1f}")
    print("-" * 38)
    print(f"{'NS TOTAL':<10} {len(active):>8} {total_h:>8.1f} {total_h/8:>8.1f}")
    print(f"\n→ {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 39: NS filtered effort estimate")
    parser.add_argument("--stories",      default=str(STORIES_CSV),      help="ado_stories.csv path")
    parser.add_argument("--reclassified", default=str(RECLASSIFIED_CSV), help="v3_service_controls_reclassified.csv path")
    parser.add_argument("--out",          default=str(OUT_CSV),           help="Output CSV path")
    args = parser.parse_args()
    main(args.stories, args.reclassified, args.out)
