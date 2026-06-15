"""
analyze_v3_controls.py
----------------------
Phases 30-32: Load v3 controls, classify relevance + automation feasibility,
then merge with user story policy coverage to produce effort estimates.

Inputs:
  data/inputs/mcsb_v3.xlsx
  scripts/ado_stories.csv  (must have policy_status from audit_policy_coverage.py)

Outputs:
  data/outputs/v3_controls.csv          Phase 30 — 85 v3 controls with relevance
  data/outputs/automation_classes.csv   Phase 31 — automation_class per control
  data/outputs/effort_estimates.csv     Phase 32 — hours per user story
  data/outputs/effort_summary.csv       Phase 32 — totals by domain

Automation classes:
  script_simple   — Azure Policy GUID present → query compliance state via CLI
  script_complex  — Policy mapping text present, no GUID → custom query needed
  manual_only     — No policy mapping → human review of config/docs required

Effort formula (hours):
  base = 1.0
  + 0.5  if policy_status == "none"         (manual audit, no policy check)
  + 0.5  if automation_class == "manual_only"
  + 1.0  if automation_class == "script_complex"
  - 0.25 if policy_status == "confirmed"    (automated check reduces effort)
  min = 0.5 hours per story

Usage:
  cd scripts/
  python3 analyze_v3_controls.py
"""

import csv
import re
import pandas as pd
from pathlib import Path

ROOT       = Path(__file__).parent.parent
XLSX_PATH  = ROOT / "data" / "inputs"  / "mcsb_v3.xlsx"
CSV_PATH   = Path(__file__).parent     / "ado_stories.csv"
OUT_DIR    = ROOT / "data" / "outputs"

# Map ASB ID prefix → our 2-letter domain code
DOMAIN_MAP = {
    "NS": "NS", "IM": "IM", "PA": "PA", "DP": "DP",
    "AM": "AM", "LT": "LT", "IR": "IR", "PV": "PV",
    "ES": "ES", "BR": "BR", "DS": "DS", "GS": "GS",
}


# ---------------------------------------------------------------------------
# Phase 30 — Load and tag v3 controls
# ---------------------------------------------------------------------------

def load_v3_controls() -> pd.DataFrame:
    df = pd.read_excel(XLSX_PATH, sheet_name="Azure Security Benchmark v3")
    df = df.rename(columns={
        "ASB ID":                           "asb_id",
        "Control Domain":                   "control_domain",
        "Recommendation":                   "recommendation",
        "Security Principle":               "security_principle",
        "Azure Guidance":                   "azure_guidance",
        "Azure Policy Mapping":             "policy_mapping",
        "Azure Policy GUID":                "policy_guid",
        "Implementation and additional context": "implementation_notes",
    })
    # Extract domain code from ASB ID (e.g. "NS-1" → "NS")
    df["domain_code"] = df["asb_id"].str.extract(r'^([A-Z]+)-')
    df["domain_code"] = df["domain_code"].map(DOMAIN_MAP).fillna("UNKNOWN")

    # Relevance: all v3.0 controls are active — flag any with deprecated signals
    deprecated_signals = ["deprecated", "not applicable", "n/a", "removed"]
    def _relevance(row):
        text = " ".join([
            str(row.get("recommendation", "")),
            str(row.get("security_principle", "")),
        ]).lower()
        if any(s in text for s in deprecated_signals):
            return "deprecated"
        return "active"

    df["relevance"] = df.apply(_relevance, axis=1)
    return df


# ---------------------------------------------------------------------------
# Phase 31 — Automation feasibility classification
# ---------------------------------------------------------------------------

def classify_automation(df: pd.DataFrame) -> pd.DataFrame:
    def _classify(row):
        has_guid    = pd.notna(row.get("policy_guid"))    and str(row.get("policy_guid",    "")).strip() not in ("", "nan")
        has_mapping = pd.notna(row.get("policy_mapping")) and str(row.get("policy_mapping", "")).strip() not in ("", "nan")
        if has_guid:
            return "script_simple"
        if has_mapping:
            return "script_complex"
        return "manual_only"

    df["automation_class"] = df.apply(_classify, axis=1)
    return df


# ---------------------------------------------------------------------------
# Phase 32 — Effort estimation per user story
# ---------------------------------------------------------------------------

# Industry-calibrated: 4-6h/control avg (Qwen3 benchmark research, Phase 33)
# base=3.0 + modifiers → produces ~640h total (vs initial 152h which was 4-6x low)
EFFORT_FORMULA = {
    # (policy_status, automation_class) → hours
    ("none",      "manual_only"):    7.0,   # full manual audit + docs
    ("none",      "script_complex"): 5.0,   # manual + partial tooling
    ("none",      "script_simple"):  4.0,   # policy check exists but unconfirmed
    ("uncertain", "manual_only"):    5.0,
    ("uncertain", "script_complex"): 4.0,
    ("uncertain", "script_simple"):  3.0,
    ("confirmed", "manual_only"):    4.0,
    ("confirmed", "script_complex"): 3.0,
    ("confirmed", "script_simple"):  2.0,   # automated check + review only
}


def estimate_effort(stories: list[dict], ctrl_df: pd.DataFrame) -> list[dict]:
    # Build lookup: domain_code → median automation_class (most common)
    from collections import Counter
    domain_auto_class: dict[str, str] = {}
    for domain in DOMAIN_MAP:
        domain_rows = ctrl_df[ctrl_df["domain_code"] == domain]
        if domain_rows.empty:
            domain_auto_class[domain] = "manual_only"
        else:
            counts = Counter(domain_rows["automation_class"])
            domain_auto_class[domain] = counts.most_common(1)[0][0]

    estimates = []
    for story in stories:
        domain          = story.get("domain", "")
        policy_status   = story.get("policy_status", "none")
        auto_class      = domain_auto_class.get(domain, "manual_only")
        hours           = EFFORT_FORMULA.get((policy_status, auto_class), 1.0)

        estimates.append({
            "domain":           domain,
            "story_id":         story.get("story_id", ""),
            "story_title":      story.get("story_title", "")[:60],
            "policy_status":    policy_status,
            "automation_class": auto_class,
            "estimated_hours":  hours,
        })
    return estimates


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # ── Phase 30 ─────────────────────────────────────────────────────────────
    print("Phase 30 — Loading v3 controls...")
    df = load_v3_controls()
    print(f"  {len(df)} controls loaded. Domains: {df['domain_code'].value_counts().to_dict()}")
    print(f"  Relevance: {df['relevance'].value_counts().to_dict()}")

    # ── Phase 31 ─────────────────────────────────────────────────────────────
    print("\nPhase 31 — Classifying automation feasibility...")
    df = classify_automation(df)
    print(f"  Automation classes: {df['automation_class'].value_counts().to_dict()}")

    # Save v3 controls CSV
    v3_out = OUT_DIR / "v3_controls.csv"
    df[["asb_id","domain_code","control_domain","recommendation","relevance","automation_class",
        "policy_mapping","policy_guid"]].to_csv(v3_out, index=False)
    print(f"  → {v3_out}")

    # Domain-level automation summary
    auto_out = OUT_DIR / "automation_classes.csv"
    summary = df.groupby(["domain_code","automation_class"]).size().reset_index(name="count")
    summary.to_csv(auto_out, index=False)
    print(f"  → {auto_out}")

    # ── Phase 32 ─────────────────────────────────────────────────────────────
    print("\nPhase 32 — Estimating effort per user story...")
    if not CSV_PATH.exists():
        print(f"  [ERROR] {CSV_PATH} not found. Run parse_stories.py + audit_policy_coverage.py first.")
        return

    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        stories = list(csv.DictReader(f))

    if "policy_status" not in stories[0]:
        print("  [ERROR] policy_status column missing. Run audit_policy_coverage.py first.")
        return

    estimates = estimate_effort(stories, df)
    total_hours = sum(e["estimated_hours"] for e in estimates)

    effort_path = OUT_DIR / "effort_estimates.csv"
    with open(effort_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(estimates[0].keys()))
        writer.writeheader()
        writer.writerows(estimates)
    print(f"  → {effort_path}")

    # Domain summary
    from collections import defaultdict
    domain_totals: dict[str, float] = defaultdict(float)
    domain_counts: dict[str, int]   = defaultdict(int)
    for e in estimates:
        domain_totals[e["domain"]] += e["estimated_hours"]
        domain_counts[e["domain"]] += 1

    print("\n── Effort Summary by Domain ──────────────────────────────────")
    print(f"{'Domain':<6} {'Stories':>8} {'Hours':>8} {'Days(8h)':>10}")
    print("-" * 36)
    for domain in sorted(domain_totals):
        h = domain_totals[domain]
        print(f"{domain:<6} {domain_counts[domain]:>8} {h:>8.1f} {h/8:>10.1f}")
    print("-" * 36)
    print(f"{'TOTAL':<6} {len(estimates):>8} {total_hours:>8.1f} {total_hours/8:>10.1f}")

    summary_path = OUT_DIR / "effort_summary.csv"
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["domain","stories","hours","days_8h"])
        writer.writeheader()
        for domain in sorted(domain_totals):
            writer.writerow({
                "domain":   domain,
                "stories":  domain_counts[domain],
                "hours":    round(domain_totals[domain], 1),
                "days_8h":  round(domain_totals[domain] / 8, 1),
            })
        writer.writerow({
            "domain": "TOTAL", "stories": len(estimates),
            "hours": round(total_hours, 1), "days_8h": round(total_hours / 8, 1),
        })
    print(f"\n→ {summary_path}")


if __name__ == "__main__":
    main()
