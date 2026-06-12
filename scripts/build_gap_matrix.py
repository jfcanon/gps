#!/usr/bin/env python3
"""
Join all coverage sources against master_controls.csv → gap_matrix.csv.

Inputs:
  data/outputs/master_controls.csv       (unified MCSB control list ~162 rows)
  data/outputs/optive_coverage.csv       (from parse_optive_csv.py)
  data/outputs/az_policy_coverage.csv   (from parse_az_policy.py)
  data/outputs/az_defender_coverage.csv (from parse_az_defender.py)
  data/outputs/ado_coverage.csv         (from parse_ado_export.py)

Outputs:
  data/outputs/gap_matrix.csv           (all controls with coverage flags)
  data/outputs/ado_items_to_create.csv  (GAP rows only, with ADO field stubs)

Run order:
  1. fetch_mcsb_v2.py
  2. load_mcsb_v3.py
  3. map_v3_to_v2_domains.py
  4. build_master_controls.py
  5. parse_optive_csv.py
  6. parse_az_policy.py
  7. parse_az_defender.py
  8. parse_ado_export.py
  9. build_gap_matrix.py  ← this script
"""

import sys
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).parent.parent
OUTPUT_DIR = ROOT / "data" / "outputs"

MASTER_FILE = OUTPUT_DIR / "master_controls.csv"
OPTIVE_FILE = OUTPUT_DIR / "optive_coverage.csv"
POLICY_FILE = OUTPUT_DIR / "az_policy_coverage.csv"
DEFENDER_FILE = OUTPUT_DIR / "az_defender_coverage.csv"
ADO_FILE = OUTPUT_DIR / "ado_coverage.csv"

GAP_MATRIX_FILE = OUTPUT_DIR / "gap_matrix.csv"
ADO_ITEMS_FILE = OUTPUT_DIR / "ado_items_to_create.csv"

SEVERITY_WEIGHT = {"High": 3.0, "Medium": 2.0, "Low": 1.0}
COVERAGE_SCORE = {"COVERED": 1.0, "PARTIAL": 0.5, "UNKNOWN": 0.3, "GAP": 0.0}

FEATURE_MAP = {
    "NS": "[SEC-NS-F",
    "IM": "[SEC-IM-F",
    "PA": "[SEC-PA-F",
    "DP": "[SEC-DP-F",
    "AM": "[SEC-AM-F",
    "LT": "[SEC-LT-F",
    "IR": "[SEC-IR-F",
    "PV": "[SEC-PV-F",
    "ES": "[SEC-ES-F",
    "BR": "[SEC-BR-F",
    "DS": "[SEC-DS-F",
    "GS": "[SEC-GS-F",
}

EPIC_TITLES = {
    "NS": "[SEC] Network Security Controls — MCSB v2",
    "IM": "[SEC] Identity Management Controls — MCSB v2",
    "PA": "[SEC] Privileged Access Controls — MCSB v2",
    "DP": "[SEC] Data Protection Controls — MCSB v2",
    "AM": "[SEC] Asset Management Controls — MCSB v2",
    "LT": "[SEC] Logging and Threat Detection Controls — MCSB v2",
    "IR": "[SEC] Incident Response Controls — MCSB v2",
    "PV": "[SEC] Posture and Vulnerability Management — MCSB v2",
    "ES": "[SEC] Endpoint Security Controls — MCSB v2",
    "BR": "[SEC] Backup and Recovery Controls — MCSB v2",
    "DS": "[SEC] DevOps Security Controls — MCSB v2",
    "GS": "[SEC] Governance and Strategy Controls — MCSB v2",
}

STORY_POINTS_MATRIX = {
    ("Automated", "High"): 3,
    ("Automated", "Medium"): 2,
    ("Automated", "Low"): 1,
    ("Manual", "High"): 8,
    ("Manual", "Medium"): 5,
    ("Manual", "Low"): 3,
    ("Hybrid", "High"): 5,
    ("Hybrid", "Medium"): 3,
    ("Hybrid", "Low"): 2,
}


def compute_gap_status(row: pd.Series) -> str:
    covered = sum([
        str(row.get("optive_covered", "")).strip() == "Covered",
        str(row.get("az_policy_covered", "")).strip() == "Enforced",
        str(row.get("defender_covered", "")).strip() == "Covered",
        str(row.get("ado_covered", "")).strip() in ("Covered", "In Progress"),
    ])
    partial = sum([
        str(row.get("optive_covered", "")).strip() == "Partial",
        str(row.get("az_policy_covered", "")).strip() == "Audit",
        str(row.get("ado_covered", "")).strip() == "Likely",
    ])
    unknown = sum([
        str(row.get(col, "")).strip() in ("Unknown", "")
        for col in ["optive_covered", "az_policy_covered", "defender_covered", "ado_covered"]
    ])

    if covered >= 2:
        return "COVERED"
    elif covered == 1 or partial >= 1:
        return "PARTIAL"
    elif unknown >= 4:
        return "UNKNOWN"
    else:
        return "GAP"


def score_priority(row: pd.Series) -> float:
    sev = SEVERITY_WEIGHT.get(str(row.get("severity", "Medium")), 2.0)
    cov = COVERAGE_SCORE.get(str(row.get("gap_status", "UNKNOWN")), 0.3)
    return round(sev * (1.0 - cov), 2)


def build_ado_story_title(row: pd.Series) -> str:
    uid = row.get("unified_id", "")
    domain = row.get("domain_code", "")
    title = row.get("control_title", "Unknown Control")
    resource = row.get("v3_resource", "")

    if resource and str(resource) != "nan" and row.get("source") == "v3":
        return f"[SEC-{domain}-{uid}] {title} — {resource}"
    return f"[SEC-{domain}-{uid}] {title}"


def story_points(row: pd.Series) -> int:
    impl = str(row.get("implementation_type", "Hybrid"))
    sev = str(row.get("severity", "Medium"))
    return STORY_POINTS_MATRIX.get((impl, sev), STORY_POINTS_MATRIX.get(("Hybrid", sev), 3))


def load_optional(path: Path, label: str) -> pd.DataFrame | None:
    if path.exists():
        df = pd.read_csv(path)
        print(f"  Loaded {label}: {len(df)} rows")
        return df
    print(f"  MISSING {label}: {path.name} — coverage will show Unknown")
    return None


def join_optive(master: pd.DataFrame, optive: pd.DataFrame | None) -> pd.DataFrame:
    if optive is None:
        master["optive_covered"] = "Unknown"
        master["optive_notes"] = ""
        return master
    # Join on v3_control_id (v3 controls) and control title (v2 controls)
    optive_map = optive.set_index("v3_control_id")[["optive_status", "optive_notes"]].to_dict(orient="index")

    def get_optive_status(row):
        v3_id = str(row.get("v3_control_id", "")).strip()
        if v3_id and v3_id in optive_map:
            return optive_map[v3_id]["optive_status"], optive_map[v3_id]["optive_notes"]
        return "Unknown", ""

    statuses = master.apply(lambda r: pd.Series(get_optive_status(r)), axis=1)
    master["optive_covered"] = statuses[0]
    master["optive_notes"] = statuses[1]
    return master


def join_policy(master: pd.DataFrame, policy: pd.DataFrame | None) -> pd.DataFrame:
    if policy is None:
        master["az_policy_covered"] = "Unknown"
        return master

    # Aggregate policy coverage by domain: if any Enforced policy in domain → mark domain as having policy coverage
    domain_policy_status = {}
    for domain in master["domain_code"].unique():
        domain_policies = policy[policy["guessed_domain"] == domain]
        if domain_policies.empty:
            domain_policy_status[domain] = "Unknown"
        elif (domain_policies["enforcement_normalized"] == "Enforced").any():
            domain_policy_status[domain] = "Enforced"
        elif (domain_policies["enforcement_normalized"] == "Audit").any():
            domain_policy_status[domain] = "Audit"
        else:
            domain_policy_status[domain] = "Not Configured"

    master["az_policy_covered"] = master["domain_code"].map(domain_policy_status).fillna("Unknown")
    return master


def join_defender(master: pd.DataFrame, defender: pd.DataFrame | None) -> pd.DataFrame:
    if defender is None:
        master["defender_covered"] = "Unknown"
        return master

    # Aggregate defender coverage by domain
    domain_defender_status = {}
    for domain in master["domain_code"].unique():
        domain_recs = defender[defender["guessed_domain"] == domain]
        if domain_recs.empty:
            domain_defender_status[domain] = "Unknown"
        else:
            covered_count = (domain_recs["defender_covered"] == "Covered").sum()
            total = len(domain_recs)
            ratio = covered_count / total if total > 0 else 0
            if ratio >= 0.7:
                domain_defender_status[domain] = "Covered"
            elif ratio >= 0.3:
                domain_defender_status[domain] = "Partial"
            else:
                domain_defender_status[domain] = "Not Covered"

    master["defender_covered"] = master["domain_code"].map(domain_defender_status).fillna("Unknown")
    return master


def join_ado(master: pd.DataFrame, ado: pd.DataFrame | None) -> pd.DataFrame:
    if ado is None:
        master["ado_covered"] = "Unknown"
        master["ado_item_id"] = ""
        master["ado_match_confidence"] = "None"
        return master

    ado_high = ado[ado["match_confidence"] == "High"]
    ado_medium = ado[ado["match_confidence"] == "Medium"]

    covered_ids = set(ado_high["matched_unified_id"].dropna())
    likely_ids = set(ado_medium["matched_unified_id"].dropna())

    id_to_ado_item = {}
    for _, row in ado_high.iterrows():
        uid = row.get("matched_unified_id", "")
        if uid:
            id_to_ado_item[uid] = (row.get("ado_item_id", ""), "High")
    for _, row in ado_medium.iterrows():
        uid = row.get("matched_unified_id", "")
        if uid and uid not in id_to_ado_item:
            id_to_ado_item[uid] = (row.get("ado_item_id", ""), "Medium")

    def get_ado_coverage(uid):
        if uid in covered_ids:
            return "Covered", id_to_ado_item.get(uid, ("", "High"))[0], "High"
        elif uid in likely_ids:
            return "Likely", id_to_ado_item.get(uid, ("", "Medium"))[0], "Medium"
        return "Not Found", "", "None"

    results = master["unified_id"].apply(lambda uid: pd.Series(get_ado_coverage(uid)))
    master["ado_covered"] = results[0]
    master["ado_item_id"] = results[1]
    master["ado_match_confidence"] = results[2]
    return master


def build_ado_items_csv(gap_df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in gap_df.iterrows():
        domain = str(row.get("domain_code", ""))
        rows.append({
            "unified_id": row.get("unified_id", ""),
            "domain_code": domain,
            "domain_name": row.get("domain_name", ""),
            "control_title": row.get("control_title", ""),
            "severity": row.get("severity", ""),
            "implementation_type": row.get("implementation_type", ""),
            "source": row.get("source", ""),
            "v2_control_id": row.get("v2_control_id", ""),
            "v3_resource": row.get("v3_resource", ""),
            "gap_status": row.get("gap_status", ""),
            "priority_score": row.get("priority_score", ""),
            "ado_epic_title": EPIC_TITLES.get(domain, f"[SEC] {domain} Controls — MCSB v2"),
            "ado_story_title": build_ado_story_title(row),
            "story_points": story_points(row),
            "tags": f"MCSB-v2; {domain}; {row.get('source', 'v2')}; {row.get('severity', 'Medium')}; gap-assessment",
            "description_stub": f"MCSB control {row.get('unified_id', '')} — {row.get('control_title', '')}. "
                                 f"Domain: {domain}. Severity: {row.get('severity', '')}. "
                                 f"Source: {row.get('source', '')}. Gap status: {row.get('gap_status', '')}.",
        })
    return pd.DataFrame(rows)


def main():
    if not MASTER_FILE.exists():
        print(f"ERROR: master_controls.csv not found. Run build_master_controls.py first.")
        sys.exit(1)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading inputs...")
    master = pd.read_csv(MASTER_FILE)
    print(f"  Master controls: {len(master)} rows")

    optive = load_optional(OPTIVE_FILE, "Optive coverage")
    policy = load_optional(POLICY_FILE, "Az Policy coverage")
    defender = load_optional(DEFENDER_FILE, "Az Defender coverage")
    ado = load_optional(ADO_FILE, "ADO coverage")

    print("\nJoining sources...")
    master = join_optive(master, optive)
    master = join_policy(master, policy)
    master = join_defender(master, defender)
    master = join_ado(master, ado)

    print("Computing gap status and priority scores...")
    master["gap_status"] = master.apply(compute_gap_status, axis=1)
    master["priority_score"] = master.apply(score_priority, axis=1)

    # Sort by priority (highest first)
    master = master.sort_values("priority_score", ascending=False)

    master.to_csv(GAP_MATRIX_FILE, index=False)
    print(f"\nWrote gap_matrix.csv: {len(master)} rows → {GAP_MATRIX_FILE}")

    # Gap status summary
    status_counts = master["gap_status"].value_counts()
    print(f"\nGap status summary:\n{status_counts.to_string()}")

    # Generate ADO items for GAP rows only
    gap_rows = master[master["gap_status"] == "GAP"].copy()
    partial_rows = master[master["gap_status"] == "PARTIAL"].copy()

    print(f"\nGAP controls (new ADO items needed): {len(gap_rows)}")
    print(f"PARTIAL controls (existing items to enrich): {len(partial_rows)}")

    if len(gap_rows) > 0:
        ado_items = build_ado_items_csv(gap_rows)
        ado_items = ado_items.sort_values("priority_score", ascending=False)
        ado_items.to_csv(ADO_ITEMS_FILE, index=False)
        print(f"\nWrote {len(ado_items)} ADO items to create → {ADO_ITEMS_FILE}")
        print(f"Top 5 priority gaps:")
        for _, r in ado_items.head(5).iterrows():
            print(f"  [{r['domain_code']}] {r['control_title']} (score={r['priority_score']}, {r['severity']})")
    else:
        print("\nNo GAP controls found — all controls have some coverage.")


if __name__ == "__main__":
    main()
