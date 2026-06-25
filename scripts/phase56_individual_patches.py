"""Phase 56 Step 2 — Individual row patches.

Handles rows that bulk backfill skipped (has_evidence=True from Phase48-cache
or already in INDIVIDUAL_PATCH_ROWS exclusion set) but still need MCSB baseline URL.
Also flips azuredns PA-7 from conditional → now_applicable_native per Q1-B evidence.
"""
import csv
import pathlib

HEADER = [
    "asb_control_id", "feature_name", "feature_supported_original",
    "feature_enabled_by_default_original", "status_2025", "verdict_2025",
    "azure_api_property", "script_module", "script_function", "notes",
    "service", "severity", "blast_radius", "risk_rank",
]

BASELINE_URLS = {
    "appgateway":     "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/application-gateway-security-baseline",
    "servicebus":     "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/service-bus-security-baseline",
    "ddosprotection": "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-ddos-protection-security-baseline",
    "vpngateway":     "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/vpn-gateway-security-baseline",
    "azuredns":       "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-dns-security-baseline",
    "frontdoor":      "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-front-door-security-baseline",
}

SEVERITY_SCORE = {"High": 3, "Medium": 2, "Low": 1}
BLAST_SCORE = {"Wide": 2, "Narrow": 1}


def recompute_risk(row: dict) -> str:
    sev = SEVERITY_SCORE.get(row.get("severity", ""), 0)
    blast = BLAST_SCORE.get(row.get("blast_radius", ""), 0)
    return str(sev * blast) if sev and blast else row.get("risk_rank", "")


def compute_blast(row: dict) -> str:
    verdict = row.get("verdict_2025", "")
    prop = row.get("azure_api_property", "")
    default_off = row.get("feature_enabled_by_default_original", "").strip() == "False"
    if verdict == "conditional" or not prop or prop.strip() in ("", "N/A") or default_off:
        return "Wide"
    return "Narrow"


# Individual patches: (slug, ctrl, feat_exact_or_fragment, append_note, new_verdict)
# new_verdict=None means keep existing verdict
PATCHES = [
    # appgateway PV-3/PV-5 — already have Phase48-cache note, add MCSB URL
    {
        "slug": "appgateway", "ctrl": "PV-3", "feat": "Azure Automation State Configuration",
        "append": " | MCSB v3 baseline confirmed still_not_applicable: {url}",
        "new_verdict": None,
    },
    {
        "slug": "appgateway", "ctrl": "PV-3", "feat": "Azure Policy Guest Configuration Agent",
        "append": " | MCSB v3 baseline confirmed still_not_applicable: {url}",
        "new_verdict": None,
    },
    {
        "slug": "appgateway", "ctrl": "PV-3", "feat": "Custom Container Images",
        "append": " | MCSB v3 baseline confirmed still_not_applicable: {url}",
        "new_verdict": None,
    },
    {
        "slug": "appgateway", "ctrl": "PV-3", "feat": "Custom VM Images",
        "append": " | MCSB v3 baseline confirmed still_not_applicable: {url}",
        "new_verdict": None,
    },
    {
        "slug": "appgateway", "ctrl": "PV-5", "feat": "Vulnerability Assessment using Microsoft Defender",
        "append": " | MCSB v3 baseline confirmed still_not_applicable: {url}",
        "new_verdict": None,
    },
    # appgateway IM-3 SP — still_not_applicable + URL
    {
        "slug": "appgateway", "ctrl": "IM-3", "feat": "Use Azure AD Service Principals",
        "append": " | MCSB v3 baseline: feature_supported=False for per-gateway SP. Source: {url}",
        "new_verdict": None,
    },
    # servicebus PV-3/PV-5 — add MCSB URL to Phase48-cache notes
    {
        "slug": "servicebus", "ctrl": "PV-3", "feat": "Azure Automation State Configuration",
        "append": " | MCSB v3 baseline confirmed still_not_applicable: {url}",
        "new_verdict": None,
    },
    {
        "slug": "servicebus", "ctrl": "PV-3", "feat": "Azure Policy Guest Configuration Agent",
        "append": " | MCSB v3 baseline confirmed still_not_applicable: {url}",
        "new_verdict": None,
    },
    {
        "slug": "servicebus", "ctrl": "PV-3", "feat": "Custom Container Images",
        "append": " | MCSB v3 baseline confirmed still_not_applicable: {url}",
        "new_verdict": None,
    },
    {
        "slug": "servicebus", "ctrl": "PV-3", "feat": "Custom VM Images",
        "append": " | MCSB v3 baseline confirmed still_not_applicable: {url}",
        "new_verdict": None,
    },
    {
        "slug": "servicebus", "ctrl": "PV-5", "feat": "Vulnerability Assessment using Microsoft Defender",
        "append": " | MCSB v3 baseline confirmed still_not_applicable: {url}",
        "new_verdict": None,
    },
    # ddosprotection DP-3 — confirm no data plane, add URL
    {
        "slug": "ddosprotection", "ctrl": "DP-3", "feat": "Data in Transit Encryption",
        "append": " | MCSB v3 baseline: feature_supported=False (no data plane). Source: {url}",
        "new_verdict": None,
    },
    # vpngateway IM-7 — conditional CA for P2S+AAD, add URL
    {
        "slug": "vpngateway", "ctrl": "IM-7", "feat": "Conditional Access for Data Plane",
        "append": " | Source: {url}",
        "new_verdict": None,
    },
    # vpngateway PA-7 — implemented, add URL
    {
        "slug": "vpngateway", "ctrl": "PA-7", "feat": "Azure RBAC for Data Plane",
        "append": " | Source: {url}",
        "new_verdict": None,
    },
    # azuredns PA-7 — flip conditional → now_applicable_native per Q1-B evidence
    # Exa June 2026: "RBAC at subscription/RG/zone/recordset granularity all GA — fully supported"
    {
        "slug": "azuredns", "ctrl": "PA-7", "feat": "Limit Access via RBAC",
        "append": " | Q1-B June 2026 confirmed: DNS Zone RBAC fully GA (zone/recordset granularity). Source: {url}",
        "new_verdict": "now_applicable_native",
    },
    # frontdoor PA-7 — conditional (management RBAC), add URL
    {
        "slug": "frontdoor", "ctrl": "PA-7", "feat": "Limit Access via RBAC",
        "append": " | Source: {url}",
        "new_verdict": None,
    },
]


def apply_patches_to_slug(slug: str, patches: list) -> int:
    csv_path = pathlib.Path(f"data/outputs/ns/{slug}.final.csv")
    if not csv_path.exists():
        print(f"  {slug}: file not found, skip")
        return 0

    url = BASELINE_URLS.get(slug, "")
    rows = list(csv.DictReader(open(csv_path)))
    updated = 0

    for row in rows:
        ctrl = row["asb_control_id"].strip()
        feat = row["feature_name"]
        notes = row.get("notes", "")

        for patch in patches:
            if patch["slug"] != slug:
                continue
            if ctrl != patch["ctrl"]:
                continue
            if patch["feat"].lower() not in feat.lower():
                continue

            append_text = patch["append"].replace("{url}", url)
            row["notes"] = notes.rstrip() + append_text

            if patch["new_verdict"] is not None:
                old_verdict = row["verdict_2025"]
                row["verdict_2025"] = patch["new_verdict"]
                row["blast_radius"] = compute_blast(row)
                row["risk_rank"] = recompute_risk(row)
                print(f"  FLIP {slug} {ctrl} '{feat[:40]}': {old_verdict} → {patch['new_verdict']}")

            updated += 1
            break

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        for row in rows:
            writer.writerow([row.get(h, "") for h in HEADER])

    return updated


if __name__ == "__main__":
    print("=" * 60)
    print("Phase 56 Step 2 — Individual row patches")
    print("=" * 60)

    slugs = sorted(set(p["slug"] for p in PATCHES))
    total = 0
    for slug in slugs:
        slug_patches = [p for p in PATCHES if p["slug"] == slug]
        n = apply_patches_to_slug(slug, slug_patches)
        total += n
        print(f"  {slug:<22} patches_applied={n:>3}")

    print()
    print(f"Total patches applied: {total}")
    print("Done.")
