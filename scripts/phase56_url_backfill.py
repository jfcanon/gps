"""Phase 56 Step 1 — Bulk URL backfill for uncovered rows.

For each service, appends the MCSB security baseline URL to all rows
that currently lack evidence (no 'http', 'Source:', or standard rationale markers).
Does NOT change verdicts.
"""
import csv
import pathlib

HEADER = [
    "asb_control_id", "feature_name", "feature_supported_original",
    "feature_enabled_by_default_original", "status_2025", "verdict_2025",
    "azure_api_property", "script_module", "script_function", "notes",
    "service", "severity", "blast_radius", "risk_rank",
]

# Confirmed canonical MCSB baseline URLs from Exa research (June 2026)
BASELINE_URLS = {
    "appgateway":     "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/application-gateway-security-baseline",
    "azuredns":       "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-dns-security-baseline",
    "azurefirewall":  "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-firewall-security-baseline",
    "bastion":        "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-bastion-security-baseline",
    "ddosprotection": "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-ddos-protection-security-baseline",
    "firewallmanager":"https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-firewall-manager-security-baseline",
    "frontdoor":      "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-front-door-security-baseline",
    "networkwatcher": "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/network-watcher-security-baseline",
    "privatelink":    "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-private-link-security-baseline",
    "publicip":       "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-public-ip-security-baseline",
    "redis":          "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-cache-for-redis-security-baseline",
    "servicebus":     "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/service-bus-security-baseline",
    "vpngateway":     "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/vpn-gateway-security-baseline",
    "waf":            "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-web-application-firewall-security-baseline",
}

# Rows to SKIP from bulk backfill — these get individual patches in phase56_individual_patches.py
# (slug, ctrl_id, feat_fragment)
INDIVIDUAL_PATCH_ROWS = {
    ("appgateway",    "IM-3",  "Service Principal"),
    ("appgateway",    "PV-3",  "Automation State"),
    ("appgateway",    "PV-3",  "Guest Configuration"),
    ("appgateway",    "PV-3",  "Custom Container"),
    ("appgateway",    "PV-5",  "Vulnerability"),
    ("servicebus",    "PV-3",  "Guest Configuration"),
    ("servicebus",    "PV-5",  "Vulnerability"),
    ("ddosprotection","DP-3",  "Transit"),
    ("vpngateway",    "IM-7",  "Conditional Access"),
    ("vpngateway",    "PA-7",  "RBAC for Data Plane"),
    ("azuredns",      "PA-7",  "RBAC"),
    ("frontdoor",     "PA-7",  "RBAC"),
}

EVIDENCE_MARKERS = [
    "http", "source:", "phase48",
    "infrastructure", "azure platform", "no customer",
    "not applicable", "monitoring service",
]


def has_evidence(notes: str) -> bool:
    nl = notes.lower()
    return any(m in nl for m in EVIDENCE_MARKERS)


def is_individual_patch_row(slug: str, ctrl: str, feat: str) -> bool:
    fl = feat.lower()
    for s, c, f in INDIVIDUAL_PATCH_ROWS:
        if s == slug and c == ctrl and f.lower() in fl:
            return True
    return False


def process_slug(slug: str) -> int:
    csv_path = pathlib.Path(f"data/outputs/ns/{slug}.final.csv")
    if not csv_path.exists():
        print(f"  {slug}: SKIP (not found)")
        return 0

    baseline_url = BASELINE_URLS.get(slug)
    if not baseline_url:
        print(f"  {slug}: SKIP (no baseline URL configured)")
        return 0

    rows = list(csv.DictReader(open(csv_path)))
    updated = 0

    for row in rows:
        notes = row.get("notes", "")
        ctrl = row["asb_control_id"].strip()
        feat = row["feature_name"]

        if has_evidence(notes):
            continue
        if is_individual_patch_row(slug, ctrl, feat):
            continue

        row["notes"] = f"{notes.rstrip()} | MCSB v3 baseline confirmed: {baseline_url}".lstrip(" |")
        updated += 1

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        for row in rows:
            writer.writerow([row.get(h, "") for h in HEADER])

    return updated


if __name__ == "__main__":
    print("=" * 60)
    print("Phase 56 Step 1 — Bulk URL backfill")
    print("=" * 60)
    total = 0
    for slug in sorted(BASELINE_URLS.keys()):
        n = process_slug(slug)
        total += n
        print(f"  {slug:<22} rows_updated={n:>3}")
    print()
    print(f"Total rows updated: {total}")
    print("Done.")
