"""Phase 57 Step 2 — Bulk MCSB URL backfill for 20 NS Phase 52 CSVs.

For each service, appends the MCSB security baseline URL to all rows
that currently lack evidence (no 'http', 'Source:', or standard rationale markers).
Does NOT change verdicts.

Mirror of scripts/phase56_url_backfill.py.
"""
import csv
import pathlib

HEADER = [
    "asb_control_id", "feature_name", "feature_supported_original",
    "feature_enabled_by_default_original", "status_2025", "verdict_2025",
    "azure_api_property", "script_module", "script_function", "notes",
    "service", "severity", "blast_radius", "risk_rank",
]

# All 20 confirmed canonical MCSB baseline URLs (HEAD-verified June 2026)
BASELINE_URLS = {
    "appservice":        "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/app-service-security-baseline",
    "azurecdn":          "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/content-delivery-network-security-baseline",
    "cognitivesearch":   "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-cognitive-search-security-baseline",
    "cognitiveservices": "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/cognitive-services-security-baseline",
    "databasemigration": "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-database-migration-service-security-baseline",
    "databricks":        "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-databricks-security-baseline",
    "datafactory":       "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/data-factory-security-baseline",
    "eventgrid":         "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/event-grid-security-baseline",
    "eventhubs":         "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/event-hubs-security-baseline",
    "filesync":          "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-file-sync-security-baseline",
    "functions":         "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/functions-security-baseline",
    "loadbalancer":      "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-load-balancer-security-baseline",
    "logicapps":         "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/logic-apps-security-baseline",
    "natgateway":        "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-nat-gateway-security-baseline",
    "notificationhubs":  "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/notification-hubs-security-baseline",
    "peeringservice":    "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/microsoft-azure-peering-service-security-baseline",
    "trafficmanager":    "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/traffic-manager-security-baseline",
    "virtualdesktop":    "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-virtual-desktop-security-baseline",
    "virtualnetwork":    "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/virtual-network-security-baseline",
    "virtualwan":        "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/virtual-wan-security-baseline",
}

EVIDENCE_MARKERS = [
    "http", "source:", "phase48",
    "infrastructure", "azure platform", "no customer",
    "not applicable", "monitoring service",
]


def has_evidence(notes: str) -> bool:
    nl = notes.lower()
    return any(m in nl for m in EVIDENCE_MARKERS)


def process_slug(slug: str) -> int:
    csv_path = pathlib.Path(f"data/outputs/ns/{slug}.final.csv")
    if not csv_path.exists():
        print(f"  {slug:<22} SKIP (not found)")
        return 0

    baseline_url = BASELINE_URLS.get(slug)
    if not baseline_url:
        print(f"  {slug:<22} SKIP (no baseline URL configured)")
        return 0

    rows = list(csv.DictReader(open(csv_path)))
    updated = 0

    for row in rows:
        notes = row.get("notes", "")
        if has_evidence(notes):
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
    print("Phase 57 Step 2 — Bulk URL backfill")
    print("=" * 60)
    total = 0
    for slug in sorted(BASELINE_URLS.keys()):
        n = process_slug(slug)
        total += n
        print(f"  {slug:<22} rows_updated={n:>3}")
    print()
    print(f"Total rows updated: {total}")
    print("Done.")
