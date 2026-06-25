"""Phase 58 — Per-row evidence enrichment for 20 NS CSVs.

Q1-A: Append specific ARM property + source URL to now_applicable_native rows
      (10 NS-2 Private Link services + 4 IM-7 Conditional Access services).
Q1-B: Append conditional logic notes to azurecdn conditional rows.
Q1-C: filesync NS-2 flip still_not_applicable → now_applicable_native (GA confirmed).
      notificationhubs NS-1 note appended (Private Link preview, not GA).
Dedup: Remove duplicate NS-2 Azure Private Link row from appservice (keep first).
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
    "appservice":        "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/app-service-security-baseline",
    "azurecdn":          "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/content-delivery-network-security-baseline",
    "cognitivesearch":   "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-cognitive-search-security-baseline",
    "cognitiveservices": "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/cognitive-services-security-baseline",
    "databasemigration": "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/database-migration-service-security-baseline",
    "databricks":        "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-databricks-security-baseline",
    "datafactory":       "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/data-factory-security-baseline",
    "eventgrid":         "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/event-grid-security-baseline",
    "eventhubs":         "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/event-hubs-security-baseline",
    "filesync":          "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-file-sync-security-baseline",
    "functions":         "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/functions-security-baseline",
    "loadbalancer":      "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/load-balancer-security-baseline",
    "logicapps":         "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/logic-apps-security-baseline",
    "natgateway":        "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-nat-gateway-security-baseline",
    "notificationhubs":  "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/notification-hubs-security-baseline",
    "peeringservice":    "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/microsoft-azure-peering-service-security-baseline",
    "trafficmanager":    "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/traffic-manager-security-baseline",
    "virtualdesktop":    "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-virtual-desktop-security-baseline",
    "virtualnetwork":    "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/virtual-network-security-baseline",
    "virtualwan":        "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/virtual-wan-security-baseline",
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


# Each patch: slug, ctrl, feat fragment (case-insensitive match), append text,
# new_verdict (None = keep existing), idem_key (skip if already in notes).
PATCHES = [
    # ── Q1-A: NS-2 Private Link — 10 services ──────────────────────────────
    {
        "slug": "appservice", "ctrl": "NS-2", "feat": "azure private link",
        "append": (
            " | ARM: Microsoft.Web/sites/privateEndpointConnections (API 2024-11-01);"
            " disable public access via properties.publicNetworkAccess=Disabled."
            " Customer creates private endpoint in target VNet; App Service assigns private IP."
            " Source: https://learn.microsoft.com/en-us/azure/app-service/overview-private-endpoint"
        ),
        "new_verdict": None,
        "idem_key": "overview-private-endpoint",
    },
    {
        "slug": "databricks", "ctrl": "NS-2", "feat": "azure private link",
        "append": (
            " | ARM: Microsoft.Databricks/workspaces/privateEndpointConnections;"
            " disable public access via workspace publicNetworkAccess=Disabled."
            " Supports both front-end (user→workspace) and back-end (workspace→data) private link."
            " Source: https://learn.microsoft.com/en-us/azure/databricks/security/network/concepts/private-link"
        ),
        "new_verdict": None,
        "idem_key": "databricks/security/network/concepts/private-link",
    },
    {
        "slug": "datafactory", "ctrl": "NS-2", "feat": "azure private link",
        "append": (
            " | ARM: Microsoft.DataFactory/factories/privateEndpointConnections;"
            " managed VNet with managed private endpoints isolates ADF pipeline execution."
            " Factory publicNetworkAccess property controls internet exposure."
            " Source: https://learn.microsoft.com/en-us/azure/data-factory/data-factory-private-link"
        ),
        "new_verdict": None,
        "idem_key": "data-factory-private-link",
    },
    {
        "slug": "eventgrid", "ctrl": "NS-2", "feat": "azure private link",
        "append": (
            " | ARM: Microsoft.EventGrid/topics/privateEndpointConnections (topics)"
            " or Microsoft.EventGrid/domains/privateEndpointConnections (domains);"
            " publicNetworkAccess=Disabled blocks internet traffic."
            " Source: https://learn.microsoft.com/en-us/azure/event-grid/configure-private-endpoints"
        ),
        "new_verdict": None,
        "idem_key": "event-grid/configure-private-endpoints",
    },
    {
        "slug": "eventhubs", "ctrl": "NS-2", "feat": "azure private link",
        "append": (
            " | ARM: Microsoft.EventHub/namespaces/privateEndpointConnections;"
            " namespace properties.publicNetworkAccess=Disabled enforces private-only access."
            " Source: https://learn.microsoft.com/en-us/azure/event-hubs/private-link-service"
        ),
        "new_verdict": None,
        "idem_key": "event-hubs/private-link-service",
    },
    {
        "slug": "functions", "ctrl": "NS-2", "feat": "azure private link",
        "append": (
            " | ARM: Microsoft.Web/sites/privateEndpointConnections"
            " (Functions shares App Service ARM model; API 2024-11-01);"
            " properties.publicNetworkAccess=Disabled. Premium/Dedicated/Flex plans required."
            " Source: https://learn.microsoft.com/en-us/azure/azure-functions/functions-create-vnet"
        ),
        "new_verdict": None,
        "idem_key": "functions-create-vnet",
    },
    {
        "slug": "logicapps", "ctrl": "NS-2", "feat": "azure private link",
        "append": (
            " | ARM: Microsoft.Web/sites/privateEndpointConnections"
            " (Logic Apps Standard runs on App Service platform);"
            " Standard tier supports private endpoint for inbound trigger isolation."
            " Source: https://learn.microsoft.com/en-us/azure/logic-apps/secure-single-tenant-workflow-virtual-network-private-endpoint"
        ),
        "new_verdict": None,
        "idem_key": "secure-single-tenant-workflow-virtual-network-private-endpoint",
    },
    {
        "slug": "virtualdesktop", "ctrl": "NS-2", "feat": "azure private link",
        "append": (
            " | ARM: Microsoft.DesktopVirtualization/workspaces/privateEndpointConnections"
            " + Microsoft.DesktopVirtualization/hostPools/privateEndpointConnections."
            " Two sub-resources: feed (workspace) and connection (host pool)."
            " Source: https://learn.microsoft.com/en-us/azure/virtual-desktop/private-link-overview"
        ),
        "new_verdict": None,
        "idem_key": "virtual-desktop/private-link-overview",
    },
    {
        "slug": "cognitivesearch", "ctrl": "NS-2", "feat": "azure private link",
        "append": (
            " | ARM: Microsoft.Search/searchServices (publicNetworkAccess=Disabled);"
            " private endpoint created in VNet maps to search service private IP."
            " Source: https://learn.microsoft.com/en-us/azure/search/service-create-private-endpoint"
        ),
        "new_verdict": None,
        "idem_key": "search/service-create-private-endpoint",
    },
    {
        "slug": "cognitiveservices", "ctrl": "NS-2", "feat": "azure private link",
        "append": (
            " | ARM: Microsoft.CognitiveServices/accounts/privateEndpointConnections;"
            " accounts.properties.publicNetworkAccess=Disabled."
            " Source: https://learn.microsoft.com/en-us/azure/ai-services/cognitive-services-virtual-networks"
        ),
        "new_verdict": None,
        "idem_key": "cognitive-services-virtual-networks",
    },
    # ── Q1-A: IM-7 Conditional Access — 4 services ─────────────────────────
    {
        "slug": "appservice", "ctrl": "IM-7", "feat": "conditional access",
        "append": (
            " | Entra ID Conditional Access enforced via App Registration in Entra ID"
            " — not an ARM property on the service itself."
            " CA policies (MFA, compliant device, location) applied at Entra ID level via EasyAuth."
            " Source: https://learn.microsoft.com/en-us/azure/app-service/overview-authentication-authorization"
        ),
        "new_verdict": None,
        "idem_key": "overview-authentication-authorization",
    },
    {
        "slug": "cognitivesearch", "ctrl": "IM-7", "feat": "conditional access",
        "append": (
            " | Entra ID Conditional Access applies to AI Search data plane via App Registration."
            " RBAC + CA enforced at Entra ID level; no ARM property on searchServices for CA."
            " Source: https://learn.microsoft.com/en-us/azure/search/search-security-rbac"
        ),
        "new_verdict": None,
        "idem_key": "search-security-rbac",
    },
    {
        "slug": "cognitiveservices", "ctrl": "IM-7", "feat": "conditional access",
        "append": (
            " | Entra ID Conditional Access applies to Azure AI Services data plane via App Registration."
            " CA policies (MFA, device compliance) enforced at Entra ID level."
            " Source: https://learn.microsoft.com/en-us/azure/ai-services/authentication"
        ),
        "new_verdict": None,
        "idem_key": "ai-services/authentication",
    },
    {
        "slug": "virtualdesktop", "ctrl": "IM-7", "feat": "conditional access",
        "append": (
            " | Entra ID Conditional Access required for AVD connections."
            " Policies applied at Entra ID level (not ARM property on hostPool)."
            " MFA + compliant device enforced on user connection request."
            " Source: https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-mfa"
        ),
        "new_verdict": None,
        "idem_key": "virtual-desktop/set-up-mfa",
    },
    # ── Q1-B: azurecdn conditional rows ────────────────────────────────────
    {
        "slug": "azurecdn", "ctrl": "NS-2", "feat": "disable public network",
        "append": (
            " | CDN classic has no publicNetworkAccess ARM toggle."
            " Restrict requires WAF policy with DeliveryPolicy rules OR migration to Azure Front Door Standard/Premium."
            " Source: https://learn.microsoft.com/en-us/azure/cdn/cdn-restrict-access-by-country-region"
        ),
        "new_verdict": None,
        "idem_key": "cdn-restrict-access-by-country",
    },
    {
        "slug": "azurecdn", "ctrl": "NS-2", "feat": "azure private link",
        "append": (
            " | CDN classic Private Link for origins: GA in CDN Premium from Verizon SKU;"
            " Standard SKU does not support Private Link origins."
            " ARM: Microsoft.Cdn/profiles/endpoints/originGroups/origins with privateLinkResourceId."
            " Source: https://learn.microsoft.com/en-us/azure/cdn/cdn-private-endpoint"
        ),
        "new_verdict": None,
        "idem_key": "cdn-private-endpoint",
    },
    # ── Q1-C: filesync NS-2 flip ────────────────────────────────────────────
    {
        "slug": "filesync", "ctrl": "NS-2", "feat": "azure private link",
        "append": (
            " | Q1-C June 2026 confirmed: Azure File Sync DOES support private endpoints"
            " via Microsoft.StorageSync/storageSyncServices. DNS: privatelink.afs.azure.net."
            " Verdict updated to now_applicable_native."
            " Source: https://learn.microsoft.com/en-us/azure/storage/file-sync/file-sync-networking-endpoints"
        ),
        "new_verdict": "now_applicable_native",
        "idem_key": "file-sync-networking-endpoints",
    },
    # ── Q1-C: notificationhubs NS-1 note (preview, no verdict flip) ─────────
    {
        "slug": "notificationhubs", "ctrl": "NS-1", "feat": "virtual network integration",
        "append": (
            " | Q1-C June 2026: Azure Notification Hubs Private Link is in PREVIEW (not GA)."
            " Verdict remains still_not_applicable until GA."
            " Source: https://learn.microsoft.com/en-us/azure/notification-hubs/private-link"
        ),
        "new_verdict": None,
        "idem_key": "notification-hubs/private-link",
    },
]


def dedup_appservice(rows: list) -> tuple[list, int]:
    """Remove duplicate NS-2 Azure Private Link rows in appservice — keep first."""
    seen = set()
    deduped = []
    removed = 0
    for row in rows:
        key = (row["asb_control_id"].strip(), row["feature_name"].strip().lower())
        if key in seen:
            removed += 1
            print(f"  DEDUP removed: {row['asb_control_id']} | {row['feature_name'][:50]}")
        else:
            seen.add(key)
            deduped.append(row)
    return deduped, removed


def apply_patches_to_slug(slug: str, patches: list) -> int:
    csv_path = pathlib.Path(f"data/outputs/ns/{slug}.final.csv")
    if not csv_path.exists():
        print(f"  {slug}: file not found, skip")
        return 0

    rows = list(csv.DictReader(open(csv_path)))
    updated = 0
    removed = 0

    # Dedup appservice before patching
    if slug == "appservice":
        rows, removed = dedup_appservice(rows)

    for row in rows:
        ctrl = row["asb_control_id"].strip()
        feat = row["feature_name"].lower()
        notes = row.get("notes", "")

        for patch in patches:
            if patch["slug"] != slug:
                continue
            if ctrl != patch["ctrl"]:
                continue
            if patch["feat"].lower() not in feat:
                continue
            # Idempotency: skip if already applied
            if patch["idem_key"] in notes:
                continue

            row["notes"] = notes.rstrip() + patch["append"]

            if patch["new_verdict"] is not None:
                old_verdict = row["verdict_2025"]
                row["verdict_2025"] = patch["new_verdict"]
                row["blast_radius"] = compute_blast(row)
                row["risk_rank"] = recompute_risk(row)
                print(f"  FLIP {slug} {ctrl} '{row['feature_name'][:40]}': {old_verdict} → {patch['new_verdict']}")

            updated += 1
            break  # one patch per row

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        for row in rows:
            writer.writerow([row.get(h, "") for h in HEADER])

    return updated + removed


if __name__ == "__main__":
    print("=" * 60)
    print("Phase 58 — Individual row patches")
    print("=" * 60)

    slugs = sorted(set(p["slug"] for p in PATCHES))
    total = 0
    for slug in slugs:
        slug_patches = [p for p in PATCHES if p["slug"] == slug]
        n = apply_patches_to_slug(slug, slug_patches)
        total += n
        print(f"  {slug:<22} patches_applied={n:>3}")

    print()
    print(f"Total patches/changes: {total}")
    print("Done.")
