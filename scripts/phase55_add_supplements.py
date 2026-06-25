"""Phase 55 Step 4 — Add v2-only supplement rows (Q2).

NS-6-SUPPLEMENT: azurefirewall — IDPS (properties.intrusionDetection, Premium SKU)
NS-7-SUPPLEMENT: redis + servicebus — disable public endpoint when PE active
"""
import csv
import pathlib

HEADER = [
    "asb_control_id", "feature_name", "feature_supported_original",
    "feature_enabled_by_default_original", "status_2025", "verdict_2025",
    "azure_api_property", "script_module", "script_function", "notes",
    "service", "severity", "blast_radius", "risk_rank",
]

SUPPLEMENTS = [
    {
        "path": "data/outputs/ns/azurefirewall.final.csv",
        "row": {
            "asb_control_id": "NS-6-SUPPLEMENT",
            "feature_name": "IDPS — Intrusion Detection and Prevention System",
            "feature_supported_original": "False",
            "feature_enabled_by_default_original": "False",
            "status_2025": "gap",
            "verdict_2025": "conditional",
            "azure_api_property": "properties.intrusionDetection",
            "script_module": "",
            "script_function": "",
            "notes": (
                "v2 gap: IDPS available in Azure Firewall Premium SKU only. "
                "Supported via properties.intrusionDetection (mode: Alert|Deny|Off). "
                "Standard SKU has no IDPS — gap if using Standard tier. "
                "Conditional: requires Premium SKU. "
                "Source: https://learn.microsoft.com/en-us/azure/firewall/premium-features"
            ),
            "service": "azurefirewall",
            "severity": "High",
            "blast_radius": "Wide",
            "risk_rank": "6",
        },
    },
    {
        "path": "data/outputs/ns/redis.final.csv",
        "row": {
            "asb_control_id": "NS-7-SUPPLEMENT",
            "feature_name": "Disable Public Network Access When Private Endpoint Active",
            "feature_supported_original": "False",
            "feature_enabled_by_default_original": "False",
            "status_2025": "gap",
            "verdict_2025": "conditional",
            "azure_api_property": "properties.publicNetworkAccess",
            "script_module": "",
            "script_function": "",
            "notes": (
                "v2 gap: when Private Endpoint is configured, public network access "
                "should be disabled via properties.publicNetworkAccess=Disabled. "
                "Not disabled by default when PE is added. "
                "Conditional: gap only if Private Endpoint is configured and public "
                "access not explicitly disabled. "
                "Policy: 'Azure Cache for Redis should disable public network access'. "
                "Source: https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-private-link"
            ),
            "service": "redis",
            "severity": "High",
            "blast_radius": "Wide",
            "risk_rank": "6",
        },
    },
    {
        "path": "data/outputs/ns/servicebus.final.csv",
        "row": {
            "asb_control_id": "NS-7-SUPPLEMENT",
            "feature_name": "Disable Public Network Access When Private Endpoint Active",
            "feature_supported_original": "False",
            "feature_enabled_by_default_original": "False",
            "status_2025": "gap",
            "verdict_2025": "conditional",
            "azure_api_property": "properties.publicNetworkAccess",
            "script_module": "",
            "script_function": "",
            "notes": (
                "v2 gap: when Private Endpoint is configured, public network access "
                "should be disabled via properties.publicNetworkAccess=Disabled. "
                "Not disabled by default when PE is added to Service Bus namespace. "
                "Conditional: gap only if Private Endpoint is configured and public "
                "access not explicitly disabled. "
                "Source: https://learn.microsoft.com/en-us/azure/service-bus-messaging/private-link-service"
            ),
            "service": "servicebus",
            "severity": "High",
            "blast_radius": "Wide",
            "risk_rank": "6",
        },
    },
]


def add_supplement(spec: dict) -> bool:
    csv_path = pathlib.Path(spec["path"])
    rows = list(csv.DictReader(open(csv_path)))

    supplement_id = spec["row"]["asb_control_id"]
    if any(r["asb_control_id"] == supplement_id for r in rows):
        print(f"  {csv_path.name}: {supplement_id} already present, skipping")
        return False

    rows.append(spec["row"])

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        for row in rows:
            writer.writerow([row.get(h, "") for h in HEADER])

    print(f"  {csv_path.name}: added {supplement_id}")
    return True


if __name__ == "__main__":
    print("Adding supplement rows (Q2)...")
    for spec in SUPPLEMENTS:
        add_supplement(spec)
    print("Done.")
