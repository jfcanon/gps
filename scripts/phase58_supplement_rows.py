"""Phase 58 Step 2 — Add Q2 supplement rows for 2025-2026 new NS features.

Mirror: scripts/phase57_supplement_rows.py
Idempotent: skip if asb_control_id already present in CSV.

Q2 findings:
- eventgrid: Event Grid Namespaces (Standard/MQTT tier) has own privateEndpointConnections
  resource (Microsoft.EventGrid/namespaces) — distinct from Basic tier topics/domains.
- notificationhubs: Azure Notification Hubs Private Link in PREVIEW as of June 2026.
"""
import csv
import pathlib

HEADER = [
    "asb_control_id", "feature_name", "feature_supported_original",
    "feature_enabled_by_default_original", "status_2025", "verdict_2025",
    "azure_api_property", "script_module", "script_function", "notes",
    "service", "severity", "blast_radius", "risk_rank",
]

SUPPLEMENT_ROWS = [
    {
        "slug": "eventgrid",
        "row": {
            "asb_control_id": "NS-2-SUPPLEMENT-EVENTGRID",
            "feature_name": "Azure Event Grid Namespaces Private Endpoint (Standard/MQTT Tier)",
            "feature_supported_original": "False",
            "feature_enabled_by_default_original": "False",
            "status_2025": "gap",
            "verdict_2025": "now_applicable_native",
            "azure_api_property": "Microsoft.EventGrid/namespaces/privateEndpointConnections",
            "script_module": "ns_eventgrid",
            "script_function": "check_eventgrid_namespace_private_endpoint",
            "notes": (
                "v2 gap: Event Grid Standard tier (Namespaces/MQTT broker) introduced its own"
                " private endpoint resource (Microsoft.EventGrid/namespaces/privateEndpointConnections),"
                " separate from Basic tier topics/domains already covered by NS-2."
                " Namespaces support MQTT v3.1.1 and v5.0 pub-sub over private link."
                " Source: https://learn.microsoft.com/en-us/azure/event-grid/mqtt-configure-private-endpoints"
                " | Q2-D WebSearch June 2026 confirmed GA."
            ),
            "service": "eventgrid",
            "severity": "Medium",
            "blast_radius": "Narrow",
            "risk_rank": "2",
        },
    },
    {
        "slug": "notificationhubs",
        "row": {
            "asb_control_id": "NS-2-SUPPLEMENT-NOTIFICATIONHUBS",
            "feature_name": "Azure Notification Hubs Private Link (Preview)",
            "feature_supported_original": "False",
            "feature_enabled_by_default_original": "False",
            "status_2025": "gap",
            "verdict_2025": "conditional",
            "azure_api_property": "Microsoft.NotificationHubs/namespaces/privateEndpointConnections",
            "script_module": "ns_notificationhubs",
            "script_function": "check_notificationhubs_private_endpoint",
            "notes": (
                "v2 gap: Azure Notification Hubs Private Link is in PREVIEW as of June 2026."
                " DNS: privatelink.servicebus.windows.net + privatelink.notificationhub.windows.net."
                " Conditional: not GA — requires preview opt-in."
                " Monitor for GA; update to now_applicable_native when released."
                " Source: https://learn.microsoft.com/en-us/azure/notification-hubs/private-link"
                " | Q2-D WebSearch June 2026 confirmed preview status."
            ),
            "service": "notificationhubs",
            "severity": "Medium",
            "blast_radius": "Wide",
            "risk_rank": "2",
        },
    },
]


def add_supplement(slug: str, new_row: dict) -> bool:
    csv_path = pathlib.Path(f"data/outputs/ns/{slug}.final.csv")
    if not csv_path.exists():
        print(f"  {slug}: file not found, skip")
        return False

    rows = list(csv.DictReader(open(csv_path)))
    existing_ids = {r["asb_control_id"].strip() for r in rows}

    if new_row["asb_control_id"] in existing_ids:
        print(f"  {slug}: {new_row['asb_control_id']} already present — skip (idempotent)")
        return False

    rows.append(new_row)

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        for row in rows:
            writer.writerow([row.get(h, "") for h in HEADER])

    print(f"  {slug}: added {new_row['asb_control_id']}")
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("Phase 58 Step 2 — Q2 supplement rows")
    print("=" * 60)

    added = 0
    for entry in SUPPLEMENT_ROWS:
        ok = add_supplement(entry["slug"], entry["row"])
        if ok:
            added += 1

    print()
    print(f"Supplement rows added: {added}")
    print("Done.")
