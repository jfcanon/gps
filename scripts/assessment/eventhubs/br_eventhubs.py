"""
Backup and Recovery checks for Azure Event Hubs (MCSB v3).
Event Hubs does not support Azure Backup as a backup target. All UNKNOWN.
"""


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    return {
        "resource": namespace_name or "all",
        "control_id": "BR-1",
        "feature": "Ensure Regular Automated Backups — Azure Backup Service",
        "status": "UNKNOWN",
        "actual_value": "Azure Backup does not support Event Hubs namespaces as a managed backup target. Geo-disaster recovery (namespace pairing) provides metadata replication but not message backup.",
        "expected_value": "N/A — use Geo-DR pairing for namespace metadata recovery; consumer group checkpoints stored in client storage",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-geo-dr",
    }
