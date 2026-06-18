"""
Backup and Recovery checks for Azure Service Bus (MCSB v3).

BR-1 azure_backup: Azure Backup does not support Service Bus as a managed backup target → UNKNOWN.
BR-1 native_backup: Service Bus has no soft-delete or purge-protection equivalent for message data.
                    Geo-disaster recovery (active/passive pairing) is for availability, not data backup → UNKNOWN.

Read-only. Zero ARM writes.
"""


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    return {
        "resource": namespace_name or "all",
        "control_id": "BR-1",
        "feature": "Ensure Regular Automated Backups — Azure Backup Service",
        "status": "UNKNOWN",
        "actual_value": "Azure Backup (Recovery Services Vault) does not support Azure Service Bus as a backup target. Message data is transient by design. Geo-disaster recovery pairs namespaces for availability failover but does not back up individual messages.",
        "expected_value": "N/A — use geo-disaster recovery and client-side message persistence patterns",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-geo-dr",
    }


def check_br1_native_backup(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    return {
        "resource": namespace_name or "all",
        "control_id": "BR-1",
        "feature": "Ensure Regular Automated Backups — Native Soft-Delete and Purge Protection",
        "status": "UNKNOWN",
        "actual_value": "Azure Service Bus has no soft-delete or purge-protection mechanism equivalent to Key Vault or Storage. Message data is transient. Entity configuration (queues, topics, subscriptions) can be exported via ARM templates but no native automated backup exists for message payloads.",
        "expected_value": "N/A — no soft-delete or purge-protection for Service Bus message data",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-geo-dr",
    }
