"""
Backup and Recovery checks for Azure Event Grid (MCSB v3).
Event Grid is a stateless event routing service — no backup target. All UNKNOWN.
"""


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, topic_name: str | None) -> dict:
    return {
        "resource": topic_name or "all",
        "control_id": "BR-1",
        "feature": "Ensure Regular Automated Backups — Azure Backup Service",
        "status": "UNKNOWN",
        "actual_value": "Azure Event Grid is a stateless event routing service. Events are not persisted by the service (delivery is at-most-once). Topic configuration backup relies on ARM templates/IaC. Dead-letter storage on subscriptions provides event retention for failed deliveries.",
        "expected_value": "N/A — use IaC for topic config recovery; configure dead-letter storage for event retention",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-grid/manage-event-delivery",
    }
