"""
Backup and Recovery checks for Azure Firewall (MCSB v3).

BR-1 Azure Backup: Azure Backup service does not support Azure Firewall configuration → UNKNOWN.
BR-1 Native Backup: No native automated backup; ARM template export is manual only → UNKNOWN.

Read-only. Zero ARM writes.
"""


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "BR-1",
        "feature": "Azure Backup",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Backup does not support Azure Firewall rule collections or Firewall Policy as a backup target. "
            "Firewall configuration is recoverable via ARM template export or Firewall Policy version history (if used), "
            "both of which are manual operations. No automated backup solution exists for this service."
        ),
        "expected_value": "N/A — Azure Backup not supported for Azure Firewall configuration",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/backup/backup-support-matrix",
    }


def check_br1_native_backup(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "BR-1",
        "feature": "Service Native Backup Capability",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Firewall has no native automated backup capability. "
            "Firewall Policy (recommended configuration model) supports version control via ARM, "
            "and rule collections can be exported as ARM templates, but these are manual/scripted exports — "
            "not automated point-in-time recovery. Consider storing Firewall Policy in source control as a compensating control."
        ),
        "expected_value": "N/A — no native automated backup; use Firewall Policy + ARM export as compensating control",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/policy-overview",
    }
