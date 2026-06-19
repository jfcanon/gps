"""
Backup and Recovery checks for Azure Private Link / Private Endpoint (MCSB v3).

BR-1×2: UNKNOWN static — PE is a network configuration resource.
    Azure Backup does not support Private Endpoint as a backup target.
    PE configuration (subnet, private DNS zone link, connection approval state)
    is recoverable via IaC (Bicep/Terraform/ARM template export).
    No persistent data to back up.

Read-only. Zero ARM writes. No SDK import needed.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview"
_RELAY_NOTE = "Private Endpoint is a network configuration resource (NIC + DNS + approval state); "


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "BR-1",
        "feature": "Azure Backup",
        "status": "UNKNOWN",
        "actual_value": _RELAY_NOTE + "Azure Backup does not support Private Endpoint as a backup target. PE config recoverable via IaC (subnet ID, private DNS zone link, connection approval). not_applicable in MCSB v3 baseline.",
        "expected_value": "N/A — Azure Backup does not support PE; IaC-recoverable",
        "evidence_url": _EVIDENCE,
    }


def check_br1_native_backup(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "BR-1",
        "feature": "Service Native Backup Capability",
        "status": "UNKNOWN",
        "actual_value": _RELAY_NOTE + "No native backup capability. PE configuration (target resource ID, subnet, private DNS zone group) is declarative and IaC-recoverable. not_applicable in MCSB v3 baseline.",
        "expected_value": "N/A — no native backup; IaC-recoverable config resource",
        "evidence_url": _EVIDENCE,
    }
