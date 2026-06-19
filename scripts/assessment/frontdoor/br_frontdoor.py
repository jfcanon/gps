"""
Backup and Recovery checks for Azure Front Door (MCSB v3).

BR-1: Azure Backup and native backup — Not Applicable.
      AFD configuration is IaC-recoverable. No Azure Backup support.
All UNKNOWN static.

Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/frontdoor/front-door-overview"


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "BR-1",
        "feature": "Azure Backup",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Backup does not support Azure Front Door. "
            "AFD configuration (routing rules, backend pools, frontend endpoints, WAF links) is fully "
            "described in ARM and recreatable from IaC (ARM/Bicep/Terraform). Not Applicable."
        ),
        "expected_value": "N/A — Azure Backup not supported; use IaC as compensating control",
        "evidence_url": _EVIDENCE,
    }


def check_br1_native_backup(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "BR-1",
        "feature": "Service Native Backup Capability",
        "status": "UNKNOWN",
        "actual_value": (
            "No native backup product for Azure Front Door. "
            "Export via 'az network front-door show -g <rg> -n <name> --output json > afd-config.json'. "
            "IaC (ARM/Bicep/Terraform) is the primary compensating control. Not Applicable."
        ),
        "expected_value": "N/A — no native backup; JSON export + IaC as compensating controls",
        "evidence_url": _EVIDENCE,
    }
