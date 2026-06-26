"""
Backup and Recovery checks for Azure Virtual Network (MCSB v3).
VNet configuration is IaC-managed — no Azure Backup support. All UNKNOWN.
"""


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, vnet_name: str | None) -> dict:
    return {
        "resource": vnet_name or "all",
        "control_id": "BR-1",
        "feature": "Ensure Regular Automated Backups — Azure Backup Service",
        "status": "UNKNOWN",
        "actual_value": "Azure Backup does not support Virtual Network configuration as a managed backup target. VNet configuration recovery relies on ARM templates, Bicep, or Terraform state.",
        "expected_value": "N/A — use IaC (ARM/Bicep/Terraform) for VNet configuration recovery",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/security-baseline",
    }
