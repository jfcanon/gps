"""
Backup and Recovery checks for Azure Bastion (MCSB v3).

BR-1×2: UNKNOWN static — feature_supported=False, final_verdict=not_applicable.
    Azure Backup does not support Bastion hosts as backup targets.
    Bastion configuration is declarative (subnet reference, public IP, SKU, scale units).
    Recovery: IaC-recoverable via ARM template export or Bicep/Terraform.

Read-only. Zero ARM writes. No SDK import needed.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/bastion/bastion-overview"
_IaC_NOTE = "Azure Bastion config (subnet='AzureBastionSubnet', public IP, SKU, scale units) is declarative and IaC-recoverable; "


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "BR-1",
        "feature": "Azure Backup",
        "status": "UNKNOWN",
        "actual_value": _IaC_NOTE + "Azure Backup does not support Bastion hosts as backup targets. feature_supported=False in MCSB v3 baseline. not_applicable.",
        "expected_value": "N/A — feature_supported=False; Azure Backup not applicable for Bastion",
        "evidence_url": _EVIDENCE,
    }


def check_br1_native_backup(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "BR-1",
        "feature": "Service Native Backup Capability",
        "status": "UNKNOWN",
        "actual_value": _IaC_NOTE + "No native backup capability for Bastion. Export ARM config: 'az network bastion show --rg <rg> --name <name>'. SKU, scale units, subnet, and public IP are all recoverable from IaC. feature_supported=False in MCSB v3 baseline. not_applicable.",
        "expected_value": "N/A — feature_supported=False; no native backup; IaC-recoverable",
        "evidence_url": _EVIDENCE,
    }
