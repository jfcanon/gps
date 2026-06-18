"""
Backup and Recovery checks for Azure Firewall Manager (MCSB v3).
BR-1: Firewall Policy is IaC-recoverable config — UNKNOWN static (False/N/A in CSV).
Read-only. Zero ARM writes.
"""


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "BR-1", "feature": "Azure Backup", "status": "UNKNOWN", "actual_value": "Azure Backup not supported for Firewall Policy. Policy is a configuration object (rule collections, threat intel settings) fully recreatable from IaC (ARM/Bicep/Terraform). Feature=False in MCSB v3.", "expected_value": "N/A — IaC as compensating control; no backup product for policy resource", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview"}


def check_br1_native_backup(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "BR-1", "feature": "Service Native Backup Capability", "status": "UNKNOWN", "actual_value": "No native backup capability for Firewall Policy. Policy configuration export (ARM template) serves as manual backup. Recommended: store policy definition in source control via IaC pipeline. Feature=False in MCSB v3.", "expected_value": "N/A — export ARM template + IaC source control as compensating control", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview"}
