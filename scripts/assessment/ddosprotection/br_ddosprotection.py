"""
Backup and Recovery checks for Azure DDoS Protection (MCSB v3).
BR-1: DDoS plan is configuration-only; recreatable from IaC — UNKNOWN static.
Read-only. Zero ARM writes.
"""


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "BR-1", "feature": "Azure Backup", "status": "UNKNOWN", "actual_value": "Azure Backup not supported for DDoS Protection Plans; plan is a configuration object recreatable from IaC (ARM/Bicep/Terraform) with no stateful data requiring backup.", "expected_value": "N/A — PaaS; IaC as compensating control", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/manage-ddos-protection"}


def check_br1_native_backup(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "BR-1", "feature": "Service Native Backup Capability", "status": "UNKNOWN", "actual_value": "No native backup capability; DDoS plan configuration is stateless — VNet associations can be re-established from IaC; recommended compensating control: store plan definition in source control.", "expected_value": "N/A — PaaS; no native backup; IaC recommended", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/manage-ddos-protection"}
